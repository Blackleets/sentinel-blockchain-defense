import test from "node:test";
import assert from "node:assert/strict";
import { ERC20_TRANSFER_TOPIC, decodeTransferLogs, buildLiveTransferGraph, formatTokenAmount, decodeAbiString, decodeTokenMetadata, bindNetworkRpc } from "../src/live-visualizer.js";

const a="0x1111111111111111111111111111111111111111";
const b="0x2222222222222222222222222222222222222222";
const token="0x3333333333333333333333333333333333333333";
const tx="0x"+"a".repeat(64);
const topic=value=>"0x"+value.slice(2).padStart(64,"0");
const log=(from=a,to=b,index="0x0")=>({address:token,topics:[ERC20_TRANSFER_TOPIC,topic(from),topic(to)],data:"0x"+(42n).toString(16).padStart(64,"0"),transactionHash:tx,blockNumber:"0x64",logIndex:index});

test("decodes indexed Transfer logs and preserves raw base-unit amount",()=>{
 const result=decodeTransferLogs([log()],{chainId:"0x1"});
 assert.equal(result.length,1);assert.equal(result[0].from,a);assert.equal(result[0].to,b);
 assert.equal(result[0].amountRaw,"42");assert.equal(result[0].chainId,"0x1");
});
test("deduplicates logs and ignores malformed or unrelated events",()=>{
 const malformedTopic=log();malformedTopic.topics[1]="0x"+"f".repeat(64);
 const removed={...log(a,b,"0x2"),removed:true};
 const result=decodeTransferLogs([log(),log(),{...log("0x4444444444444444444444444444444444444444",b,"0x1"),topics:["0x"+"0".repeat(64)]},malformedTopic,removed],{chainId:"0x1"});
 assert.equal(result.length,1);
});
test("builds an address-centred graph with bounded edges and chain isolation",()=>{
 const transfers=decodeTransferLogs([log(a,b,"0x0"),log(b,a,"0x1"),log("0x4444444444444444444444444444444444444444",b,"0x2")],{chainId:"0x1"});
 const graph=buildLiveTransferGraph(transfers,{address:a,chainId:"0x1",scannedFrom:"100",scannedTo:"200",maxEdges:1});
 assert.equal(graph.nodeCount,2);assert.equal(graph.edgeCount,1);assert.equal(graph.totalObservedEdges,2);
 assert.equal(graph.truncated,true);assert.equal(graph.origin,a);assert.equal(graph.coverage,"bounded-live-rpc-transfer-event-logs");
});
test("formats base-unit amounts without floating-point precision loss",()=>{
 assert.equal(formatTokenAmount("1234567890123456789",18),"1.234567890123456789");
 assert.equal(formatTokenAmount("5000000",6),"5");
 assert.equal(formatTokenAmount("42",0),"42");
 assert.match(formatTokenAmount("42",null),/raw units/);
});
test("decodes standard ABI strings, bytes32 symbols and bounded decimals",()=>{
 const word=n=>BigInt(n).toString(16).padStart(64,"0");
 const bytes=Buffer.from("USDC","utf8").toString("hex").padEnd(64,"0");
 const dynamic="0x"+word(32)+word(4)+Buffer.from("USDC","utf8").toString("hex").padEnd(64,"0");
 assert.equal(decodeAbiString(dynamic),"USDC");
 assert.equal(decodeAbiString("0x"+bytes),"USDC");
 const metadata=decodeTokenMetadata({symbolResult:dynamic,nameResult:dynamic,decimalsResult:"0x"+word(6)});
 assert.deepEqual(metadata,{symbol:"USDC",name:"USDC",decimals:6});
 assert.equal(decodeTokenMetadata({decimalsResult:"0x"+word(255)}).decimals,null);
});
test("expands relationship graph to two bounded hops",()=>{
 const c="0x5555555555555555555555555555555555555555";
 const d="0x6666666666666666666666666666666666666666";
 const transfers=decodeTransferLogs([log(a,b,"0x0"),log(b,c,"0x1"),log(c,d,"0x2")],{chainId:"0x1"});
 const one=buildLiveTransferGraph(transfers,{address:a,chainId:"0x1",hops:1});
 const two=buildLiveTransferGraph(transfers,{address:a,chainId:"0x1",hops:2});
 assert.equal(one.nodeCount,2);assert.equal(one.edgeCount,1);
 assert.equal(two.nodeCount,3);assert.equal(two.edgeCount,2);assert.equal(two.hops,2);
 const capped=buildLiveTransferGraph(transfers,{address:a,chainId:"0x1",hops:2,maxNodes:2});
 assert.equal(capped.nodeCount,2);assert.equal(capped.truncated,true);
});
test("rejects invalid addresses and edge bounds",()=>{
 assert.throws(()=>buildLiveTransferGraph([],{address:"bad",chainId:"0x1"}),/valid EVM address/);
 assert.throws(()=>buildLiveTransferGraph([],{address:a,chainId:"0x1",maxEdges:501}),/maxEdges/);
 assert.throws(()=>buildLiveTransferGraph([],{address:a,chainId:"invalid"}),/chain ID/);
});


test("pins every visualizer RPC request to the network selected when tracing began",async()=>{
 const calls=[],ethereum={chainId:"0x1",rpc:"https://rpc.example/eth",explorer:"https://etherscan.io"},polygon={chainId:"0x89",rpc:"https://rpc.example/poly",explorer:"https://polygonscan.com"};
 const activeNetwork=ethereum;
 const pinned=bindNetworkRpc((method,params,network)=>{calls.push({method,params,chainId:network.chainId,url:network.rpc});return network.chainId;},activeNetwork);
 assert.equal(pinned("eth_chainId"),"0x1");
 assert.equal(pinned("eth_blockNumber"),"0x1");
 assert.equal(pinned("eth_getLogs",[]),"0x1");
 assert.equal(calls.length,3);
 assert.ok(calls.every(call=>call.chainId==="0x1"&&call.url===ethereum.rpc));
 assert.notEqual(polygon.chainId,activeNetwork.chainId);
});
