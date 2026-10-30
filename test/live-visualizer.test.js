import test from "node:test";
import assert from "node:assert/strict";
import { ERC20_TRANSFER_TOPIC, decodeTransferLogs, buildLiveTransferGraph } from "../src/live-visualizer.js";

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
 const result=decodeTransferLogs([log(),log(),{...log("0x4444444444444444444444444444444444444444",b,"0x1"),topics:["0x"+"0".repeat(64)]}],{chainId:"0x1"});
 assert.equal(result.length,1);
});
test("builds an address-centred graph with bounded edges and chain isolation",()=>{
 const transfers=decodeTransferLogs([log(a,b,"0x0"),log(b,a,"0x1"),log("0x4444444444444444444444444444444444444444",b,"0x2")],{chainId:"0x1"});
 const graph=buildLiveTransferGraph(transfers,{address:a,chainId:"0x1",scannedFrom:"100",scannedTo:"200",maxEdges:1});
 assert.equal(graph.nodeCount,2);assert.equal(graph.edgeCount,1);assert.equal(graph.totalObservedEdges,2);
 assert.equal(graph.truncated,true);assert.equal(graph.origin,a);assert.equal(graph.coverage,"bounded-live-rpc-transfer-event-logs");
});
test("rejects invalid addresses and edge bounds",()=>{
 assert.throws(()=>buildLiveTransferGraph([],{address:"bad",chainId:"0x1"}),/valid EVM address/);
 assert.throws(()=>buildLiveTransferGraph([],{address:a,chainId:"0x1",maxEdges:501}),/maxEdges/);
});
