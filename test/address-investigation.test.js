import test from "node:test";
import assert from "node:assert/strict";
import { buildAddressInvestigation, listInvestigableAddresses } from "../src/address-investigation.js";

const a="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const b="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const c="0xcccccccccccccccccccccccccccccccccccccccc";
const txhash=n=>"0x"+String(n).repeat(64).slice(0,64);
const report=(subject,observations,chainId="0x1")=>({schema:"sentinel.case-report.v1",subject,subjectType:"transaction",chainId,observations,provenance:{blockNumber:"0x10"}});
const graph={schema:"sentinel.correlation-graph.v1",nodes:[{chainId:"0x1",address:a,roles:["transaction-sender"],cases:[txhash(1)]}],edges:[{chainId:"0x1",from:a,to:b,type:"observed-transaction-flow",evidence:[{caseSubjects:[txhash(1)]}]}]};
const threat={schema:"sentinel.threat-intelligence.v1",signals:[{chainId:"0x1",entities:[a],evidence:[]}],transactionLinks:[{chainId:"0x1",from:a,via:b,to:c}],addressProfiles:[{chainId:"0x1",address:a,observedTransactionCount:1}],tokenAddressProfiles:[{chainId:"0x1",address:a,token:c,incomingTransferCount:0,outgoingTransferCount:1}],tokenTransfers:[{chainId:"0x1",token:c,from:a,to:b,amountRaw:"42",blockNumber:"0x12",logIndex:"0x0",transactionHash:txhash(2)}]};

test("builds chain-scoped address investigation with transactions, tokens, graph and signals",()=>{
 const reports=[report(txhash(1),[{kind:"transaction",value:{hash:txhash(1),from:a,to:b,blockNumber:"0x11",transactionIndex:"0x0"}},{kind:"erc1967-slots",implementation:a}])];
 const result=buildAddressInvestigation({reports,graph,threatIntelligence:threat,chainId:"0x1",address:a});
 assert.equal(result.schema,"sentinel.address-investigation.v1");
 assert.equal(result.summary.observedTransactionCount,1);
 assert.equal(result.summary.tokenTransferCount,1);
 assert.equal(result.summary.transactionHandoffCount,1);
 assert.equal(result.summary.correlationEdgeCount,1);
 assert.equal(result.summary.threatSignalCount,1);
 assert.ok(result.roles.includes("proxy-implementation"));
 assert.equal(result.transactions[0].hash,txhash(1));
 assert.equal(result.tokenTransfers[0].direction,"outgoing");
 assert.equal(result.assessment.verdict,"not-assessed");
});

test("does not mix activity from another chain",()=>{
 const reports=[report(txhash(1),[{kind:"transaction",value:{hash:txhash(1),from:a,to:b,blockNumber:"0x11"}}],"0x38")];
 const result=buildAddressInvestigation({reports,graph,threatIntelligence:threat,chainId:"0x1",address:a});
 assert.equal(result.summary.observedTransactionCount,0);
 assert.equal(result.summary.tokenTransferCount,1);
 assert.equal(result.summary.relatedCaseCount,1);
});

test("deduplicates transactions and bounds transaction detail",()=>{
 const observations=[{kind:"transaction",value:{hash:txhash(1),from:a,to:b,blockNumber:"0x11"}}];
 const reports=[report(txhash(1),observations),report(txhash(1),observations)];
 const result=buildAddressInvestigation({reports,graph,threatIntelligence:threat,chainId:"0x1",address:a,maxTransactions:1});
 assert.equal(result.summary.observedTransactionCount,1);
 assert.equal(result.summary.truncatedTransactions,false);
});

test("validates required inputs and filters",()=>{
 assert.throws(()=>buildAddressInvestigation({reports:[],graph,threatIntelligence:threat,chainId:"0x1",address:"bad"}),/valid EVM address/);
 assert.throws(()=>buildAddressInvestigation({reports:[],graph:{},threatIntelligence:threat,chainId:"0x1",address:a}),/correlation graph/);
 assert.throws(()=>buildAddressInvestigation({reports:[],graph,threatIntelligence:threat,chainId:"0x1",address:a,maxTransactions:501}),/between 1 and 500/);
});

test("lists addresses across graph, transaction and token evidence",()=>{
 const list=listInvestigableAddresses({graph,threatIntelligence:threat});
 assert.ok(list.some(item=>item.chainId==="0x1"&&item.address===a));
 assert.ok(list.some(item=>item.chainId==="0x1"&&item.address===b));
});
