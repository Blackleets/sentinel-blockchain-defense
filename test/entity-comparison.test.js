import test from "node:test";
import assert from "node:assert/strict";
import { compareObservedEntities } from "../src/entity-comparison.js";
const a="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",b="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",c="0xcccccccccccccccccccccccccccccccccccccccc",d="0xdddddddddddddddddddddddddddddddddddddddd";
const tx="0x"+"1".repeat(64),caseId="0x"+"2".repeat(64);
const graph={schema:"sentinel.correlation-graph.v1",edges:[
 {chainId:"0x1",from:a,to:b,type:"observed-transaction-flow",evidence:[{caseSubjects:[caseId]}]},
 {chainId:"0x1",from:a,to:c,type:"observed-transaction-flow",evidence:[{caseSubjects:[caseId]}]},
 {chainId:"0x1",from:b,to:c,type:"observed-transaction-flow",evidence:[{caseSubjects:[caseId]}]},
 {chainId:"0x38",from:a,to:d,type:"observed-transaction-flow",evidence:[]}
]};
const threatIntelligence={schema:"sentinel.threat-intelligence.v1",tokenTransfers:[
 {chainId:"0x1",from:a,to:c,transactionHash:tx,amountRaw:"10"},
 {chainId:"0x1",from:b,to:c,transactionHash:tx,amountRaw:"10"},
 {chainId:"0x38",from:a,to:d,transactionHash:tx,amountRaw:"99"}
],transactionLinks:[]};
test("compares direct links and shared counterparties on one chain only",()=>{
 const result=compareObservedEntities({graph,threatIntelligence,chainId:"0x1",addressA:a,addressB:b});
 assert.equal(result.summary.directRelationshipCount,1);
 assert.deepEqual(result.sharedCounterparties.map(item=>item.address),[c]);
 assert.equal(result.summary.sharedTransactionHashCount,1);
 assert.deepEqual(result.sharedCaseSubjects,[caseId]);
 assert.equal(result.assessment.verdict,"not-assessed");
});
test("does not manufacture a relationship when there is no shared evidence",()=>{
 const result=compareObservedEntities({graph,threatIntelligence,chainId:"0x1",addressA:a,addressB:d});
 assert.equal(result.summary.directRelationshipCount,0);
 assert.equal(result.summary.sharedCounterpartyCount,0);
 assert.equal(result.summary.sharedTransactionHashCount,0);
});
test("rejects invalid, identical and incomplete comparison inputs",()=>{
 assert.throws(()=>compareObservedEntities({graph,threatIntelligence,chainId:"0x1",addressA:a,addressB:a}),/different addresses/);
 assert.throws(()=>compareObservedEntities({graph,threatIntelligence,chainId:"0x1",addressA:"bad",addressB:b}),/valid EVM/);
 assert.throws(()=>compareObservedEntities({graph,threatIntelligence,chainId:"",addressA:a,addressB:b}),/chain ID/);
});
