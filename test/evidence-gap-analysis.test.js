import test from "node:test";
import assert from "node:assert/strict";
import {analyzeEvidenceGaps} from "../src/evidence-gap-analysis.js";
const a="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",b="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const tx="0x"+"1".repeat(64);
const base={schema:"sentinel.entity-neighborhood.v1",subject:{chainId:"0x1",address:a},nodes:[{address:a}],edges:[],summary:{truncated:false,truncatedNodes:false,truncatedEdges:false}};
const graph={schema:"sentinel.correlation-graph.v1",edges:[]};
const intel={schema:"sentinel.threat-intelligence.v1",signals:[],tokenTransfers:[],transactionLinks:[]};
test("returns a bounded-coverage prompt when no specific gap rule fires",()=>{
 const result=analyzeEvidenceGaps({neighborhood:base,graph,threatIntelligence:intel});
 assert.equal(result.schema,"sentinel.evidence-gap-analysis.v1");
 assert.equal(result.summary.recommendationCount,1);
 assert.equal(result.recommendations[0].id,"broaden-source-coverage");
 assert.equal(result.assessment.verdict,"not-assessed");
});
test("prioritizes explicit neighborhood truncation and does not hide its cause",()=>{
 const neighborhood={...base,summary:{truncated:true,truncatedNodes:true,truncatedEdges:false}};
 const result=analyzeEvidenceGaps({neighborhood,graph,threatIntelligence:intel});
 assert.equal(result.recommendations[0].id,"expand-truncated-neighborhood");
 assert.equal(result.recommendations[0].priority,"high");
});
test("recommends receipt and token-contract validation for imported transfer-shaped logs",()=>{
 const threatIntelligence={...intel,tokenTransfers:[{chainId:"0x1",from:a,to:b,transactionHash:tx,blockNumber:"0x10",logIndex:"0x0"}]};
 const result=analyzeEvidenceGaps({neighborhood:base,graph,threatIntelligence});
 assert.ok(result.recommendations.some(item=>item.id==="validate-transfer-receipts"));
 assert.match(result.recommendations.find(item=>item.id==="validate-transfer-receipts").check,/decimals/);
});
test("recommends verification of handoff legs without claiming asset movement",()=>{
 const threatIntelligence={...intel,transactionLinks:[{chainId:"0x1",from:a,via:b,to:a,transactionHashes:[tx]}]};
 const result=analyzeEvidenceGaps({neighborhood:base,graph,threatIntelligence});
 assert.ok(result.recommendations.some(item=>item.id==="verify-handoff-receipts"));
 assert.ok(result.limitations.some(item=>item.includes("movement of the same assets")));
});
test("detects direct relationship provenance gaps and rejects invalid input",()=>{
 const neighborhood={...base,edges:[{id:"edge-1",chainId:"0x1",from:a,to:b,type:"observed-transaction-flow",evidence:[]}]};
 const result=analyzeEvidenceGaps({neighborhood,graph,threatIntelligence:intel});
 assert.ok(result.recommendations.some(item=>item.id==="recover-transaction-identifiers"));
 assert.throws(()=>analyzeEvidenceGaps({neighborhood:{},graph,threatIntelligence:intel}),/neighborhood/);
});
