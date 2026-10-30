import test from "node:test";
import assert from "node:assert/strict";
import {buildInvestigationIntelligence} from "../src/investigation-intelligence.js";
const address="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const other="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const hash="0x"+"1".repeat(64);
const neighborhood={schema:"sentinel.entity-neighborhood.v1",subject:{chainId:"0x1",address},nodes:[{address},{address:other}],edges:[
 {id:"edge-transfer",chainId:"0x1",type:"observed-token-transfer-log",from:address,to:other,source:"receipt-log",evidence:[{transactionHash:hash,blockNumber:"0x10",logIndex:"0x2"}]}
],summary:{nodeCount:2,edgeCount:1,truncated:false},limitations:["bounded"]};
const graph={schema:"sentinel.correlation-graph.v1",edges:[]};
const threatIntelligence={schema:"sentinel.threat-intelligence.v1",signals:[],timelines:[],
 tokenTransfers:[{chainId:"0x1",from:address,to:other,transactionHash:hash,blockNumber:"0x10",logIndex:"0x2",token:other,amountRaw:"5",caseSubject:address}],
 transactionLinks:[{chainId:"0x1",from:address,via:other,to:address,transactionHashes:[hash]}]};
const gapAnalysis={schema:"sentinel.evidence-gap-analysis.v1",subject:{chainId:"0x1",address},summary:{recommendationCount:1},recommendations:[{id:"validate",evidence:[hash]}],limitations:["gaps"]};
const playbook={schema:"sentinel.investigation-playbook.v1",id:"playbook-1",subject:{chainId:"0x1",address},updatedAt:"2026-10-30T10:00:00.000Z",tasks:[{id:"validate",status:"pending",title:"Validate receipt"}],limitations:["workflow"]};
const inputs={neighborhood,graph,threatIntelligence,gapAnalysis,playbook,generatedAt:"2026-10-30T10:00:00.000Z"};
test("builds a reproducible, explicitly unassessed dossier from supplied evidence",()=>{
 const dossier=buildInvestigationIntelligence(inputs);
 assert.equal(dossier.schema,"sentinel.investigation-intelligence.v1");
 assert.equal(dossier.assessment.verdict,"not-assessed");
 assert.equal(dossier.assessment.riskScore,null);
 assert.equal(dossier.summary.timelineEntryCount,3);
 assert.equal(dossier.summary.hypothesisCount,2);
 assert.ok(dossier.timeline.every(item=>item.transactionHash===hash));
 assert.ok(dossier.hypotheses.every(item=>item.status==="unverified"));
 assert.equal(dossier.analystWorkflow.tasks[0].status,"pending");
 assert.ok(dossier.limitations.includes("gaps"));
});
test("sorts known block numbers numerically and keeps unknown blocks last",()=>{
 const data={...inputs,neighborhood:{...neighborhood,edges:[
  {id:"later",chainId:"0x1",type:"observed-transaction-flow",from:address,to:other,source:"correlation-graph",evidence:[{blockNumber:"0x100"}]},
  {id:"earlier",chainId:"0x1",type:"observed-transaction-flow",from:address,to:other,source:"correlation-graph",evidence:[{blockNumber:"0x2"}]},
  {id:"unknown",chainId:"0x1",type:"observed-transaction-flow",from:address,to:other,source:"correlation-graph",evidence:[{}]}
 ]}};
 const result=buildInvestigationIntelligence(data);
 const blocks=result.timeline.map(item=>item.blockNumber);\n assert.deepEqual(blocks.filter(value=>value!==null),["0x2","0x10","0x100"]);\n assert.ok(blocks.slice(-2).every(value=>value===null));
});
test("rejects mismatched subjects and invalid source artifacts",()=>{
 assert.throws(()=>buildInvestigationIntelligence({...inputs,playbook:{...playbook,subject:{chainId:"0x89",address}}}),/does not match/);
 assert.throws(()=>buildInvestigationIntelligence({...inputs,gapAnalysis:null}),/gap analysis/);
});
test("hypotheses remain verification questions rather than attribution claims",()=>{
 const result=buildInvestigationIntelligence(inputs);
 assert.match(result.hypotheses.find(item=>item.id==="transfer-log-semantics").question,/Transfer-shaped logs/);
 assert.match(result.hypotheses.find(item=>item.id==="handoff-asset-continuity").verification,/each leg/);
 assert.equal(result.assessment.riskScore,null);
});
