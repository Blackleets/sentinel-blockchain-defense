import test from "node:test";
import assert from "node:assert/strict";
import {validateInvestigationDossier} from "../src/investigation-dossier-validation.js";
const address="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const tx="0x"+"1".repeat(64);
const base=()=>({
 schema:"sentinel.investigation-intelligence.v1",caseId:"case-0x1-"+address,generatedAt:"2026-10-30T12:00:00.000Z",
 subject:{chainId:"0x1",address},coverage:"bounded-neighborhood-and-imported-evidence-only",
 assessment:{verdict:"not-assessed",riskScore:null},
 summary:{timelineEntryCount:1,hypothesisCount:1,sourceReferenceCount:1,hypothesisReview:{total:1,open:1,supported:0,notSupported:0,inconclusive:0,assessmentCount:0},neighborhoodTruncated:false},
 timeline:[{kind:"observed-token-transfer-log",chainId:"0x1",blockNumber:"0x10",transactionHash:tx,logIndex:"0x0",transactionIndex:"0x0",subject:address,source:"receipt-log",record:{edgeId:"edge-1"}}],
 hypotheses:[{id:"transfer-review",question:"Does the event represent a valid token transfer?",why:"A receipt log matched.",verification:"Inspect receipt and token contract.",supportingReferences:[tx],status:"unverified"}],
 sourceReferences:[tx],evidenceCoverage:{neighborhood:{truncated:false}},analystWorkflow:{playbookId:"p1",tasks:[{id:"task-1",status:"pending",evidenceReference:""}]},
 hypothesisReview:{schema:"sentinel.hypothesis-ledger.v1",subject:{chainId:"0x1",address},entries:[{id:"transfer-review",status:"open",assessments:[]}]},
 limitations:["bounded evidence only"]
});
test("accepts a structurally coherent dossier but never claims source verification",()=>{
 const result=validateInvestigationDossier(base());
 assert.equal(result.valid,true);
 assert.equal(result.structuralStatus,"valid");
 assert.equal(result.sourceVerification,"not-performed");
 assert.equal(result.summary.timelineEntries,1);
});
test("rejects malformed schema, subject, assessment or summary counts",()=>{
 const dossier=base();dossier.schema="unknown";dossier.subject.address="not-an-address";dossier.assessment.riskScore=5;dossier.summary.timelineEntryCount=9;
 const result=validateInvestigationDossier(dossier);
 assert.equal(result.valid,false);
 assert.ok(result.errors.length>=4);
});
test("rejects cross-chain timeline observations and malformed transaction hashes",()=>{
 const dossier=base();dossier.timeline[0].chainId="0x89";dossier.timeline[0].transactionHash="0x1234";
 const result=validateInvestigationDossier(dossier);
 assert.ok(result.errors.some(item=>item.includes("outside the dossier subject chain")));
 assert.ok(result.errors.some(item=>item.includes("invalid transaction hash")));
});
test("requires references for verified tasks and conclusive analyst reviews",()=>{
 const dossier=base();dossier.analystWorkflow.tasks[0].status="verified";
 dossier.hypothesisReview.entries[0]={id:"transfer-review",status:"supported",assessments:[{revision:1,status:"supported",note:"Checked",evidenceReference:null,updatedAt:"2026-10-30T12:00:00.000Z"}]};
 dossier.summary.hypothesisReview={total:1,open:0,supported:1,notSupported:0,inconclusive:0,assessmentCount:1};
 const result=validateInvestigationDossier(dossier);
 assert.ok(result.errors.some(item=>item.includes("Verified task")));
 assert.ok(result.errors.some(item=>item.includes("Conclusive assessment")));
});
test("reports bounded coverage and retained historical ledger hypotheses as warnings",()=>{
 const dossier=base();dossier.summary.neighborhoodTruncated=true;dossier.evidenceCoverage.neighborhood.truncated=true;
 dossier.hypothesisReview.entries.push({id:"old-hypothesis",status:"inconclusive",assessments:[]});
 dossier.summary.hypothesisReview.total=2;dossier.summary.hypothesisReview.open=1;dossier.summary.hypothesisReview.inconclusive=1;
 const result=validateInvestigationDossier(dossier);
 assert.equal(result.valid,true);
 assert.ok(result.warnings.some(item=>item.includes("not generated in this snapshot")));
 assert.ok(result.warnings.some(item=>item.includes("truncated")));
});
test("rejects duplicate IDs and malformed review history",()=>{
 const dossier=base();dossier.analystWorkflow.tasks.push({id:"task-1",status:"pending"});
 dossier.hypothesisReview.entries[0].assessments=[{revision:2,status:"supported",note:"checked",evidenceReference:"case/log",updatedAt:"2026-10-30T12:00:00.000Z"}];
 dossier.summary.hypothesisReview.assessmentCount=1;
 const result=validateInvestigationDossier(dossier);
 assert.ok(result.errors.some(item=>item.includes("Duplicate playbook task ID")));
 assert.ok(result.errors.some(item=>item.includes("non-sequential assessment revision")));
});
test("handles non-object inputs without throwing",()=>{
 const result=validateInvestigationDossier(null);
 assert.equal(result.valid,false);
 assert.equal(result.sourceVerification,"not-performed");
});
