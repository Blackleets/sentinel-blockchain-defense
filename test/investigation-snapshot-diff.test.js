import test from "node:test";
import assert from "node:assert/strict";
import {compareInvestigationSnapshots} from "../src/investigation-snapshot-diff.js";
const subject={chainId:"0x1",address:"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
const tx1="0x"+"1".repeat(64),tx2="0x"+"2".repeat(64);
const event=(transactionHash,blockNumber,amountRaw="10")=>({kind:"observed-token-transfer-log",chainId:"0x1",blockNumber,transactionHash,logIndex:"0x0",source:"receipt-log",record:{amountRaw}});
const dossier=(generatedAt,timeline,hypotheses=[{id:"h1",question:"Check it",status:"unverified"}],tasks=[{id:"t1",status:"pending"}])=>({
 schema:"sentinel.investigation-intelligence.v1",caseId:"case-0x1-0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 generatedAt,subject,timeline,hypotheses,sourceReferences:timeline.map(item=>item.transactionHash).filter(Boolean),
 evidenceCoverage:{neighborhood:{nodeCount:2}},analystWorkflow:{tasks},
 hypothesisReview:{entries:[{id:"h1",status:"open",assessments:[]}]}
});
test("detects added, retained and no-longer-included observations",()=>{
 const before=dossier("2026-10-30T10:00:00Z",[event(tx1,"0x10")]);
 const after=dossier("2026-10-30T11:00:00Z",[event(tx1,"0x10"),event(tx2,"0x11")]);
 const diff=compareInvestigationSnapshots(before,after);
 assert.deepEqual(diff.evidence.summary,{added:1,retained:1,notInCurrentSnapshot:0,retainedWithChangedRecord:0});
 assert.equal(diff.evidence.added[0].transactionHash,tx2);
 assert.deepEqual(diff.sourceReferences.added,[tx2]);
 assert.equal(diff.summary.addedEvidence,1);
});
test("surfaces hypothesis, analyst review and playbook status changes",()=>{
 const before=dossier("2026-10-30T10:00:00Z",[],[{id:"h1",question:"Check it",status:"unverified"}],[{id:"t1",status:"pending"}]);
 const after=dossier("2026-10-30T11:00:00Z",[],[{id:"h1",question:"Check it",status:"unverified"},{id:"h2",question:"New question",status:"unverified"}],[{id:"t1",status:"verified"},{id:"t2",status:"pending"}]);
 after.hypothesisReview.entries[0].status="supported";after.hypothesisReview.entries[0].assessments=[{id:"review-1",revision:1,status:"supported"}];
 const diff=compareInvestigationSnapshots(before,after);
 assert.equal(diff.hypothesisChanges[0].change,"introduced");
 assert.equal(diff.reviewChanges.length,1);
 assert.equal(diff.reviewChanges[0].appendedAssessments.length,1);
 assert.deepEqual(diff.taskChanges,[{id:"t1",change:"status-changed",previous:"pending",current:"verified"},{id:"t2",change:"introduced",previous:null,current:"pending"}]);
});
test("does not claim missing snapshot evidence disappeared on chain",()=>{
 const before=dossier("2026-10-30T10:00:00Z",[event(tx1,"0x10")]);
 const after=dossier("2026-10-30T11:00:00Z",[]);
 const diff=compareInvestigationSnapshots(before,after);
 assert.equal(diff.evidence.summary.notInCurrentSnapshot,1);
 assert.match(diff.limitations[1],/not evidence that an on-chain event disappeared/);
});
test("compares duplicate event identities as a multiset",()=>{
 const one=event(tx1,"0x10"),two=event(tx1,"0x10");
 const before=dossier("2026-10-30T10:00:00Z",[one,two]);
 const after=dossier("2026-10-30T11:00:00Z",[one]);
 const diff=compareInvestigationSnapshots(before,after);
 assert.equal(diff.evidence.summary.retained,1);
 assert.equal(diff.evidence.summary.notInCurrentSnapshot,1);
});
test("detects changed retained records without misclassifying them as new evidence",()=>{
 const before=dossier("2026-10-30T10:00:00Z",[event(tx1,"0x10","10")]);
 const after=dossier("2026-10-30T11:00:00Z",[event(tx1,"0x10","11")]);
 const diff=compareInvestigationSnapshots(before,after);
 assert.equal(diff.evidence.summary.added,0);
 assert.equal(diff.evidence.summary.retainedWithChangedRecord,1);
});
test("rejects incompatible subjects, cases, schemas and malformed dossiers",()=>{
 const before=dossier("2026-10-30T10:00:00Z",[]);
 const after=dossier("2026-10-30T11:00:00Z",[]);
 after.subject={...subject,chainId:"0x89"};
 assert.throws(()=>compareInvestigationSnapshots(before,after),/same chain and subject/);
 assert.throws(()=>compareInvestigationSnapshots(before,{...after,subject,caseId:"another-case"}),/same case ID/);
 assert.throws(()=>compareInvestigationSnapshots({},before),/SENTINEL/);
 assert.throws(()=>compareInvestigationSnapshots(before,{...after,subject,generatedAt:"bad-date",caseId:before.caseId}),/timestamp/);
 assert.throws(()=>compareInvestigationSnapshots(before,{...after,subject,caseId:before.caseId,sourceReferences:null}),/source references/);
});
