import test from "node:test";
import assert from "node:assert/strict";
import {compareInvestigationSnapshots} from "../src/investigation-snapshot-diff.js";
const subject={chainId:"0x1",address:"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
const tx1="0x"+"1".repeat(64),tx2="0x"+"2".repeat(64);
const event=(transactionHash,blockNumber)=>({kind:"observed-token-transfer-log",chainId:"0x1",blockNumber,transactionHash,logIndex:"0x0",source:"receipt-log",record:{amountRaw:"10"}});
const dossier=(generatedAt,timeline,hypotheses=[{id:"h1",question:"Check it",status:"unverified"}],tasks=[{id:"t1",status:"pending"}])=>({
 schema:"sentinel.investigation-intelligence.v1",generatedAt,subject,timeline,hypotheses,
 evidenceCoverage:{neighborhood:{nodeCount:2}},analystWorkflow:{tasks},
 hypothesisReview:{entries:[{id:"h1",status:"open",assessments:[]}]}
});
test("detects added, retained and no-longer-included observations",()=>{
 const before=dossier("2026-10-30T10:00:00Z",[event(tx1,"0x10")]);
 const after=dossier("2026-10-30T11:00:00Z",[event(tx1,"0x10"),event(tx2,"0x11")]);
 const diff=compareInvestigationSnapshots(before,after);
 assert.deepEqual(diff.evidence.summary,{added:1,retained:1,notInCurrentSnapshot:0,retainedWithChangedRecord:0});
 assert.equal(diff.evidence.added[0].transactionHash,tx2);
});
test("surfaces hypothesis, analyst review and playbook status changes",()=>{
 const before=dossier("2026-10-30T10:00:00Z",[],[{id:"h1",question:"Check it",status:"unverified"}],[{id:"t1",status:"pending"}]);
 const after=dossier("2026-10-30T11:00:00Z",[],[{id:"h1",question:"Check it",status:"unverified"},{id:"h2",question:"New question",status:"unverified"}],[{id:"t1",status:"verified"}]);
 after.hypothesisReview.entries[0].status="supported";after.hypothesisReview.entries[0].assessments=[{revision:1,status:"supported"}];
 const diff=compareInvestigationSnapshots(before,after);
 assert.equal(diff.hypothesisChanges[0].change,"introduced");
 assert.equal(diff.reviewChanges.length,1);
 assert.deepEqual(diff.taskChanges,[{id:"t1",previous:"pending",current:"verified"}]);
});
test("does not claim missing snapshot evidence disappeared on chain",()=>{
 const before=dossier("2026-10-30T10:00:00Z",[event(tx1,"0x10")]);
 const after=dossier("2026-10-30T11:00:00Z",[]);
 const diff=compareInvestigationSnapshots(before,after);
 assert.equal(diff.evidence.summary.notInCurrentSnapshot,1);
 assert.match(diff.limitations[1],/not evidence that an on-chain event disappeared/);
});
test("rejects incompatible subjects and schemas",()=>{
 const before=dossier("2026-10-30T10:00:00Z",[]);
 const after=dossier("2026-10-30T11:00:00Z",[]);
 after.subject={...subject,chainId:"0x89"};
 assert.throws(()=>compareInvestigationSnapshots(before,after),/same chain and subject/);
 assert.throws(()=>compareInvestigationSnapshots({},before),/SENTINEL/);
});
