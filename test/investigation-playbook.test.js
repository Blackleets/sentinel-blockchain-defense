import test from "node:test";
import assert from "node:assert/strict";
import {createInvestigationPlaybook,updateInvestigationTask,summarizeInvestigationPlaybook,investigationPlaybookStorageKey} from "../src/investigation-playbook.js";
const address="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const analysis={schema:"sentinel.evidence-gap-analysis.v1",generatedAt:"2026-10-30T10:00:00.000Z",coverage:"bounded",subject:{chainId:"0x1",address},recommendations:[
 {id:"check-receipt",priority:"high",title:"Check receipt",why:"A log was observed.",check:"Open the receipt.",gap:"Receipt provenance",evidence:["0x"+"1".repeat(64)]},
 {id:"check-history",priority:"normal",title:"Check history",why:"Coverage is limited.",check:"Inspect history.",gap:"History coverage",evidence:[]}
]};
test("creates a deterministic task list from analysis with all tasks pending",()=>{
 const playbook=createInvestigationPlaybook(analysis,{createdAt:"2026-10-30T10:00:00.000Z"});
 assert.equal(playbook.schema,"sentinel.investigation-playbook.v1");
 assert.equal(playbook.tasks.length,2);
 assert.equal(playbook.tasks[0].status,"pending");
 assert.equal(summarizeInvestigationPlaybook(playbook).highPriorityOpen,1);
});
test("requires a reference before an analyst can mark a task verified",()=>{
 const playbook=createInvestigationPlaybook(analysis);
 assert.throws(()=>updateInvestigationTask(playbook,"check-receipt",{status:"verified"}),/evidence reference/);
});
test("records analyst status, evidence reference and append-only history",()=>{
 const playbook=createInvestigationPlaybook(analysis,{createdAt:"2026-10-30T10:00:00.000Z"});
 const next=updateInvestigationTask(playbook,"check-receipt",{status:"verified",evidenceReference:"Explorer receipt URL / internal case #42",analystNote:"Receipt checked against block and log index."},{updatedAt:"2026-10-30T11:00:00.000Z"});
 assert.equal(next.tasks[0].status,"verified");
 assert.equal(next.tasks[0].history.length,2);
 assert.equal(playbook.tasks[0].status,"pending","updates do not mutate the original playbook");
 assert.equal(summarizeInvestigationPlaybook(next).completionPercent,50);
});
test("supports in-progress and not-applicable states and safe storage keys",()=>{
 let playbook=createInvestigationPlaybook(analysis);
 playbook=updateInvestigationTask(playbook,"check-receipt",{status:"in-progress"});
 playbook=updateInvestigationTask(playbook,"check-history",{status:"not-applicable",analystNote:"Not relevant to this investigation."});
 assert.equal(summarizeInvestigationPlaybook(playbook).inProgress,1);
 assert.equal(summarizeInvestigationPlaybook(playbook).notApplicable,1);
 assert.equal(investigationPlaybookStorageKey({chainId:"0x1",address}),"sentinel:investigation-playbook:v1:0x1:"+address);
});
test("rejects invalid playbook, task and status values",()=>{
 assert.throws(()=>createInvestigationPlaybook({}),/analysis/);
 const playbook=createInvestigationPlaybook(analysis);
 assert.throws(()=>updateInvestigationTask(playbook,"missing",{status:"verified",evidenceReference:"x"}),/not found/);
 assert.throws(()=>updateInvestigationTask(playbook,"check-receipt",{status:"unknown"}),/status/);
});
