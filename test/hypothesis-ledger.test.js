import test from "node:test";
import assert from "node:assert/strict";
import {hypothesisLedgerStorageKey,reconcileHypothesisLedger,recordHypothesisAssessment,summarizeHypothesisLedger} from "../src/hypothesis-ledger.js";
const subject={chainId:"0x1",address:"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
const hypotheses=[{id:"transfer-review",question:"Does this log represent a valid transfer?",why:"A receipt log matched.",verification:"Check receipt and emitting contract.",supportingReferences:["0x"+"1".repeat(64)]}];
const base={subject,hypotheses,createdAt:"2026-10-30T11:00:00.000Z"};
test("creates subject-scoped ledger and preserves hypothesis provenance",()=>{
 const ledger=reconcileHypothesisLedger(base);
 assert.equal(ledger.schema,"sentinel.hypothesis-ledger.v1");
 assert.equal(ledger.entries[0].status,"open");
 assert.deepEqual(ledger.entries[0].supportingReferences,hypotheses[0].supportingReferences);
 assert.match(hypothesisLedgerStorageKey(subject),/0x1:0xaaaa/);
});
test("appends analyst assessments without overwriting history",()=>{
 const initial=reconcileHypothesisLedger(base);
 const first=recordHypothesisAssessment(initial,"transfer-review",{status:"supported",note:"Receipt and contract were independently inspected.",evidenceReference:"case-12/log-4",updatedAt:"2026-10-30T11:05:00.000Z"});
 const second=recordHypothesisAssessment(first,"transfer-review",{status:"inconclusive",note:"Token identity remains uncertain.",updatedAt:"2026-10-30T11:10:00.000Z"});
 assert.equal(initial.entries[0].assessments.length,0);
 assert.equal(second.entries[0].assessments.length,2);
 assert.equal(second.entries[0].status,"inconclusive");
 assert.equal(second.entries[0].assessments[0].status,"supported");
 assert.equal(summarizeHypothesisLedger(second).assessmentCount,2);
});
test("requires analyst rationale and a source for conclusive outcomes",()=>{
 const ledger=reconcileHypothesisLedger(base);
 assert.throws(()=>recordHypothesisAssessment(ledger,"transfer-review",{status:"supported",note:"Looks likely"}),/source reference/);
 assert.throws(()=>recordHypothesisAssessment(ledger,"transfer-review",{status:"inconclusive"}),/note is required/);
 assert.throws(()=>recordHypothesisAssessment(ledger,"missing",{status:"open",note:"Reviewed"}),/does not exist/);
});
test("reconciles new hypotheses while rejecting cross-subject state",()=>{
 const ledger=reconcileHypothesisLedger(base);
 const extended=reconcileHypothesisLedger({...base,ledger,hypotheses:[...hypotheses,{id:"new",question:"Is the sample complete?"}]});
 assert.equal(extended.entries.length,2);
 assert.throws(()=>reconcileHypothesisLedger({...base,ledger:{...ledger,subject:{chainId:"0x89",address:subject.address}}}),/subject mismatch/);
});
