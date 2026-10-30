import test from "node:test";
import assert from "node:assert/strict";
import {hypothesisLedgerStorageKey,reconcileHypothesisLedger,recordHypothesisAssessment,mergeHypothesisLedgers} from "../src/hypothesis-ledger.js";
const subject={chainId:"0x1",address:"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
const otherSubject={chainId:"0x89",address:subject.address};
const hypotheses=[{id:"transfer-review",question:"Does this log represent a valid transfer?",why:"Receipt log matched.",verification:"Inspect receipt.",supportingReferences:["tx-1"]}];
const base={subject,hypotheses,createdAt:"2026-10-30T11:00:00.000Z"};
const reviewed=(status,note,reference,time)=>recordHypothesisAssessment(reconcileHypothesisLedger(base),"transfer-review",{status,note,evidenceReference:reference,updatedAt:time});
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
test("imports a new portable ledger and keeps its complete review history",()=>{
 const imported=reviewed("supported","Receipt independently checked.","case-1/log-2","2026-10-30T11:05:00.000Z");
 const result=mergeHypothesisLedgers({imported,subject,mergedAt:"2026-10-30T11:10:00.000Z"});
 assert.equal(result.summary.addedEntries,1);
 assert.equal(result.summary.addedAssessments,1);
 assert.equal(result.ledger.entries[0].status,"supported");
 assert.equal(result.ledger.entries[0].assessments.length,1);
});
test("merges new sequential assessments and deduplicates identical imported history",()=>{
 const local=reviewed("supported","Checked receipt.","case-1/log-2","2026-10-30T11:05:00.000Z");
 const imported=recordHypothesisAssessment(local,"transfer-review",{status:"inconclusive",note:"Contract identity unresolved.",updatedAt:"2026-10-30T11:10:00.000Z"});
 const first=mergeHypothesisLedgers({current:local,imported,subject});
 assert.equal(first.summary.addedAssessments,1);
 assert.equal(first.ledger.entries[0].assessments.length,2);
 const repeat=mergeHypothesisLedgers({current:first.ledger,imported,subject});
 assert.equal(repeat.summary.duplicateAssessments,2);
 assert.equal(repeat.summary.addedAssessments,0);
 assert.equal(repeat.ledger.entries[0].assessments.length,2);
});
test("reports competing histories without overwriting the local assessment",()=>{
 const local=reviewed("supported","Local review.","case-local","2026-10-30T11:05:00.000Z");
 const imported=reviewed("not-supported","Conflicting imported review.","case-imported","2026-10-30T11:06:00.000Z");
 const result=mergeHypothesisLedgers({current:local,imported,subject});
 assert.equal(result.summary.conflicts,1);
 assert.equal(result.conflicts[0].reason,"same-assessment-id-different-content");
 assert.equal(result.ledger.entries[0].assessments[0].note,"Local review.");
});
test("rejects cross-subject, malformed and non-sequential imported histories",()=>{
 const local=reconcileHypothesisLedger(base());
 assert.throws(()=>mergeHypothesisLedgers({current:local,imported:local,subject:otherSubject}),/different chain or subject/);
 const malformed=reviewed("supported","Checked.","case-1","2026-10-30T11:05:00.000Z");
 malformed.entries[0].assessments[0].revision=4;
 assert.throws(()=>mergeHypothesisLedgers({current:local,imported:malformed,subject}),/non-sequential assessment history/);
});
