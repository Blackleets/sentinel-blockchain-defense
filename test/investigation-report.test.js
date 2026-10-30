import test from "node:test";
import assert from "node:assert/strict";
import {buildInvestigationMarkdownReport} from "../src/investigation-report.js";
const dossier={schema:"sentinel.investigation-intelligence.v1",caseId:"case-0x1",generatedAt:"2026-10-30T12:00:00.000Z",
 subject:{chainId:"0x1",address:"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},coverage:"bounded-neighborhood-and-imported-evidence-only",
 assessment:{verdict:"not-assessed",riskScore:null},summary:{entityCount:2,relationshipCount:1,timelineEntryCount:1,hypothesisCount:1,sourceReferenceCount:1,neighborhoodTruncated:false,
  playbook:{total:1,pending:0,inProgress:0,verifiedByAnalyst:1,notApplicable:0},hypothesisReview:{assessmentCount:1}},
 timeline:[{kind:"observed-token-transfer-log",blockNumber:"0x10",transactionHash:"0x"+"1".repeat(64),logIndex:"0x0",source:"receipt-log"}],
 hypotheses:[{id:"transfer-review",question:"Does this log represent a valid transfer?",status:"unverified",why:"A receipt log matched.",verification:"Check the receipt.",supportingReferences:["case-1/log-1"]}],
 hypothesisReview:{entries:[{id:"transfer-review",status:"supported",assessments:[{updatedAt:"2026-10-30T12:01:00Z",status:"supported",note:"Receipt inspected",evidenceReference:"case-1/log-1"}]}]},
 analystWorkflow:{tasks:[{id:"task-1",title:"Validate receipt",status:"verified",evidenceReference:"case-1/log-1",analystNote:"Reviewed"}]},
 evidenceCoverage:{neighborhood:{nodeCount:2},gapAnalysis:{recommendationCount:1},sourceCaseSubjects:[]},
 sourceReferences:["0x"+"1".repeat(64)],limitations:["No external enrichment."]};
test("renders a human-readable report with evidence and review history",()=>{
 const report=buildInvestigationMarkdownReport(dossier);
 assert.match(report,/# SENTINEL — Investigation Report/);
 assert.match(report,/NOT ASSESSED/);
 assert.match(report,/observed-token-transfer-log/);
 assert.match(report,/Receipt inspected/);
 assert.match(report,/Validate receipt/);
 assert.match(report,/No external enrichment\./);
});
test("escapes analyst-controlled markdown and prevents injected headings",()=>{
 const unsafe={...dossier,hypotheses:[{...dossier.hypotheses[0],question:"# Injected heading\n**bold**"}],
  hypothesisReview:{entries:[{id:"transfer-review",status:"open",assessments:[{status:"open",note:"line one\n## fake section",updatedAt:"now"}]}]}};
 const report=buildInvestigationMarkdownReport(unsafe);
 assert.doesNotMatch(report,/\n# Injected heading/);
 assert.doesNotMatch(report,/\n## fake section/);
 assert.match(report,/fake section/);
});
test("rejects non-SENTINEL or incomplete dossiers",()=>{
 assert.throws(()=>buildInvestigationMarkdownReport({}),/SENTINEL investigation intelligence dossier/);
 assert.throws(()=>buildInvestigationMarkdownReport({...dossier,timeline:null}),/timeline/);
});
