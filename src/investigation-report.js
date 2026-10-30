const clean=value=>String(value??"").replace(/\\/g,"\\\\").replace(/([\\`*_{}\[\]()#+.!|>~])/g,"\\$1").replace(/[\r\n]+/g," ");
const code=value=>"`"+String(value??"").replace(/`/g,"\\`").replace(/[\r\n]+/g," ")+"`";
const list=(items,render,empty="None recorded.")=>items?.length?items.map(item=>"- "+render(item)).join("\n"): "- "+empty;
const count=(value)=>Number.isFinite(value)?String(value):"Not available";
function validate(dossier){
 if(!dossier||dossier.schema!=="sentinel.investigation-intelligence.v1")throw new TypeError("A SENTINEL investigation intelligence dossier is required");
 if(!dossier.subject||typeof dossier.subject.chainId!=="string"||typeof dossier.subject.address!=="string")throw new TypeError("Dossier subject is missing");
 if(!Array.isArray(dossier.timeline)||!Array.isArray(dossier.hypotheses)||!Array.isArray(dossier.limitations))throw new TypeError("Dossier timeline, hypotheses or limitations are missing");
}
export function buildInvestigationMarkdownReport(dossier){
 validate(dossier);
 const subject=dossier.subject,summary=dossier.summary||{},review=dossier.hypothesisReview?.entries||[],tasks=dossier.analystWorkflow?.tasks||[];
 const reviewsById=new Map(review.map(item=>[item.id,item]));
 const lines=[
 "# SENTINEL — Investigation Report",
 "",
 "> Evidence-led case report. This document describes the supplied dossier snapshot; it is not an automated security verdict.",
 "",
 "## Case metadata",
 "",
 "| Field | Value |",
 "|---|---|",
 "| Case ID | "+code(dossier.caseId)+" |",
 "| Chain ID | "+code(subject.chainId)+" |",
 "| Subject | "+code(subject.address)+" |",
 "| Dossier generated | "+clean(dossier.generatedAt||"Not recorded")+" |",
 "| Coverage | "+clean(dossier.coverage||"Not specified")+" |",
 "| Assessment | **NOT ASSESSED** |",
 "| Risk score | Not assigned |",
 "",
 "## Executive snapshot",
 "",
 "- Entities in bounded neighborhood: "+count(summary.entityCount),
 "- Relationships in bounded neighborhood: "+count(summary.relationshipCount),
 "- Timeline observations: "+count(summary.timelineEntryCount),
 "- Generated hypotheses: "+count(summary.hypothesisCount),
 "- Source references: "+count(summary.sourceReferenceCount),
 "- Neighborhood truncated: "+(summary.neighborhoodTruncated?"Yes":"No"),
 "- Analyst tasks: "+count(summary.playbook?.total)+" total; "+count(summary.playbook?.pending)+" pending; "+count(summary.playbook?.inProgress)+" in progress; "+count(summary.playbook?.verifiedByAnalyst)+" marked verified by analyst; "+count(summary.playbook?.notApplicable)+" not applicable",
 "- Analyst assessments: "+count(summary.hypothesisReview?.assessmentCount),
 "",
 "## Scope and method",
 "",
 "This report is assembled from the bounded entity neighborhood, imported threat-intelligence observations, evidence-gap analysis, analyst playbook and any saved hypothesis-review ledger included in the dossier. It performs no external RPC calls, explorer lookups or independent validation.",
 "",
 "## Evidence timeline",
 "",
 list(dossier.timeline,(item)=>[
  "**"+clean(item.kind)+"**",
  item.blockNumber!==null&&item.blockNumber!==undefined?"block "+code(item.blockNumber):"block unknown",
  item.transactionHash?"tx "+code(item.transactionHash):"no transaction hash",
  item.logIndex!==null&&item.logIndex!==undefined?"log "+code(item.logIndex):"",
  "source "+clean(item.source||"unspecified")
 ].filter(Boolean).join(" · ")),
 "",
 "## Testable hypotheses and analyst review",
 ""
 ];
 if(dossier.hypotheses.length){
  for(const hypothesis of dossier.hypotheses){
   const entry=reviewsById.get(hypothesis.id);
   lines.push("### "+clean(hypothesis.question||hypothesis.id),"",
    "- Hypothesis ID: "+code(hypothesis.id),
    "- Machine-generated status: "+clean(hypothesis.status||"unverified"),
    "- Rationale for review: "+clean(hypothesis.why||"Not supplied"),
    "- Verification procedure: "+clean(hypothesis.verification||"Not supplied"),
    "- Supporting references: "+(hypothesis.supportingReferences?.length?hypothesis.supportingReferences.map(code).join(", "):"None recorded"),
    "- Latest analyst status: "+clean(entry?.status||"Not reviewed"),
    "");
   if(entry?.assessments?.length){
    lines.push("Analyst assessment history:");
    for(const assessment of entry.assessments){
     lines.push("- "+clean(assessment.updatedAt||"Date not recorded")+" · "+clean(assessment.status)+" · "+clean(assessment.note)+" · reference: "+(assessment.evidenceReference?code(assessment.evidenceReference):"none supplied"));
    }
    lines.push("");
   }
  }
 }else lines.push("- No hypotheses were generated.","");
 lines.push("## Analyst task register","","| Task | Status | Evidence reference | Analyst note |","|---|---|---|---|");
 if(tasks.length){
  for(const task of tasks)lines.push("| "+clean(task.title||task.id)+" | "+clean(task.status)+" | "+(task.evidenceReference?code(task.evidenceReference):"—")+" | "+clean(task.analystNote||"—")+" |");
 }else lines.push("| No tasks recorded | — | — | — |");
 lines.push("","## Evidence coverage","","- Neighborhood: "+clean(JSON.stringify(dossier.evidenceCoverage?.neighborhood||{})),
  "- Gap analysis: "+clean(JSON.stringify(dossier.evidenceCoverage?.gapAnalysis||{})),
  "- Source case subjects: "+(dossier.evidenceCoverage?.sourceCaseSubjects?.length?dossier.evidenceCoverage.sourceCaseSubjects.map(code).join(", "):"None recorded"),
  "",
  "## Source references","",
  list(dossier.sourceReferences||[],code),
  "",
  "## Limitations and interpretation",
  "",
  list(dossier.limitations,item=>clean(item)),
  "",
  "Analyst statuses and references are recorded as supplied. A reference is not fetched or authenticated by SENTINEL. The absence of an observation from this bounded snapshot does not establish its absence from the blockchain.",
  "",
  "---",
  "",
  "Generated by SENTINEL. Preserve the original sealed JSON dossier alongside this human-readable report for integrity verification and reproducibility.",
  "");
 return lines.join("\n");
}
