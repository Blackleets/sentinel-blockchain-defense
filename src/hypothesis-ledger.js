const ADDRESS=/^0x[0-9a-f]{40}$/i;
const STATUSES=new Set(["open","supported","not-supported","inconclusive"]);
const clone=value=>JSON.parse(JSON.stringify(value));
const cleanSubject=subject=>{
 if(!subject||typeof subject.chainId!=="string"||!ADDRESS.test(subject.address||""))throw new TypeError("A valid chain and EVM subject address are required");
 return {chainId:subject.chainId.toLowerCase(),address:subject.address.toLowerCase()};
};
const validDate=value=>typeof value==="string"&&!Number.isNaN(Date.parse(value));
export function hypothesisLedgerStorageKey(subject){
 const clean=cleanSubject(subject);
 return "sentinel:hypothesis-ledger:v1:"+clean.chainId+":"+clean.address;
}
/** Keep analyst assessments separate from machine-generated hypothesis suggestions. */
export function reconcileHypothesisLedger({ledger,subject,hypotheses,createdAt=new Date().toISOString()}){
 const normalized=cleanSubject(subject);
 if(!validDate(createdAt))throw new TypeError("createdAt must be a valid date string");
 if(!Array.isArray(hypotheses))throw new TypeError("hypotheses must be an array");
 if(ledger&&(ledger.schema!=="sentinel.hypothesis-ledger.v1"||ledger.subject?.chainId!==normalized.chainId||ledger.subject?.address!==normalized.address))throw new TypeError("Hypothesis ledger schema or subject mismatch");
 const result=ledger?clone(ledger):{schema:"sentinel.hypothesis-ledger.v1",subject:normalized,createdAt,updatedAt:createdAt,entries:[],limitations:[
  "Assessments are analyst-entered interpretations, not automated validation or proof.",
  "A cited evidence reference is recorded as supplied and is not fetched or authenticated by SENTINEL."
 ]};
 const byId=new Map(result.entries.map(entry=>[entry.id,entry]));
 for(const hypothesis of hypotheses){
  if(!hypothesis||typeof hypothesis.id!=="string"||!hypothesis.id.trim()||typeof hypothesis.question!=="string")throw new TypeError("Each hypothesis requires a stable id and question");
  const current=byId.get(hypothesis.id);
  if(current){current.question=hypothesis.question;current.why=hypothesis.why||current.why;current.verification=hypothesis.verification||current.verification;current.supportingReferences=[...new Set(hypothesis.supportingReferences||[])];}
  else{
   const entry={id:hypothesis.id,question:hypothesis.question,why:hypothesis.why||"",verification:hypothesis.verification||"",
    supportingReferences:[...new Set(hypothesis.supportingReferences||[])],status:"open",assessments:[]};
   result.entries.push(entry);byId.set(entry.id,entry);
  }
 }
 result.updatedAt=createdAt;
 return result;
}
/** Append a new analyst assessment; prior assessments are never overwritten. */
export function recordHypothesisAssessment(ledger,hypothesisId,{status,note,evidenceReference="",updatedAt=new Date().toISOString(),analyst="analyst"}={}){
 if(!ledger||ledger.schema!=="sentinel.hypothesis-ledger.v1"||!Array.isArray(ledger.entries))throw new TypeError("A valid SENTINEL hypothesis ledger is required");
 if(!STATUSES.has(status))throw new TypeError("Unsupported hypothesis assessment status");
 if(!validDate(updatedAt))throw new TypeError("updatedAt must be a valid date string");
 if(typeof note!=="string"||!note.trim())throw new TypeError("An analyst note is required for every assessment");
 if(typeof evidenceReference!=="string")throw new TypeError("evidenceReference must be a string");
 if((status==="supported"||status==="not-supported")&&!evidenceReference.trim())throw new TypeError("A source reference is required for supported or not-supported assessments");
 if(typeof analyst!=="string"||!analyst.trim())throw new TypeError("analyst must be a non-empty label");
 const index=ledger.entries.findIndex(entry=>entry.id===hypothesisId);
 if(index<0)throw new TypeError("Hypothesis does not exist in this ledger");
 const next=clone(ledger),entry=next.entries[index];
 const assessment={id:entry.id+"-assessment-"+String(entry.assessments.length+1).padStart(4,"0"),
  revision:entry.assessments.length+1,status,note:note.trim(),evidenceReference:evidenceReference.trim()||null,
  analyst:analyst.trim(),updatedAt};
 entry.assessments.push(assessment);entry.status=status;entry.latestAssessment=assessment.id;
 next.updatedAt=updatedAt;
 return next;
}
export function summarizeHypothesisLedger(ledger){
 const entries=ledger?.entries||[];
 return {total:entries.length,open:entries.filter(item=>item.status==="open").length,
  supported:entries.filter(item=>item.status==="supported").length,
  notSupported:entries.filter(item=>item.status==="not-supported").length,
  inconclusive:entries.filter(item=>item.status==="inconclusive").length,
  assessmentCount:entries.reduce((sum,item)=>sum+item.assessments.length,0)};
}

const sameAssessment=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
function validateLedger(ledger,subject,label){
 if(!ledger||ledger.schema!=="sentinel.hypothesis-ledger.v1"||!Array.isArray(ledger.entries))throw new TypeError(label+" is not a valid SENTINEL hypothesis ledger");
 if(ledger.subject?.chainId?.toLowerCase()!==subject.chainId||ledger.subject?.address?.toLowerCase()!==subject.address)throw new TypeError(label+" belongs to a different chain or subject address");
 if(!validDate(ledger.createdAt)||!validDate(ledger.updatedAt))throw new TypeError(label+" has invalid creation or update timestamps");
 const ids=new Set();
 for(const entry of ledger.entries){
  if(!entry||typeof entry.id!=="string"||!entry.id.trim()||ids.has(entry.id))throw new TypeError(label+" contains a missing or duplicate hypothesis ID");
  ids.add(entry.id);
  if(!STATUSES.has(entry.status)||!Array.isArray(entry.assessments))throw new TypeError(label+" contains an invalid hypothesis review entry");
  if(entry.assessments.length===0&&entry.status!=="open")throw new TypeError(label+" has a reviewed status without an assessment history");
  entry.assessments.forEach((assessment,index)=>{
   if(!assessment||typeof assessment.id!=="string"||!assessment.id.trim()||assessment.revision!==index+1||!STATUSES.has(assessment.status)||!validDate(assessment.updatedAt)||typeof assessment.note!=="string"||!assessment.note.trim()||typeof assessment.analyst!=="string"||!assessment.analyst.trim())throw new TypeError(label+" contains an invalid or non-sequential assessment history");
   if((assessment.status==="supported"||assessment.status==="not-supported")&&(typeof assessment.evidenceReference!=="string"||!assessment.evidenceReference.trim()))throw new TypeError(label+" contains a conclusive assessment without an evidence reference");
   if(assessment.evidenceReference!==null&&assessment.evidenceReference!==undefined&&typeof assessment.evidenceReference!=="string")throw new TypeError(label+" contains a malformed evidence reference");
  });
  if(entry.assessments.length&&(entry.status!==entry.assessments.at(-1).status||entry.latestAssessment!==entry.assessments.at(-1).id))throw new TypeError(label+" has a status that does not match its latest assessment");
 }
 return true;
}
/**
 * Merge a portable analyst ledger without deleting or silently replacing history.
 * Identical assessment IDs/content are deduplicated; competing histories are reported as conflicts.
 */
export function mergeHypothesisLedgers({current,imported,subject,mergedAt=new Date().toISOString()}){
 const normalized=cleanSubject(subject);
 if(!validDate(mergedAt))throw new TypeError("mergedAt must be a valid date string");
 validateLedger(imported,normalized,"Imported ledger");
 if(current)validateLedger(current,normalized,"Current ledger");
 const result=current?clone(current):clone(imported);
 const summary={addedEntries:0,addedAssessments:0,duplicateAssessments:0,conflicts:0};
 const conflicts=[];
 if(!current){
  summary.addedEntries=imported.entries.length;
  summary.addedAssessments=imported.entries.reduce((sum,entry)=>sum+entry.assessments.length,0);
  return {ledger:result,summary,conflicts};
 }
 const byId=new Map(result.entries.map(entry=>[entry.id,entry]));
 for(const incoming of imported.entries){
  const existing=byId.get(incoming.id);
  if(!existing){result.entries.push(clone(incoming));byId.set(incoming.id,result.entries.at(-1));summary.addedEntries++;summary.addedAssessments+=incoming.assessments.length;continue;}
  existing.supportingReferences=[...new Set([...(existing.supportingReferences||[]),...(incoming.supportingReferences||[])])];
  const known=new Map(existing.assessments.map(item=>[item.id,item]));
  for(const assessment of incoming.assessments){
   const duplicate=known.get(assessment.id);
   if(duplicate){
    if(sameAssessment(duplicate,assessment))summary.duplicateAssessments++;
    else{summary.conflicts++;conflicts.push({hypothesisId:incoming.id,assessmentId:assessment.id,reason:"same-assessment-id-different-content"});}
    continue;
   }
   if(assessment.revision!==existing.assessments.length+1){
    summary.conflicts++;conflicts.push({hypothesisId:incoming.id,assessmentId:assessment.id,reason:"competing-or-gapped-assessment-revision",expectedRevision:existing.assessments.length+1,receivedRevision:assessment.revision});
    continue;
   }
   existing.assessments.push(clone(assessment));known.set(assessment.id,assessment);
   existing.status=assessment.status;existing.latestAssessment=assessment.id;summary.addedAssessments++;
  }
 }
 const currentTime=Date.parse(result.updatedAt),importedTime=Date.parse(imported.updatedAt);
 result.updatedAt=new Date(Math.max(currentTime,importedTime,Date.parse(mergedAt))).toISOString();
 result.limitations=[...new Set([...(result.limitations||[]),...(imported.limitations||[]),
  "Imported analyst history is merged locally after SHA-256 and schema checks; evidence references are not fetched or authenticated."])];
 return {ledger:result,summary,conflicts};
}
