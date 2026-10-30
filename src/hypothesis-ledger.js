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
