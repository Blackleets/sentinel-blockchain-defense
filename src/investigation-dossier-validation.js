const ADDRESS=/^0x[0-9a-f]{40}$/i;
const HASH=/^0x[0-9a-f]{64}$/i;
const TASK_STATUSES=new Set(["pending","in-progress","verified","not-applicable"]);
const REVIEW_STATUSES=new Set(["open","supported","not-supported","inconclusive"]);
const validDate=value=>typeof value==="string"&&!Number.isNaN(Date.parse(value));
const validIndex=value=>value===null||value===undefined||(typeof value==="number"&&Number.isSafeInteger(value)&&value>=0)||(typeof value==="string"&&/^(0x[0-9a-f]+|[0-9]+)$/i.test(value));
const isObject=value=>value!==null&&typeof value==="object"&&!Array.isArray(value);
const unique=values=>new Set(values).size===values.length;

/**
 * Check dossier structure and internal consistency only.
 * This intentionally does not fetch RPC data or authenticate source references.
 */
export function validateInvestigationDossier(dossier){
 const errors=[],warnings=[];
 const error=message=>errors.push(message),warn=message=>warnings.push(message);
 if(!isObject(dossier))return {schema:"sentinel.investigation-dossier-validation.v1",valid:false,structuralStatus:"invalid",sourceVerification:"not-performed",errors:["Dossier must be a JSON object."],warnings:[],summary:null,limitations:["Structural validation does not authenticate sources or prove on-chain truth."]};
 if(dossier.schema!=="sentinel.investigation-intelligence.v1")error("Unsupported dossier schema.");
 if(!isObject(dossier.subject)||typeof dossier.subject.chainId!=="string"||!dossier.subject.chainId.trim()||!ADDRESS.test(dossier.subject.address||""))error("Dossier subject must contain a chain ID and valid EVM address.");
 const chainId=typeof dossier.subject?.chainId==="string"?dossier.subject.chainId.toLowerCase():null;
 if(typeof dossier.caseId!=="string"||!dossier.caseId.trim())error("Dossier caseId is missing.");
 if(!validDate(dossier.generatedAt))error("Dossier generatedAt is not a valid date string.");
 if(dossier.coverage!=="bounded-neighborhood-and-imported-evidence-only")warn("Dossier coverage label is missing or differs from the supported bounded-evidence mode.");
 if(!isObject(dossier.assessment)||dossier.assessment.verdict!=="not-assessed"||dossier.assessment.riskScore!==null)error("Dossier assessment must remain not-assessed with a null risk score.");
 if(!Array.isArray(dossier.timeline))error("Dossier timeline must be an array.");
 else{
  dossier.timeline.forEach((item,index)=>{
   const label="Timeline entry "+index;
   if(!isObject(item)){error(label+" must be an object.");return;}
   if(typeof item.kind!=="string"||!item.kind.trim())error(label+" is missing kind.");
   if(typeof item.source!=="string"||!item.source.trim())error(label+" is missing source provenance.");
   if(typeof item.chainId!=="string"||item.chainId.toLowerCase()!==chainId)error(label+" is outside the dossier subject chain.");
   if(item.transactionHash!==null&&item.transactionHash!==undefined&&!HASH.test(item.transactionHash))error(label+" has an invalid transaction hash.");
   if(!validIndex(item.blockNumber))error(label+" has an invalid block number.");
   if(!validIndex(item.logIndex)||!validIndex(item.transactionIndex))error(label+" has an invalid log or transaction index.");
   if(item.subject!==null&&item.subject!==undefined&&!ADDRESS.test(item.subject))error(label+" has an invalid subject address.");
   if(!isObject(item.record))error(label+" is missing its source record object.");
   if(!item.transactionHash&&item.blockNumber===null)warn(label+" has neither transaction hash nor block number; traceability is limited.");
  });
 }
 if(!Array.isArray(dossier.hypotheses))error("Dossier hypotheses must be an array.");
 else{
  const ids=new Set();
  dossier.hypotheses.forEach((item,index)=>{
   if(!isObject(item)){error("Hypothesis "+index+" must be an object.");return;}
   if(typeof item.id!=="string"||!item.id.trim())error("Hypothesis "+index+" is missing an ID.");
   else if(ids.has(item.id))error("Duplicate hypothesis ID: "+item.id);else ids.add(item.id);
   if(typeof item.question!=="string"||!item.question.trim())error("Hypothesis "+index+" is missing its verification question.");
   if(item.status!=="unverified")error("Generated hypothesis "+(item.id||index)+" must remain unverified; analyst assessments belong in the separate review ledger.");
   if(!Array.isArray(item.supportingReferences)||item.supportingReferences.some(value=>typeof value!=="string"||!value.trim()))error("Hypothesis "+(item.id||index)+" has malformed supporting references.");
  });
 }
 if(!Array.isArray(dossier.sourceReferences)||dossier.sourceReferences.some(value=>typeof value!=="string"||!value.trim()))error("Dossier sourceReferences must be an array of non-empty strings.");
 else if(!unique(dossier.sourceReferences))warn("Dossier sourceReferences contains duplicate entries.");
 if(!isObject(dossier.evidenceCoverage))error("Dossier evidenceCoverage is missing.");
 if(!isObject(dossier.analystWorkflow)||!Array.isArray(dossier.analystWorkflow.tasks))error("Dossier analystWorkflow tasks are missing.");
 else{
  const ids=new Set();
  dossier.analystWorkflow.tasks.forEach((task,index)=>{
   if(!isObject(task)){error("Playbook task "+index+" must be an object.");return;}
   if(typeof task.id!=="string"||!task.id.trim())error("Playbook task "+index+" is missing an ID.");
   else if(ids.has(task.id))error("Duplicate playbook task ID: "+task.id);else ids.add(task.id);
   if(!TASK_STATUSES.has(task.status))error("Playbook task "+(task.id||index)+" has an unsupported status.");
   if(task.status==="verified"&&(typeof task.evidenceReference!=="string"||!task.evidenceReference.trim()))error("Verified task "+(task.id||index)+" has no evidence reference.");
  });
 }
 const review=dossier.hypothesisReview;
 if(review!==null&&review!==undefined){
  if(!isObject(review)||review.schema!=="sentinel.hypothesis-ledger.v1"||!Array.isArray(review.entries))error("Hypothesis review ledger has an unsupported schema or entries.");
  else{
   if(review.subject?.chainId?.toLowerCase()!==chainId||review.subject?.address?.toLowerCase()!==dossier.subject?.address?.toLowerCase())error("Hypothesis review ledger subject does not match the dossier.");
   const seen=new Set();
   for(const entry of review.entries){
    if(!isObject(entry)||typeof entry.id!=="string"||!entry.id.trim()){error("Hypothesis review entry has no ID.");continue;}
    if(seen.has(entry.id))error("Duplicate hypothesis review entry: "+entry.id);seen.add(entry.id);
    if(!REVIEW_STATUSES.has(entry.status))error("Hypothesis review "+entry.id+" has an unsupported status.");
    if(!Array.isArray(entry.assessments)){error("Hypothesis review "+entry.id+" has no assessment history.");continue;}
    entry.assessments.forEach((assessment,index)=>{
     if(!isObject(assessment)||!REVIEW_STATUSES.has(assessment.status)||!validDate(assessment.updatedAt)||typeof assessment.note!=="string"||!assessment.note.trim())error("Hypothesis review "+entry.id+" has an invalid assessment at position "+index+".");
     if((assessment.status==="supported"||assessment.status==="not-supported")&&(typeof assessment.evidenceReference!=="string"||!assessment.evidenceReference.trim()))error("Conclusive assessment "+entry.id+" requires an evidence reference.");
     if(assessment.revision!==index+1)error("Hypothesis review "+entry.id+" has a non-sequential assessment revision.");
    });
    if(!dossier.hypotheses?.some(item=>item.id===entry.id))warn("Review ledger retains hypothesis "+entry.id+" that is not generated in this snapshot.");
   }
  }
 }
 if(isObject(dossier.summary)){
  if(Array.isArray(dossier.timeline)&&dossier.summary.timelineEntryCount!==dossier.timeline.length)error("Summary timelineEntryCount does not match the timeline.");
  if(Array.isArray(dossier.hypotheses)&&dossier.summary.hypothesisCount!==dossier.hypotheses.length)error("Summary hypothesisCount does not match generated hypotheses.");
  if(Array.isArray(dossier.sourceReferences)&&dossier.summary.sourceReferenceCount!==dossier.sourceReferences.length)error("Summary sourceReferenceCount does not match sourceReferences.");
  if(dossier.summary.hypothesisReview&&review?.entries){
   const counts={total:review.entries.length,open:review.entries.filter(item=>item.status==="open").length,supported:review.entries.filter(item=>item.status==="supported").length,notSupported:review.entries.filter(item=>item.status==="not-supported").length,inconclusive:review.entries.filter(item=>item.status==="inconclusive").length,assessmentCount:review.entries.reduce((sum,item)=>sum+(Array.isArray(item.assessments)?item.assessments.length:0),0)};
   for(const [key,value] of Object.entries(counts))if(dossier.summary.hypothesisReview[key]!==value)error("Summary hypothesisReview."+key+" does not match the review ledger.");
  }
 }else error("Dossier summary is missing.");
 if(dossier.evidenceCoverage?.neighborhood?.truncated||dossier.summary?.neighborhoodTruncated)warn("Neighborhood is truncated; this dossier represents bounded coverage only.");
 if(!dossier.timeline?.length)warn("Dossier contains no timeline entries.");
 if(!dossier.sourceReferences?.length)warn("Dossier contains no source references.");
 return {schema:"sentinel.investigation-dossier-validation.v1",valid:errors.length===0,structuralStatus:errors.length===0?"valid":"invalid",
  sourceVerification:"not-performed",errors,warnings,summary:{timelineEntries:dossier.timeline?.length??null,hypotheses:dossier.hypotheses?.length??null,
   sourceReferences:dossier.sourceReferences?.length??null,analystTasks:dossier.analystWorkflow?.tasks?.length??null,
   analystAssessments:dossier.hypothesisReview?.entries?.reduce((sum,item)=>sum+(item.assessments?.length||0),0)??0},
  limitations:["This validates dossier structure and internal consistency only; it does not verify transaction hashes, addresses, receipts, contract code, external URLs or cited case records.","A valid SHA-256 seal proves only that the sealed artifact matches its digest; it does not authenticate authorship or establish source truth.","Source verification requires independent retrieval and validation against the relevant chain or original source system."]};
}
