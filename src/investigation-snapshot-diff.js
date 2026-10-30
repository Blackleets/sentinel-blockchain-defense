const clone=value=>JSON.parse(JSON.stringify(value));
const stable=value=>{
 if(Array.isArray(value))return "["+value.map(stable).join(",")+"]";
 if(value&&typeof value==="object")return "{"+Object.keys(value).sort().map(key=>JSON.stringify(key)+":"+stable(value[key])).join(",")+"}";
 return JSON.stringify(value);
};
const addressPattern=/^0x[0-9a-f]{40}$/i;
const eventKey=item=>{
 const tx=typeof item.transactionHash==="string"?item.transactionHash.toLowerCase():"";
 if(tx)return [String(item.chainId||"").toLowerCase(),item.kind||"unknown",tx,item.logIndex??"",item.source??""].join("|");
 const record=item.record||{};
 return [String(item.chainId||"").toLowerCase(),item.kind||"unknown",item.blockNumber??"",record.edgeId??"",item.source??"",stable(record)].join("|");
};
const groupBy=(items,keyFn)=>{
 const groups=new Map();
 for(const item of items){const key=keyFn(item);if(!groups.has(key))groups.set(key,[]);groups.get(key).push(item);}
 return groups;
};
function validate(snapshot,label){
 if(!snapshot||snapshot.schema!=="sentinel.investigation-intelligence.v1")throw new TypeError(label+" must be a SENTINEL investigation intelligence dossier");
 if(!snapshot.subject||typeof snapshot.subject.chainId!=="string"||!addressPattern.test(snapshot.subject.address||""))throw new TypeError(label+" is missing a valid chain/address subject");
 if(!Array.isArray(snapshot.timeline)||!Array.isArray(snapshot.hypotheses)||!Array.isArray(snapshot.sourceReferences))throw new TypeError(label+" is missing timeline, hypotheses or source references");
 if(typeof snapshot.generatedAt!=="string"||Number.isNaN(Date.parse(snapshot.generatedAt)))throw new TypeError(label+" has an invalid generation timestamp");
 if(!snapshot.caseId||typeof snapshot.caseId!=="string")throw new TypeError(label+" is missing its case ID");
 for(const item of snapshot.timeline)if(!item||typeof item.kind!=="string"||typeof item.chainId!=="string")throw new TypeError(label+" contains an invalid timeline entry");
 for(const item of snapshot.hypotheses)if(!item||typeof item.id!=="string")throw new TypeError(label+" contains an invalid hypothesis");
}
function compareGroupedEvidence(previous,current){
 const before=groupBy(previous.timeline,eventKey),after=groupBy(current.timeline,eventKey);
 const added=[],retained=[],notInCurrentSnapshot=[],matchedCounts=new Map();
 for(const [key,currentItems] of after){
  const previousItems=[...(before.get(key)||[])];
  for(const item of currentItems){
   if(previousItems.length){const old=previousItems.shift();matchedCounts.set(key,(matchedCounts.get(key)||0)+1);retained.push({key,previous:clone(old),current:clone(item),recordChanged:stable(old.record)!==stable(item.record)});}
   else added.push(clone(item));
  }
 }
 for(const [key,items] of before)for(const item of items.slice(matchedCounts.get(key)||0))notInCurrentSnapshot.push(clone(item));
 return {added,retained,notInCurrentSnapshot};
}
function compareWorkflow(previous,current){
 const changes=[];
 const before=new Map((previous.analystWorkflow?.tasks||[]).map(item=>[item.id,item]));
 const after=new Map((current.analystWorkflow?.tasks||[]).map(item=>[item.id,item]));
 for(const [id,item] of after){
  const old=before.get(id);
  if(!old)changes.push({id,change:"introduced",previous:null,current:item.status});
  else if(old.status!==item.status)changes.push({id,change:"status-changed",previous:old.status,current:item.status});
 }
 for(const [id,item] of before)if(!after.has(id))changes.push({id,change:"not-in-current-playbook",previous:item.status,current:null});
 return changes;
}
function compareHypotheses(previous,current){
 const changes=[];
 const before=new Map(previous.hypotheses.map(item=>[item.id,item]));
 const after=new Map(current.hypotheses.map(item=>[item.id,item]));
 for(const [id,item] of after){
  const old=before.get(id);
  if(!old)changes.push({id,change:"introduced",current:clone(item)});
  else if(stable(old)!==stable(item))changes.push({id,change:"updated",previous:clone(old),current:clone(item)});
 }
 for(const [id,item] of before)if(!after.has(id))changes.push({id,change:"not-generated-in-current-snapshot",previous:clone(item)});
 return changes;
}
function compareReviews(previous,current){
 const changes=[];
 const before=new Map((previous.hypothesisReview?.entries||[]).map(item=>[item.id,item]));
 const after=new Map((current.hypothesisReview?.entries||[]).map(item=>[item.id,item]));
 for(const [id,item] of after){
  const old=before.get(id),oldAssessments=old?.assessments||[],newAssessments=item.assessments||[];
  const oldIds=new Set(oldAssessments.map(assessment=>assessment.id));
  const appended=newAssessments.filter(assessment=>!oldIds.has(assessment.id));
  if(!old||old.status!==item.status||appended.length)changes.push({id,previousStatus:old?.status??null,currentStatus:item.status,
   appendedAssessments:clone(appended),previousAssessmentCount:oldAssessments.length,currentAssessmentCount:newAssessments.length});
 }
 for(const [id,item] of before)if(!after.has(id))changes.push({id,previousStatus:item.status,currentStatus:null,appendedAssessments:[],change:"not-in-current-ledger"});
 return changes;
}
/** Compare two point-in-time dossiers without treating missing rows as chain-level absence. */
export function compareInvestigationSnapshots(previous,current){
 validate(previous,"Previous snapshot");validate(current,"Current snapshot");
 if(previous.subject.chainId.toLowerCase()!==current.subject.chainId.toLowerCase()||previous.subject.address.toLowerCase()!==current.subject.address.toLowerCase())throw new TypeError("Snapshots must refer to the same chain and subject address");
 if(previous.caseId!==current.caseId)throw new TypeError("Snapshots must refer to the same case ID");
 const evidence=compareGroupedEvidence(previous,current);
 const beforeRefs=new Set(previous.sourceReferences),afterRefs=new Set(current.sourceReferences);
 const sourceReferences={added:[...afterRefs].filter(item=>!beforeRefs.has(item)).sort(),notInCurrentSnapshot:[...beforeRefs].filter(item=>!afterRefs.has(item)).sort()};
 const hypothesisChanges=compareHypotheses(previous,current);
 const reviewChanges=compareReviews(previous,current);
 const taskChanges=compareWorkflow(previous,current);
 const beforeCoverage=previous.evidenceCoverage||{},afterCoverage=current.evidenceCoverage||{};
 const coverageChanged=stable(beforeCoverage)!==stable(afterCoverage);
 const beforeAssessmentCount=previous.summary?.hypothesisReview?.assessmentCount??0;
 const afterAssessmentCount=current.summary?.hypothesisReview?.assessmentCount??0;
 return {schema:"sentinel.investigation-snapshot-diff.v1",caseId:current.caseId,subject:clone(current.subject),
  comparedAt:new Date().toISOString(),previousGeneratedAt:previous.generatedAt,currentGeneratedAt:current.generatedAt,
  evidence:{...evidence,summary:{added:evidence.added.length,retained:evidence.retained.length,
   notInCurrentSnapshot:evidence.notInCurrentSnapshot.length,retainedWithChangedRecord:evidence.retained.filter(item=>item.recordChanged).length}},
  sourceReferences,hypothesisChanges,reviewChanges,taskChanges,
  coverage:{previous:clone(beforeCoverage),current:clone(afterCoverage),changed:coverageChanged},
  summary:{addedEvidence:evidence.added.length,retainedEvidence:evidence.retained.length,
   notInCurrentSnapshot:evidence.notInCurrentSnapshot.length,addedSourceReferences:sourceReferences.added.length,
   notInCurrentSourceReferences:sourceReferences.notInCurrentSnapshot.length,hypothesisChanges:hypothesisChanges.length,
   analystReviewChanges:reviewChanges.length,taskChanges:taskChanges.length,
   appendedAnalystAssessments:Math.max(0,afterAssessmentCount-beforeAssessmentCount),coverageChanged},
  limitations:[
   "This is a comparison of two supplied dossier snapshots, not a live chain diff.",
   "An item not present in the current snapshot may be outside its traversal bounds or imported source set; it is not evidence that an on-chain event disappeared.",
   "Evidence identity is matched using chain, event kind, transaction hash, log index and source. Records without transaction hashes use a conservative record-derived key; duplicate observations are compared as a multiset.",
   "Hypothesis, review and task changes describe dossier metadata and analyst-entered workflow state, not independently verified conclusions.",
   "Both dossier seals should be independently verified before relying on the comparison. SHA-256 consistency does not authenticate authorship or prove evidence truth."
  ]};
}
