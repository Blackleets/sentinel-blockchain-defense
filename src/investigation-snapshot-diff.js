const clone=value=>JSON.parse(JSON.stringify(value));
const stable=value=>{
 if(Array.isArray(value))return "["+value.map(stable).join(",")+"]";
 if(value&&typeof value==="object")return "{"+Object.keys(value).sort().map(key=>JSON.stringify(key)+":"+stable(value[key])).join(",")+"}";
 return JSON.stringify(value);
};
const eventKey=item=>{
 const tx=typeof item.transactionHash==="string"?item.transactionHash.toLowerCase():"";
 if(tx)return [item.chainId,item.kind,tx,item.logIndex??"",item.source??""].join("|");
 const record=item.record||{};
 return [item.chainId,item.kind,item.blockNumber??"",record.edgeId??"",item.source??"",stable(record)].join("|");
};
const indexBy=(items,keyFn)=>new Map(items.map(item=>[keyFn(item),item]));
function validate(snapshot,label){
 if(!snapshot||snapshot.schema!=="sentinel.investigation-intelligence.v1")throw new TypeError(label+" must be a SENTINEL investigation intelligence dossier");
 if(!snapshot.subject||typeof snapshot.subject.chainId!=="string"||typeof snapshot.subject.address!=="string")throw new TypeError(label+" is missing its investigation subject");
 if(!Array.isArray(snapshot.timeline)||!Array.isArray(snapshot.hypotheses))throw new TypeError(label+" is missing timeline or hypotheses");
}
/** Compare two point-in-time dossiers without treating missing rows as chain-level absence. */
export function compareInvestigationSnapshots(previous,current){
 validate(previous,"Previous snapshot");validate(current,"Current snapshot");
 if(previous.subject.chainId.toLowerCase()!==current.subject.chainId.toLowerCase()||previous.subject.address.toLowerCase()!==current.subject.address.toLowerCase())throw new TypeError("Snapshots must refer to the same chain and subject address");
 const before=indexBy(previous.timeline,eventKey),after=indexBy(current.timeline,eventKey);
 const added=[],retained=[],notInCurrentSnapshot=[];
 for(const [key,item] of after){if(before.has(key)){const old=before.get(key);retained.push({key,previous:clone(old),current:clone(item),recordChanged:stable(old.record)!==stable(item.record)});}else added.push(clone(item));}
 for(const [key,item] of before)if(!after.has(key))notInCurrentSnapshot.push(clone(item));
 const oldHypotheses=indexBy(previous.hypotheses,item=>item.id),newHypotheses=indexBy(current.hypotheses,item=>item.id);
 const hypothesisChanges=[];
 for(const [id,item] of newHypotheses){const old=oldHypotheses.get(id);if(!old)hypothesisChanges.push({id,change:"introduced",current:clone(item)});else if(old.status!==item.status||stable(old)!==stable(item))hypothesisChanges.push({id,change:"updated",previous:clone(old),current:clone(item)});}
 for(const [id,item] of oldHypotheses)if(!newHypotheses.has(id))hypothesisChanges.push({id,change:"not-generated-in-current-snapshot",previous:clone(item)});
 const reviews=ledger=>new Map((ledger?.entries||[]).map(item=>[item.id,{status:item.status,assessmentCount:(item.assessments||[]).length,latest:item.assessments?.at(-1)||null}]));
 const oldReviews=reviews(previous.hypothesisReview),newReviews=reviews(current.hypothesisReview),reviewChanges=[];
 for(const [id,item] of newReviews){const old=oldReviews.get(id);if(!old||stable(old)!==stable(item))reviewChanges.push({id,previous:old||null,current:item});}
 const oldTasks=new Map((previous.analystWorkflow?.tasks||[]).map(item=>[item.id,item.status]));
 const taskChanges=(current.analystWorkflow?.tasks||[]).filter(item=>oldTasks.has(item.id)&&oldTasks.get(item.id)!==item.status).map(item=>({id:item.id,previous:oldTasks.get(item.id),current:item.status}));
 return {schema:"sentinel.investigation-snapshot-diff.v1",subject:clone(current.subject),
  comparedAt:new Date().toISOString(),previousGeneratedAt:previous.generatedAt||null,currentGeneratedAt:current.generatedAt||null,
  evidence:{added,retained,notInCurrentSnapshot,summary:{added:added.length,retained:retained.length,notInCurrentSnapshot:notInCurrentSnapshot.length,retainedWithChangedRecord:retained.filter(item=>item.recordChanged).length}},
  hypothesisChanges,reviewChanges,taskChanges,
  coverage:{previous:clone(previous.evidenceCoverage||{}),current:clone(current.evidenceCoverage||{})},
  limitations:[
   "This is a comparison of two supplied dossier snapshots, not a live chain diff.",
   "An item not present in the current snapshot may be outside its traversal bounds or imported source set; it is not evidence that an on-chain event disappeared.",
   "Evidence identity is matched using the available chain, event kind, transaction hash, log index and source. Records without transaction hashes use a conservative record-derived key and may not match across differently shaped imports.",
   "Hypothesis and task changes describe dossier metadata and analyst-entered workflow state, not independently verified conclusions."
  ]};
}
