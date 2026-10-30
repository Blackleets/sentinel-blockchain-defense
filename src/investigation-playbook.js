const STATUSES=new Set(["pending","in-progress","verified","not-applicable"]);
const cleanText=(value,max=4000)=>typeof value==="string"?value.trim().slice(0,max):"";
const isoNow=()=>new Date().toISOString();
const safeId=value=>typeof value==="string"&&/^[a-z0-9][a-z0-9-]{0,119}$/i.test(value);

function clone(value){return JSON.parse(JSON.stringify(value));}

/** Create a reproducible analyst playbook from one gap-analysis snapshot. */
export function createInvestigationPlaybook(analysis,{createdAt=isoNow(),id}={}){
 if(!analysis||analysis.schema!=="sentinel.evidence-gap-analysis.v1")throw new TypeError("A SENTINEL evidence gap analysis is required");
 if(!analysis.subject?.chainId||!/^0x[0-9a-f]{40}$/i.test(analysis.subject?.address||""))throw new TypeError("A valid playbook subject is required");
 if(!Array.isArray(analysis.recommendations))throw new TypeError("Analysis recommendations are required");
 const playbookId=id||"playbook-"+analysis.subject.chainId+"-"+analysis.subject.address.toLowerCase();
 if(!safeId(playbookId))throw new TypeError("Invalid playbook id");
 const tasks=analysis.recommendations.map((item,index)=>{
  if(!safeId(item.id))throw new TypeError("Recommendation id is invalid");
  return {id:item.id,order:index+1,title:cleanText(item.title,240),priority:item.priority==="high"?"high":"normal",
   why:cleanText(item.why),check:cleanText(item.check),gap:cleanText(item.gap),evidence:Array.isArray(item.evidence)?item.evidence.filter(value=>typeof value==="string").slice(0,50):[],
   status:"pending",analystNote:"",evidenceReference:"",updatedAt:createdAt,history:[{status:"pending",at:createdAt,note:"Task created from evidence gap analysis."}]};
 });
 return {schema:"sentinel.investigation-playbook.v1",id:playbookId,createdAt,updatedAt:createdAt,
  subject:{chainId:String(analysis.subject.chainId),address:analysis.subject.address.toLowerCase()},
  sourceAnalysis:{schema:analysis.schema,generatedAt:analysis.generatedAt||null,coverage:analysis.coverage||"unknown"},
  tasks,limitations:["Task status is an analyst-entered workflow state, not an automatic verification result.","A VERIFIED status records the analyst's assertion and attached reference; SENTINEL does not independently validate the reference.","A playbook is a working record and does not establish attribution, malicious intent or the truth of imported evidence."]};
}

/** Apply one explicit analyst update; VERIFIED requires a traceable reference string. */
export function updateInvestigationTask(playbook,taskId,update,{updatedAt=isoNow()}={}){
 if(!playbook||playbook.schema!=="sentinel.investigation-playbook.v1"||!Array.isArray(playbook.tasks))throw new TypeError("A SENTINEL investigation playbook is required");
 const task=playbook.tasks.find(item=>item.id===taskId);
 if(!task)throw new RangeError("Investigation task not found");
 if(!update||!STATUSES.has(update.status))throw new TypeError("A supported task status is required");
 const evidenceReference=cleanText(update.evidenceReference,1000);
 const analystNote=cleanText(update.analystNote,4000);
 if(update.status==="verified"&&!evidenceReference)throw new TypeError("Attach an evidence reference before marking a task verified");
 const next=clone(playbook),target=next.tasks.find(item=>item.id===taskId);
 target.status=update.status;target.evidenceReference=evidenceReference;target.analystNote=analystNote;target.updatedAt=updatedAt;
 target.history.push({status:update.status,at:updatedAt,note:analystNote||"Status updated.",evidenceReference:evidenceReference||null});
 next.updatedAt=updatedAt;
 return next;
}

export function summarizeInvestigationPlaybook(playbook){
 if(!playbook||playbook.schema!=="sentinel.investigation-playbook.v1"||!Array.isArray(playbook.tasks))throw new TypeError("A SENTINEL investigation playbook is required");
 const counts={total:playbook.tasks.length,pending:0,inProgress:0,verified:0,notApplicable:0,highPriorityOpen:0};
 for(const task of playbook.tasks){
  if(task.status==="pending")counts.pending++;
  else if(task.status==="in-progress")counts.inProgress++;
  else if(task.status==="verified")counts.verified++;
  else if(task.status==="not-applicable")counts.notApplicable++;
  if(task.priority==="high"&&task.status==="pending")counts.highPriorityOpen++;
 }
 counts.completed=counts.verified+counts.notApplicable;
 counts.completionPercent=counts.total?Math.round(counts.completed/counts.total*100):100;
 return counts;
}

export function investigationPlaybookStorageKey(subject){
 if(!subject?.chainId||!/^0x[0-9a-f]{40}$/i.test(subject.address||""))throw new TypeError("A valid playbook subject is required");
 return "sentinel:investigation-playbook:v1:"+String(subject.chainId).toLowerCase()+":"+subject.address.toLowerCase();
}
