import {createInvestigationPlaybook,updateInvestigationTask,summarizeInvestigationPlaybook,investigationPlaybookStorageKey} from "./investigation-playbook.js";

function node(tag,className,text){
 const el=document.createElement(tag);if(className)el.className=className;if(text!==undefined)el.textContent=text;return el;
}
function readSaved(key){
 try{const raw=localStorage.getItem(key);if(!raw)return null;const parsed=JSON.parse(raw);return parsed?.schema==="sentinel.investigation-playbook.v1"?parsed:null;}catch{return null;}
}
function save(key,value){try{localStorage.setItem(key,JSON.stringify(value));return true;}catch{return false;}}
export function renderInvestigationPlaybook(container,analysis){
 container.replaceChildren();
 const heading=node("div","sentinel-rel-kicker","SENTINEL / INVESTIGATION WORKFLOW");
 container.appendChild(heading);
 container.appendChild(node("h4",null,"INVESTIGATION PLAYBOOK"));
 container.appendChild(node("p",null,"Turn each recommended check into a trackable analyst task. Progress is stored locally in this browser; no evidence is uploaded."));
 if(!analysis){container.appendChild(node("p","sentinel-rel-muted","Build an entity graph to generate an investigation playbook."));return null;}
 let key,playbook;
 try{
  key=investigationPlaybookStorageKey(analysis.subject);
  playbook=readSaved(key)||createInvestigationPlaybook(analysis);
 }catch(error){container.appendChild(node("p","sentinel-rel-muted",error.message));return null;}
 const persist=()=>{if(!save(key,playbook))status.textContent="Could not save locally. Export the playbook to keep a copy.";};
 const toolbar=node("div","sentinel-playbook-toolbar");
 const metrics=node("div","sentinel-rel-compare-result");
 const status=node("p","sentinel-rel-muted","Saved in this browser only.");
 const list=node("div","sentinel-playbook-list");
 const refresh=()=>{
  metrics.replaceChildren();const summary=summarizeInvestigationPlaybook(playbook);
  for(const [label,value] of [["TOTAL TASKS",summary.total],["IN PROGRESS",summary.inProgress],["VERIFIED BY ANALYST",summary.verified],["COMPLETION",summary.completionPercent+"%"]]){
   const card=node("div","sentinel-rel-compare-metric");card.append(node("b",null,value),node("span",null,label));metrics.appendChild(card);
  }
  list.replaceChildren();
  for(const task of playbook.tasks){
   const card=node("article","sentinel-playbook-task");
   const top=node("div","sentinel-playbook-task-top");top.append(node("strong",null,task.order+". "+task.title),node("span","sentinel-gap-priority",task.priority.toUpperCase()+" PRIORITY"));
   card.append(top,node("p",null,task.why));
   const check=node("div","sentinel-gap-check");check.append(node("b",null,"RECOMMENDED CHECK"),node("p",null,task.check));card.appendChild(check);
   if(task.evidence.length){const refs=node("small","sentinel-playbook-source","Source references: "+task.evidence.join(" · "));card.appendChild(refs);}
   const controls=node("div","sentinel-playbook-controls");
   const select=node("select");select.setAttribute("aria-label","Task status for "+task.title);
   for(const [value,label] of [["pending","Pending"],["in-progress","In progress"],["verified","Verified by analyst"],["not-applicable","Not applicable"]]){const option=node("option",null,label);option.value=value;select.appendChild(option);}
   select.value=task.status;
   const reference=node("input");reference.type="text";reference.maxLength=1000;reference.placeholder="Evidence reference (URL, tx hash, case ID…)";reference.value=task.evidenceReference;reference.setAttribute("aria-label","Evidence reference for "+task.title);
   const note=node("textarea");note.rows=2;note.maxLength=4000;note.placeholder="Analyst notes / what was checked…";note.value=task.analystNote;note.setAttribute("aria-label","Analyst notes for "+task.title);
   const saveButton=node("button",null,"SAVE TASK");
   const warning=node("small","sentinel-playbook-warning","Verified means an analyst attached a reference; SENTINEL does not validate it automatically.");
   saveButton.addEventListener("click",()=>{
    try{
     playbook=updateInvestigationTask(playbook,task.id,{status:select.value,evidenceReference:reference.value,analystNote:note.value});
     persist();status.textContent="Task saved locally · "+new Date().toLocaleString();refresh();
    }catch(error){warning.textContent=error.message;warning.dataset.error="true";}
   });
   controls.append(select,reference,note,saveButton);card.append(controls,warning);
   if(task.history.length>1){const details=node("details");const summaryNode=node("summary",null,"VIEW TASK HISTORY ("+task.history.length+")");const history=node("ol","sentinel-playbook-history");for(const entry of task.history){const line=node("li",null,new Date(entry.at).toLocaleString()+" · "+entry.status.toUpperCase()+" · "+entry.note+(entry.evidenceReference?" · "+entry.evidenceReference:""));history.appendChild(line);}details.append(summaryNode,history);card.appendChild(details);}
   list.appendChild(card);
  }
 };
 const exportButton=node("button",null,"EXPORT INVESTIGATION PLAYBOOK ↓");exportButton.addEventListener("click",()=>{const blob=new Blob([JSON.stringify({...playbook,exportedAt:new Date().toISOString()},null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const link=node("a");link.href=url;link.download="sentinel-investigation-playbook-"+playbook.subject.chainId+"-"+playbook.subject.address+".json";document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);});
 const resetButton=node("button",null,"REBUILD FROM CURRENT ANALYSIS");resetButton.addEventListener("click",()=>{if(!confirm("Rebuild this playbook from the current analysis? Existing local task progress will be replaced."))return;playbook=createInvestigationPlaybook(analysis);persist();status.textContent="Playbook rebuilt from current analysis.";refresh();});
 toolbar.append(exportButton,resetButton);container.append(toolbar,metrics,status,list);
 const caveat=node("p","sentinel-rel-muted",playbook.limitations.join(" "));container.appendChild(caveat);
 refresh();return playbook;
}
