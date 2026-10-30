import {analyzeEvidenceGaps} from "./evidence-gap-analysis.js";
export function renderEvidenceGapAnalysis(container,{neighborhood,graph,threatIntelligence}){
 container.replaceChildren();
 try{
  const result=analyzeEvidenceGaps({neighborhood,graph,threatIntelligence});
  const heading=document.createElement("div");heading.className="sentinel-rel-kicker";heading.textContent="SENTINEL / NEXT BEST CHECK";
  const title=document.createElement("h4");title.textContent="EVIDENCE GAP ANALYSIS";
  const intro=document.createElement("p");intro.textContent="What is missing, why it matters, and the next verification step. Suggestions are evidence-led, not verdicts.";
  const metrics=document.createElement("div");metrics.className="sentinel-rel-compare-result";
  for(const [label,value] of [["NEXT CHECKS",result.summary.recommendationCount],["PRIORITY REVIEW",result.summary.highPriorityCount],["MATCHED SIGNALS",result.summary.matchedSignalCount],["TRUNCATED",result.summary.truncated?"YES":"NO"]]){
   const card=document.createElement("div");card.className="sentinel-rel-compare-metric";const number=document.createElement("b");number.textContent=value;const caption=document.createElement("span");caption.textContent=label;card.append(number,caption);metrics.appendChild(card);
  }
  const list=document.createElement("div");list.className="sentinel-gap-list";
  for(const item of result.recommendations){
   const card=document.createElement("article");card.className="sentinel-gap-card";
   const top=document.createElement("div");top.className="sentinel-gap-top";
   const name=document.createElement("strong");name.textContent=item.title;
   const priority=document.createElement("span");priority.className="sentinel-gap-priority";priority.textContent=item.priority.toUpperCase()+" PRIORITY";
   top.append(name,priority);
   const why=document.createElement("p");why.textContent=item.why;
   const check=document.createElement("div");check.className="sentinel-gap-check";const label=document.createElement("b");label.textContent="NEXT VERIFICATION";const body=document.createElement("p");body.textContent=item.check;check.append(label,body);
   const gap=document.createElement("small");gap.textContent="Evidence gap: "+item.gap;
   const refs=document.createElement("small");refs.textContent=item.evidence.length?"Evidence references: "+item.evidence.join(" · "):"No direct evidence reference attached; this is a coverage recommendation.";
   card.append(top,why,check,gap,refs);list.appendChild(card);
  }
  const caveat=document.createElement("p");caveat.className="sentinel-rel-muted";caveat.textContent=result.limitations.join(" ");
  const exportButton=document.createElement("button");exportButton.type="button";exportButton.textContent="EXPORT GAP ANALYSIS ↓";exportButton.addEventListener("click",()=>{const blob=new Blob([JSON.stringify(result,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download="sentinel-evidence-gap-analysis-"+result.subject.chainId+"-"+result.subject.address+".json";document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  container.append(heading,title,intro,metrics,list,caveat,exportButton);
  return result;
 }catch(error){const message=document.createElement("p");message.textContent="Evidence gap analysis unavailable: "+error.message;container.appendChild(message);return null;}
}
