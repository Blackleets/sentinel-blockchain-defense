import { buildAddressInvestigation, listInvestigableAddresses } from "./address-investigation.js";

function safeText(value) {
  return String(value ?? "").replace(/[&<>"']/g, character => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  })[character]);
}
function saveJson(data, filename) {
  const blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"});
  const url=URL.createObjectURL(blob),link=document.createElement("a");
  link.href=url;link.download=filename;document.body.appendChild(link);link.click();link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
export function mountAddressInvestigation(container,reports,graph,threatIntelligence) {
  const entries=listInvestigableAddresses({graph,threatIntelligence});
  const panel=document.createElement("section");panel.className="notice";panel.style.marginTop="16px";
  panel.innerHTML=`
    <strong>ADDRESS INVESTIGATION · ENTITY WORKSPACE</strong>
    <p class="hint">Choose an address found in imported evidence or enter one manually. Results are isolated by chain and never imply wallet ownership or attribution.</p>
    <div class="graph-controls">
      <select data-filter="chain" aria-label="Address investigation chain"></select>
      <select data-filter="address" aria-label="Known observed address"><option value="">Select observed address…</option></select>
      <input data-filter="manual" placeholder="Or paste EVM address" aria-label="Manual EVM address">
      <button type="button" data-action="investigate">Investigate address</button>
    </div>
    <div data-role="result"><div class="empty">Select an observed address to assemble its evidence.</div></div>
  `;
  container.appendChild(panel);
  const chain=panel.querySelector('[data-filter="chain"]'),address=panel.querySelector('[data-filter="address"]');
  const manual=panel.querySelector('[data-filter="manual"]'),result=panel.querySelector('[data-role="result"]');
  const chains=[...new Set(entries.map(item=>item.chainId))].sort();
  for(const value of chains){const option=document.createElement("option");option.value=value;option.textContent=value;chain.appendChild(option);}
  const refreshAddresses=()=>{
    const selected=address.value;address.replaceChildren();
    const first=document.createElement("option");first.value="";first.textContent="Select observed address…";address.appendChild(first);
    for(const item of entries.filter(item=>item.chainId===chain.value)){
      const option=document.createElement("option");option.value=item.address;
      option.textContent=item.address.slice(0,10)+"…"+item.address.slice(-6)+" · "+(item.roles?.join(", ")||"observed address");
      address.appendChild(option);
    }
    if([...address.options].some(option=>option.value===selected))address.value=selected;
  };
  chain.addEventListener("change",refreshAddresses);refreshAddresses();
  let current=null;
  const render=()=>{
    try{
      const selected=manual.value.trim()||address.value;
      if(!selected)throw new Error("Choose an address or paste a valid EVM address.");
      current=buildAddressInvestigation({reports,graph,threatIntelligence,chainId:chain.value,address:selected,maxTransactions:100});
      const s=current.summary;
      const stats=[["Cases",s.relatedCaseCount],["Transactions",s.observedTransactionCount],["Token logs",s.tokenTransferCount],["Handoffs",s.transactionHandoffCount],["Graph links",s.correlationEdgeCount],["Signals",s.threatSignalCount]];
      const section=document.createElement("div");section.style.marginTop="14px";
      const headline=document.createElement("div");headline.className="graph-summary";
      for(const [label,value] of stats){const item=document.createElement("span");item.textContent=label+": "+value;headline.appendChild(item);}
      section.appendChild(headline);
      const identity=document.createElement("p");identity.innerHTML="<b>"+safeText(current.subject.address)+"</b> · chain "+safeText(current.subject.chainId)+" · verdict NOT ASSESSED";section.appendChild(identity);
      const metadata=document.createElement("p");metadata.className="hint";metadata.textContent="Observed roles: "+(current.roles.join(", ")||"none recorded")+" · block range: "+(s.firstSeenBlock||"unknown")+" → "+(s.lastSeenBlock||"unknown");section.appendChild(metadata);
      const addGroup=(title,items,format)=>{
        const heading=document.createElement("h4");heading.textContent=title+" ("+items.length+")";section.appendChild(heading);
        if(!items.length){const empty=document.createElement("p");empty.className="hint";empty.textContent="No matching evidence in the imported files.";section.appendChild(empty);return;}
        for(const item of items){const card=document.createElement("div");card.className="graph-edge";const pre=document.createElement("pre");pre.style.whiteSpace="pre-wrap";pre.style.overflowWrap="anywhere";pre.textContent=format(item);card.appendChild(pre);section.appendChild(card);}
      };
      addGroup("Observed transactions",current.transactions,item=>JSON.stringify(item,null,2));
      addGroup("Token transfer logs",current.tokenTransfers,item=>JSON.stringify(item,null,2));
      addGroup("Transaction handoff trails",current.transactionLinks,item=>JSON.stringify(item,null,2));
      addGroup("Correlation edges",current.correlationEdges,item=>JSON.stringify(item,null,2));
      addGroup("Threat review signals",current.threatSignals,item=>JSON.stringify(item,null,2));
      addGroup("Related addresses",current.relatedAddresses,item=>item);
      const limits=document.createElement("p");limits.className="hint";limits.textContent=current.limitations.join(" ");section.appendChild(limits);
      const exportButton=document.createElement("button");exportButton.type="button";exportButton.textContent="Export address investigation JSON ↓";
      exportButton.addEventListener("click",()=>saveJson({...current,exportedAt:new Date().toISOString()},"sentinel-address-investigation-"+current.subject.chainId+"-"+current.subject.address+".json"));
      section.appendChild(exportButton);result.replaceChildren(section);
    }catch(error){current=null;result.innerHTML='<div class="error">'+safeText(error.message)+'</div>';}
  };
  panel.querySelector('[data-action="investigate"]').addEventListener("click",render);
  return {panel,investigate:render,get result(){return current;}};
}
