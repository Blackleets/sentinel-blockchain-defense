const ADDRESS=/^0x[0-9a-f]{40}$/i;
const HASH=/^0x[0-9a-f]{64}$/i;
const validAddress=value=>typeof value==="string"&&ADDRESS.test(value);
const validHash=value=>typeof value==="string"&&HASH.test(value);
const unique=values=>[...new Set(values.filter(Boolean))].sort();

function recommendation({id,priority,title,why,check,evidence=[],gap}){
 return {id,priority,title,why,check,evidence,gap};
}

/**
 * Turn only explicit gaps and observed evidence shapes into reproducible next checks.
 * This is a review aid, not a risk score, attribution engine or verdict.
 */
export function analyzeEvidenceGaps({neighborhood,graph,threatIntelligence}){
 if(!neighborhood||neighborhood.schema!=="sentinel.entity-neighborhood.v1")throw new TypeError("A SENTINEL entity neighborhood is required");
 if(!graph||graph.schema!=="sentinel.correlation-graph.v1")throw new TypeError("A SENTINEL correlation graph is required");
 if(!threatIntelligence||threatIntelligence.schema!=="sentinel.threat-intelligence.v1")throw new TypeError("SENTINEL threat intelligence is required");
 const chainId=String(neighborhood.subject?.chainId||"unknown").toLowerCase();
 const subject=neighborhood.subject?.address;
 if(!validAddress(subject))throw new TypeError("A valid neighborhood subject address is required");
 const edges=(neighborhood.edges||[]).filter(edge=>String(edge.chainId).toLowerCase()===chainId);
 const signals=(threatIntelligence.signals||[]).filter(signal=>String(signal.chainId).toLowerCase()===chainId&&
  ((signal.entities||[]).some(value=>String(value).toLowerCase()===subject.toLowerCase())||
   (signal.evidence||[]).some(item=>[item.address,item.from,item.to,item.implementation].some(value=>typeof value==="string"&&value.toLowerCase()===subject.toLowerCase()))));
 const transfers=(threatIntelligence.tokenTransfers||[]).filter(item=>String(item.chainId).toLowerCase()===chainId&&
  [item.from,item.to].some(value=>typeof value==="string"&&value.toLowerCase()===subject.toLowerCase()));
 const handoffs=(threatIntelligence.transactionLinks||[]).filter(item=>String(item.chainId).toLowerCase()===chainId&&
  [item.from,item.via,item.to].some(value=>typeof value==="string"&&value.toLowerCase()===subject.toLowerCase()));
 const recommendations=[];
 const add=item=>recommendations.push(recommendation(item));
 if(neighborhood.summary?.truncated){
  const reasons=[];
  if(neighborhood.summary.truncatedNodes)reasons.push("node cap reached");
  if(neighborhood.summary.truncatedEdges)reasons.push("edge cap reached");
  add({id:"expand-truncated-neighborhood",priority:"high",title:"Resolve neighborhood truncation",
   why:"The current graph is incomplete ("+(reasons.join(" and ")||"a configured output cap was reached") + "). Omitted observations cannot be treated as absent.",
   check:"Repeat the exploration with a higher node/edge budget where supported, or pivot from each boundary node and inspect smaller neighborhoods.",
   evidence:[],gap:"Unexpanded neighborhood coverage"});
 }
 const infrastructure=edges.filter(edge=>/shared-erc1967|shared-eip7702/.test(edge.type||""));
 for(const edge of infrastructure){
  const refs=unique((edge.evidence||[]).flatMap(item=>[item.sharedAddress,item.implementation,item.admin,item.beacon]).filter(validAddress));
  add({id:"verify-infrastructure-"+(edge.id||edge.type).slice(0,90),priority:"high",
   title:"Independently verify shared infrastructure metadata",
   why:"A shared proxy/delegation reference is present in imported correlation evidence. The reference alone does not establish current code, control or an upgrade path.",
   check:"Inspect the referenced address on the same chain, verify its current bytecode and relevant ERC-1967 slots, then compare bounded upgrade/delegation history using an independent RPC or explorer.",
   evidence:[edge.id,...refs].filter(Boolean),gap:"Independent code, slot and history verification"});
 }
 if(transfers.length){
  const incomplete=transfers.filter(item=>!validHash(item.transactionHash||item.txHash)||item.blockNumber==null||item.logIndex==null);
  add({id:"validate-transfer-receipts",priority:"high",title:"Validate token-transfer receipt provenance",
   why:transfers.length+" Transfer-shaped log observation(s) involve the subject. Event shape is not proof that the emitting contract is a legitimate token.",
   check:"Open each source transaction receipt; match transaction hash, block number, log index, emitting contract and indexed from/to topics. Verify token contract identity and decimals separately before interpreting amounts.",
   evidence:transfers.slice(0,25).map(item=>item.transactionHash||item.txHash||item.caseSubject).filter(Boolean),
   gap:incomplete.length?"Receipt identity fields are missing for "+incomplete.length+" imported log(s); exact receipt matching is incomplete.":"Independent receipt and token-contract verification"});
 }
 if(handoffs.length){
  const hashes=unique(handoffs.flatMap(item=>item.transactionHashes||item.hashes||[]).filter(validHash));
  add({id:"verify-handoff-receipts",priority:"high",title:"Verify each transaction in the handoff trail",
   why:"A handoff is a relationship assembled from imported transaction observations; it is not proof that the same funds or assets moved through the sequence.",
   check:"Retrieve every referenced transaction and receipt, verify chain, block ordering, sender/recipient and relevant asset-specific logs. Treat each leg independently.",
   evidence:hashes.slice(0,25),gap:hashes.length?"Receipt-level confirmation of every handoff leg":"Underlying transaction hashes are not available in the imported handoff record"});
 }
 if(signals.length){
  const refs=unique(signals.flatMap(signal=>(signal.evidence||[]).map(item=>item.transactionHash||item.txHash||item.caseSubject)).filter(Boolean));
  add({id:"revalidate-review-signals",priority:"normal",title:"Revalidate the underlying observations behind review signals",
   why:signals.length+" rule-based review signal(s) match the selected entity. These are patterns in imported evidence, not maliciousness findings.",
   check:"Open each cited source case and raw transaction/event, confirm chain and block context, and cross-check critical observations with an independent provider before drawing conclusions.",
   evidence:refs.slice(0,25),gap:"Source-case and independent-provider confirmation"});
 }
 const subjectEdges=edges.filter(edge=>edge.from?.toLowerCase()===subject.toLowerCase()||edge.to?.toLowerCase()===subject.toLowerCase());
 const missingTxRefs=subjectEdges.filter(edge=>(edge.type==="observed-transaction-flow"||edge.type==="observed-token-transfer-log")&&
  !(edge.evidence||[]).some(item=>validHash(item.transactionHash||item.txHash)));
 if(missingTxRefs.length){
  add({id:"recover-transaction-identifiers",priority:"normal",title:"Recover transaction identifiers for observed links",
   why:missingTxRefs.length+" direct relationship edge(s) lack a valid transaction hash in their attached provenance.",
   check:"Return to the source case report or receipt and recover the exact transaction hash, chain ID, block number and log index where applicable. Do not infer missing identifiers from neighboring records.",
   evidence:missingTxRefs.map(edge=>edge.id).filter(Boolean),gap:"Traceable transaction-level provenance"});
 }
 if(!recommendations.length){
  add({id:"broaden-source-coverage",priority:"normal",title:"Broaden source coverage before making a conclusion",
   why:"No specific evidence gap rule fired for this bounded neighborhood. That is not evidence that the entity has no risk or no relationships.",
   check:"Import additional independently sourced case reports and transaction receipts for this chain, then rebuild the neighborhood and compare the new coverage.",
   evidence:[],gap:"Independent and broader evidence coverage"});
 }
 const counts={recommendationCount:recommendations.length,highPriorityCount:recommendations.filter(item=>item.priority==="high").length,matchedSignalCount:signals.length,subjectTransferCount:transfers.length,subjectHandoffCount:handoffs.length,truncated:Boolean(neighborhood.summary?.truncated)};
 return {schema:"sentinel.evidence-gap-analysis.v1",generatedAt:new Date().toISOString(),subject:{chainId,address:subject.toLowerCase()},coverage:"bounded-neighborhood-and-imported-evidence-only",summary:counts,recommendations,limitations:[
  "Recommendations are deterministic review prompts triggered by supplied evidence and explicit coverage gaps; they are not a risk score or verdict.",
  "SENTINEL does not fetch the recommended external evidence automatically. Analysts must verify each source independently.",
  "Missing identifiers, records or graph edges may reflect import or coverage limits, not absence of on-chain activity.",
  "Shared infrastructure, Transfer-shaped logs, handoff trails and rule-based signals do not prove ownership, coordination, malicious intent or movement of the same assets."
 ],assessment:{verdict:"not-assessed",riskScore:null}};
}
