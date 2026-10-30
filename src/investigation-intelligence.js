const ADDRESS=/^0x[0-9a-f]{40}$/i;
const HASH=/^0x[0-9a-f]{64}$/i;
const validAddress=value=>typeof value==="string"&&ADDRESS.test(value);
const validHash=value=>typeof value==="string"&&HASH.test(value);
const unique=values=>[...new Set(values.filter(value=>typeof value==="string"&&value.length))];
const asBigInt=value=>{
 if(typeof value==="number"&&Number.isSafeInteger(value)&&value>=0)return BigInt(value);
 if(typeof value==="string"&&/^(0x[0-9a-f]+|[0-9]+)$/i.test(value)){try{return BigInt(value);}catch{return null;}}
 return null;
};
const blockOf=item=>asBigInt(item?.blockNumber??item?.block??item?.provenance?.blockNumber);
const cleanAddress=value=>validAddress(value)?value.toLowerCase():null;
const clone=value=>JSON.parse(JSON.stringify(value));

function timelineEntry({kind,chainId,blockNumber,transactionHash,logIndex,transactionIndex,subject,source,record}){
 return {kind,chainId:String(chainId||"unknown").toLowerCase(),blockNumber:blockNumber??null,
  transactionHash:validHash(transactionHash)?transactionHash.toLowerCase():null,
  logIndex:logIndex??null,transactionIndex:transactionIndex??null,
  subject:cleanAddress(subject),source,record:clone(record)};
}
function sortTimeline(entries){
 return entries.sort((a,b)=>{
  const left=asBigInt(a.blockNumber),right=asBigInt(b.blockNumber);
  if(left!==null&&right!==null&&left!==right)return left<right?-1:1;
  if(left!==null&&right===null)return -1;if(left===null&&right!==null)return 1;
  const li=asBigInt(a.transactionIndex),ri=asBigInt(b.transactionIndex);
  if(li!==null&&ri!==null&&li!==ri)return li<ri?-1:1;
  const ll=asBigInt(a.logIndex),rl=asBigInt(b.logIndex);
  if(ll!==null&&rl!==null&&ll!==rl)return ll<rl?-1:1;
  return a.kind.localeCompare(b.kind)||String(a.transactionHash||"").localeCompare(String(b.transactionHash||""));
 });
}

/**
 * Assemble a reproducible analyst dossier from the exact bounded inputs already
 * displayed by the Entity Relationship Explorer. No network enrichment occurs.
 */
export function buildInvestigationIntelligence({neighborhood,graph,threatIntelligence,gapAnalysis,playbook,generatedAt=new Date().toISOString(),caseId}){
 if(!neighborhood||neighborhood.schema!=="sentinel.entity-neighborhood.v1")throw new TypeError("A SENTINEL entity neighborhood is required");
 if(!graph||graph.schema!=="sentinel.correlation-graph.v1")throw new TypeError("A SENTINEL correlation graph is required");
 if(!threatIntelligence||threatIntelligence.schema!=="sentinel.threat-intelligence.v1")throw new TypeError("SENTINEL threat intelligence is required");
 if(!gapAnalysis||gapAnalysis.schema!=="sentinel.evidence-gap-analysis.v1")throw new TypeError("A SENTINEL evidence gap analysis is required");
 if(!playbook||playbook.schema!=="sentinel.investigation-playbook.v1")throw new TypeError("A SENTINEL investigation playbook is required");
 if(playbook.subject?.chainId!==neighborhood.subject.chainId||playbook.subject?.address?.toLowerCase()!==neighborhood.subject.address.toLowerCase())throw new TypeError("Playbook subject does not match the investigation subject");
 if(gapAnalysis.subject?.chainId!==neighborhood.subject.chainId||gapAnalysis.subject?.address?.toLowerCase()!==neighborhood.subject.address.toLowerCase())throw new TypeError("Gap analysis subject does not match the investigation subject");
 if(typeof generatedAt!=="string"||Number.isNaN(Date.parse(generatedAt)))throw new TypeError("generatedAt must be a valid date string");
 const subject={chainId:String(neighborhood.subject.chainId).toLowerCase(),address:neighborhood.subject.address.toLowerCase()};
 const timeline=[];
 for(const edge of neighborhood.edges||[])for(const evidence of edge.evidence||[]){
  const record={edgeId:edge.id,edgeType:edge.type,from:edge.from,to:edge.to,evidence};
  timeline.push(timelineEntry({kind:edge.type,chainId:edge.chainId,blockNumber:evidence.blockNumber??evidence.provenance?.blockNumber,
   transactionHash:evidence.transactionHash||evidence.txHash,logIndex:evidence.logIndex,transactionIndex:evidence.transactionIndex,
   subject:subject.address,source:edge.source,record}));
 }
 for(const item of threatIntelligence.timelines||[]){
  if(String(item.chainId||"").toLowerCase()!==subject.chainId)continue;
  timeline.push(timelineEntry({kind:item.kind||"threat-intelligence-observation",chainId:item.chainId,blockNumber:item.blockNumber,
   transactionHash:item.transactionHash,transactionIndex:item.transactionIndex,subject:item.subject,source:"threat-intelligence-timeline",record:item}));
 }
 for(const item of threatIntelligence.tokenTransfers||[]){
  if(String(item.chainId||"").toLowerCase()!==subject.chainId)continue;
  if(![item.from,item.to].some(value=>cleanAddress(value)===subject.address))continue;
  timeline.push(timelineEntry({kind:"transfer-shaped-receipt-log",chainId:item.chainId,blockNumber:item.blockNumber,
   transactionHash:item.transactionHash,logIndex:item.logIndex,subject:subject.address,source:"imported-receipt-log",record:item}));
 }
 for(const item of threatIntelligence.transactionLinks||[]){
  if(String(item.chainId||"").toLowerCase()!==subject.chainId)continue;
  if(![item.from,item.via,item.to].some(value=>cleanAddress(value)===subject.address))continue;
  timeline.push(timelineEntry({kind:"transaction-handoff-observation",chainId:item.chainId,blockNumber:item.blockNumber,
   transactionHash:item.transactionHash||item.transactionHashes?.[0],subject:subject.address,source:"imported-transaction-observations",record:item}));
 }
 const orderedTimeline=sortTimeline(timeline);
 const hypotheses=[];
 const addHypothesis=item=>hypotheses.push({id:item.id,question:item.question,why:item.why,verification:item.verification,
  supportingReferences:unique(item.references||[]),status:"unverified"});
 const sharedInfrastructure=(neighborhood.edges||[]).filter(edge=>/shared-erc1967|shared-eip7702/.test(edge.type||""));
 if(sharedInfrastructure.length)addHypothesis({id:"shared-infrastructure-context",
  question:"Do the observed entities rely on the same currently deployed infrastructure, and what does that establish?",
  why:"Imported graph evidence contains "+sharedInfrastructure.length+" shared proxy/delegation infrastructure relationship(s).",
  verification:"Inspect each referenced address on the same chain, retrieve current bytecode and relevant slots, then independently verify historical events and ownership/authorization context. Do not infer common control from reuse alone.",
  references:sharedInfrastructure.map(edge=>edge.id)});
 const transfers=(threatIntelligence.tokenTransfers||[]).filter(item=>String(item.chainId||"").toLowerCase()===subject.chainId&&[item.from,item.to].some(value=>cleanAddress(value)===subject.address));
 if(transfers.length)addHypothesis({id:"transfer-log-semantics",
  question:"Do the Transfer-shaped logs represent valid token transfers emitted by a legitimate token contract?",
  why:transfers.length+" imported receipt-log candidate(s) involve the subject.",
  verification:"Match transaction receipt, block, log index, emitting contract and indexed topics; verify contract identity and decimals independently before interpreting amounts.",
  references:transfers.map(item=>item.transactionHash).filter(Boolean)});
 const handoffs=(threatIntelligence.transactionLinks||[]).filter(item=>String(item.chainId||"").toLowerCase()===subject.chainId&&[item.from,item.via,item.to].some(value=>cleanAddress(value)===subject.address));
 if(handoffs.length)addHypothesis({id:"handoff-asset-continuity",
  question:"Does each observed transaction handoff correspond to continuity of a specific asset or merely sequential transaction participation?",
  why:handoffs.length+" imported handoff trail(s) involve the subject.",
  verification:"Retrieve every transaction and receipt in the sequence. Verify chain, block order, sender/recipient and asset-specific logs independently for each leg.",
  references:handoffs.flatMap(item=>item.transactionHashes||item.hashes||[]).filter(validHash)});
 const signals=(threatIntelligence.signals||[]).filter(item=>String(item.chainId||"").toLowerCase()===subject.chainId&&((item.entities||[]).some(value=>cleanAddress(value)===subject.address)||(item.evidence||[]).some(e=>[e.address,e.from,e.to,e.implementation].some(value=>cleanAddress(value)===subject.address))));
 if(signals.length)addHypothesis({id:"review-signal-revalidation",
  question:"Do the rule-based review signals persist when their underlying source observations are independently revalidated?",
  why:signals.length+" imported review signal(s) match the subject.",
  verification:"Open each source case, inspect the raw observation and confirm chain/block context with an independent RPC or explorer. Signals are review prompts, not maliciousness findings.",
  references:signals.flatMap(item=>[...(item.caseSubjects||[]),...(item.evidence||[]).map(e=>e.transactionHash||e.txHash)].filter(Boolean))});
 if(neighborhood.summary?.truncated)addHypothesis({id:"neighborhood-coverage",
  question:"Would a larger or pivoted evidence window materially change the observed neighborhood?",
  why:"The current neighborhood reached a configured node or edge cap.",
  verification:"Repeat the traversal with higher supported bounds or pivot from boundary entities; compare source coverage and preserve each snapshot.",
  references:[]});
 if(!hypotheses.length)addHypothesis({id:"source-coverage",
  question:"Is the current imported evidence sufficiently broad and independent to support a conclusion?",
  why:"No specialized hypothesis rule was triggered by the supplied neighborhood.",
  verification:"Import additional independently sourced case reports, transaction receipts and historical context before drawing conclusions.",
  references:[]});
 const taskSummary={total:playbook.tasks.length,pending:playbook.tasks.filter(task=>task.status==="pending").length,
  inProgress:playbook.tasks.filter(task=>task.status==="in-progress").length,verifiedByAnalyst:playbook.tasks.filter(task=>task.status==="verified").length,
  notApplicable:playbook.tasks.filter(task=>task.status==="not-applicable").length};
 const sourceRefs=unique([...orderedTimeline.map(item=>item.transactionHash),...(gapAnalysis.recommendations||[]).flatMap(item=>item.evidence||[]),...signals.flatMap(item=>item.caseSubjects||[])]);
 const limitations=unique([
  "This dossier is assembled only from the bounded neighborhood and evidence already imported into SENTINEL; it performs no RPC, explorer or external enrichment.",
  "Timeline order is by available block, transaction and log indexes. Entries without ordering metadata are placed after entries with known block numbers; this is not a wall-clock chronology.",
  "Hypotheses are unverified questions for analyst testing, not allegations, findings or probability estimates.",
  "A VERIFIED playbook task is an analyst assertion with a supplied reference; SENTINEL does not validate that reference.",
  "Observed graph links, shared infrastructure, Transfer-shaped logs, handoffs and rule-based signals do not prove ownership, coordination, malicious intent or movement of the same assets.",
  "A truncated neighborhood and imported-only source set are incomplete by design; missing observations are not evidence of absence.",
  ...(neighborhood.limitations||[]),...(gapAnalysis.limitations||[]),...(playbook.limitations||[])
 ]);
 return {schema:"sentinel.investigation-intelligence.v1",caseId:caseId||"case-"+subject.chainId+"-"+subject.address,
  generatedAt,subject,coverage:"bounded-neighborhood-and-imported-evidence-only",
  assessment:{verdict:"not-assessed",riskScore:null},
  summary:{entityCount:(neighborhood.nodes||[]).length,relationshipCount:(neighborhood.edges||[]).length,
   timelineEntryCount:orderedTimeline.length,hypothesisCount:hypotheses.length,sourceReferenceCount:sourceRefs.length,
   neighborhoodTruncated:Boolean(neighborhood.summary?.truncated),playbook:taskSummary},
  timeline:orderedTimeline,hypotheses,sourceReferences:sourceRefs,
  evidenceCoverage:{neighborhood:clone(neighborhood.summary||{}),gapAnalysis:clone(gapAnalysis.summary||{}),
   playbook:taskSummary,sourceCaseSubjects:unique([...(threatIntelligence.signals||[]).filter(item=>String(item.chainId||"").toLowerCase()===subject.chainId).flatMap(item=>item.caseSubjects||[]),...(threatIntelligence.tokenTransfers||[]).filter(item=>String(item.chainId||"").toLowerCase()===subject.chainId).map(item=>item.caseSubject)])},
  analystWorkflow:{playbookId:playbook.id,updatedAt:playbook.updatedAt,tasks:clone(playbook.tasks)},
  limitations});
}
