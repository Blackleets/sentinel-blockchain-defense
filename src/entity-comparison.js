const ADDRESS=/^0x[0-9a-f]{40}$/i;
const normalize=value=>typeof value==="string"&&ADDRESS.test(value)?value.toLowerCase():null;
const unique=values=>[...new Set(values.filter(Boolean))].sort();
const HASH=/^0x[0-9a-f]{64}$/i;
const hash=value=>typeof value==="string"&&HASH.test(value)?value.toLowerCase():null;

function caseRefs(record){
 const values=[];
 for(const item of record?.evidence||[]){
  if(Array.isArray(item.caseSubjects))values.push(...item.caseSubjects);
  if(typeof item.caseSubject==="string")values.push(item.caseSubject);
 }
 if(Array.isArray(record?.caseSubjects))values.push(...record.caseSubjects);
 if(typeof record?.caseSubject==="string")values.push(record.caseSubject);
 return values.filter(value=>typeof value==="string"&&value.length>0);
}

/**
 * Compare two entities using exact, chain-scoped overlaps in supplied evidence.
 * Every overlap is returned as an observation category, never an attribution.
 */
export function compareObservedEntities({graph,threatIntelligence,chainId,addressA,addressB}){
 if(!graph||graph.schema!=="sentinel.correlation-graph.v1")throw new TypeError("A SENTINEL correlation graph is required");
 if(!threatIntelligence||threatIntelligence.schema!=="sentinel.threat-intelligence.v1")throw new TypeError("SENTINEL threat intelligence is required");
 const a=normalize(addressA),b=normalize(addressB);
 if(!a||!b)throw new TypeError("Two valid EVM addresses are required");
 if(a===b)throw new RangeError("Choose two different addresses");
 if(typeof chainId!=="string"||!chainId)throw new TypeError("A chain ID is required");
 const chain=chainId.toLowerCase();
 const edges=(graph.edges||[]).filter(edge=>String(edge.chainId).toLowerCase()===chain);
 const transfers=(threatIntelligence.tokenTransfers||[]).filter(item=>String(item.chainId).toLowerCase()===chain);
 const handoffs=(threatIntelligence.transactionLinks||[]).filter(item=>String(item.chainId).toLowerCase()===chain);
 const incident=(address)=>[
  ...edges.filter(edge=>normalize(edge.from)===address||normalize(edge.to)===address).map(edge=>({kind:"correlation-edge",counterparty:normalize(edge.from)===address?normalize(edge.to):normalize(edge.from),record:edge})),
  ...transfers.filter(item=>normalize(item.from)===address||normalize(item.to)===address).map(item=>({kind:"token-transfer-log",counterparty:normalize(item.from)===address?normalize(item.to):normalize(item.from),record:item})),
  ...handoffs.filter(item=>[item.from,item.via,item.to].some(value=>normalize(value)===address)).map(item=>({kind:"transaction-handoff",counterparty:[item.from,item.via,item.to].map(normalize).find(value=>value&&value!==address)||null,record:item}))
 ];
 const aEvidence=incident(a),bEvidence=incident(b);
 const counterparties=items=>unique(items.map(item=>item.counterparty).filter(value=>value&&value!==a&&value!==b));
 const aCounterparties=new Set(counterparties(aEvidence)),bCounterparties=new Set(counterparties(bEvidence));
 const sharedCounterparties=[...aCounterparties].filter(value=>bCounterparties.has(value)).sort();
 const directEdges=edges.filter(edge=>(normalize(edge.from)===a&&normalize(edge.to)===b)||(normalize(edge.from)===b&&normalize(edge.to)===a));
 const directReceiptLogs=transfers.filter(item=>(normalize(item.from)===a&&normalize(item.to)===b)||(normalize(item.from)===b&&normalize(item.to)===a));
 const directHandoffLinks=handoffs.filter(item=>{const sequence=[item.from,item.via,item.to].map(normalize);return sequence.some((value,index)=>value===a&&sequence[index+1]===b)||sequence.some((value,index)=>value===b&&sequence[index+1]===a);});
 const transactionMap=(items,address)=>{const map=new Map();for(const item of items){const participants=[item.from,item.to,item.via].map(normalize);if(!participants.includes(address))continue;const tx=hash(item.transactionHash||item.txHash);if(!tx)continue;if(!map.has(tx))map.set(tx,[]);map.get(tx).push(item);}return map;};
 const txA=transactionMap([...transfers,...handoffs],a),txB=transactionMap([...transfers,...handoffs],b);
 const sharedTransactionHashes=[...txA.keys()].filter(value=>txB.has(value)).sort();
 const caseA=new Set(aEvidence.flatMap(item=>caseRefs(item.record)));
 const caseB=new Set(bEvidence.flatMap(item=>caseRefs(item.record)));
 const sharedCaseSubjects=[...caseA].filter(value=>caseB.has(value)).sort();
 const sharedInfrastructureReferences=[];
 for(const edge of edges){
  const endpoints=[normalize(edge.from),normalize(edge.to)];
  if(!endpoints.includes(a)&&!endpoints.includes(b))continue;
  for(const item of edge.evidence||[]){
   const shared=normalize(item.sharedAddress);
   if(!shared||shared===a||shared===b)continue;
   const target=endpoints.includes(a)?a:b;
   sharedInfrastructureReferences.push({entity:target,sharedAddress:shared,edgeType:edge.type,role:item.role||null,observationKind:item.observationKind||null});
  }
 }
 const infraA=new Set(sharedInfrastructureReferences.filter(item=>item.entity===a).map(item=>item.sharedAddress));
 const infraB=new Set(sharedInfrastructureReferences.filter(item=>item.entity===b).map(item=>item.sharedAddress));
 const sharedInfrastructure=[...infraA].filter(value=>infraB.has(value)).sort();
 const evidenceCounts={entityA:aEvidence.length,entityB:bEvidence.length,graphEdgesA:aEvidence.filter(item=>item.kind==="correlation-edge").length,graphEdgesB:bEvidence.filter(item=>item.kind==="correlation-edge").length,tokenLogsA:aEvidence.filter(item=>item.kind==="token-transfer-log").length,tokenLogsB:bEvidence.filter(item=>item.kind==="token-transfer-log").length,handoffsA:aEvidence.filter(item=>item.kind==="transaction-handoff").length,handoffsB:bEvidence.filter(item=>item.kind==="transaction-handoff").length};
 return {
  schema:"sentinel.entity-comparison.v1",
  generatedAt:new Date().toISOString(),
  chainId:chain,
  entities:{a,b},
  summary:{directRelationshipCount:directEdges.length+directReceiptLogs.length+directHandoffLinks.length,sharedCounterpartyCount:sharedCounterparties.length,sharedTransactionHashCount:sharedTransactionHashes.length,sharedCaseSubjectCount:sharedCaseSubjects.length,sharedInfrastructureCount:sharedInfrastructure.length},
  directRelationships:[
   ...directEdges.map(edge=>({type:edge.type,from:normalize(edge.from),to:normalize(edge.to),source:"correlation-graph",evidence:edge.evidence||[]})),
   ...directReceiptLogs.map(item=>({type:"observed-token-transfer-log",from:normalize(item.from),to:normalize(item.to),source:"imported-receipt-log",transactionHash:item.transactionHash||item.txHash||null,blockNumber:item.blockNumber??null,logIndex:item.logIndex??null,amountRaw:item.amountRaw??null,token:item.token||null,caseSubject:item.caseSubject||null})),
   ...directHandoffLinks.map(item=>({type:"transaction-handoff",from:normalize(item.from),via:normalize(item.via),to:normalize(item.to),source:"imported-transaction-handoff",transactionHashes:item.transactionHashes||item.hashes||[]}))
  ],
  sharedCounterparties:sharedCounterparties.map(address=>({address,observedForA:aEvidence.filter(item=>item.counterparty===address).map(item=>item.kind),observedForB:bEvidence.filter(item=>item.counterparty===address).map(item=>item.kind)})),
  sharedTransactionHashes:sharedTransactionHashes.map(transactionHash=>({transactionHash,recordsA:txA.get(transactionHash),recordsB:txB.get(transactionHash)})),
  sharedCaseSubjects,
  sharedInfrastructure,
  evidenceCounts,
  coverage:"supplied-correlation-graph-and-imported-receipt-logs-only",
  limitations:[
   "A shared counterparty means both entities have separately observed records involving the same address; it does not prove common ownership, coordination or a relationship between the entities.",
   "A shared transaction hash means both entities appear in records carrying that exact hash; inspect the underlying records to establish what happened.",
   "A shared case subject is a source reference, not proof of ownership, control or culpability.",
   "Shared infrastructure references are exact recorded metadata and do not establish who controls an implementation, admin, beacon or delegation target.",
   "Only imported evidence on the selected chain is compared. Missing overlap is not evidence of no relationship.",
   "Transfer-shaped logs and handoff trails do not prove movement of the same assets or beneficial ownership."
  ],
  assessment:{verdict:"not-assessed",riskScore:null}
 };
}
