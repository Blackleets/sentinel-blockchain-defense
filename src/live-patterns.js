const ADDRESS=/^0x[0-9a-f]{40}$/i;
const HASH=/^0x[0-9a-f]{64}$/i;
const clean=value=>typeof value==="string"&&ADDRESS.test(value)?value.toLowerCase():null;

/**
 * Derive transparent topology review prompts from the exact loaded transfer edges.
 * These are structural observations, not risk scores, attribution or intent findings.
 */
export function deriveLivePatterns(edges,{origin=null,minCounterparties=3,maxSignals=20}={}){
 if(!Array.isArray(edges))throw new TypeError("A transfer edge array is required");
 if(!Number.isInteger(minCounterparties)||minCounterparties<2||minCounterparties>20)throw new RangeError("minCounterparties must be between 2 and 20");
 if(!Number.isInteger(maxSignals)||maxSignals<1||maxSignals>100)throw new RangeError("maxSignals must be between 1 and 100");
 const subject=origin==null?null:clean(origin);
 if(origin!=null&&!subject)throw new TypeError("origin must be a valid EVM address");
 const groups=new Map();
 edges.forEach((edge,index)=>{
  const from=clean(edge?.from),to=clean(edge?.to),token=clean(edge?.token);
  if(!from||!to||!token||from===to)return;
  const chainId=typeof edge.chainId==="string"?edge.chainId.toLowerCase():"unknown";
  const key=chainId+"|"+token;
  if(!groups.has(key))groups.set(key,{chainId,token,edges:[]});
  groups.get(key).edges.push({from,to,index,transactionHash:typeof edge.transactionHash==="string"&&HASH.test(edge.transactionHash)?edge.transactionHash.toLowerCase():null});
 });
 const signals=[];
 for(const group of groups.values()){
  for(const [address,direction] of [[null,"fan-in"],[null,"fan-out"]]){
   const buckets=new Map();
   for(const edge of group.edges){
    const pivot=direction==="fan-in"?edge.to:edge.from;
    const counterparty=direction==="fan-in"?edge.from:edge.to;
    if(!buckets.has(pivot))buckets.set(pivot,new Map());
    const bucket=buckets.get(pivot);
    if(!bucket.has(counterparty))bucket.set(counterparty,[]);
    bucket.get(counterparty).push(edge);
   }
   for(const [pivot,counterparties] of buckets){
    if(counterparties.size<minCounterparties)continue;
    const records=[...counterparties.values()].flat();
    const hashes=[...new Set(records.map(item=>item.transactionHash).filter(Boolean))];
    signals.push({
     id:direction+":"+group.chainId+":"+group.token+":"+pivot,
     pattern:direction,
     label:direction==="fan-in"?"Multiple counterparties → one address":"One address → multiple counterparties",
     chainId:group.chainId,token:group.token,subject:pivot,
     counterparties:[...counterparties.keys()].sort(),
     counterpartyCount:counterparties.size,edgeCount:records.length,
     edgeIndexes:records.map(item=>item.index).sort((a,b)=>a-b),
     transactionHashes:hashes,
     originRelated:subject===pivot||counterparties.has(subject),
     interpretation:"Observed topology only. This pattern can arise from ordinary exchange, treasury, payment, router or contract activity; it does not establish common ownership, coordination, laundering or malicious intent."
    });
   }
  }
 }
 const ordered=signals.sort((a,b)=>b.counterpartyCount-a.counterpartyCount||b.edgeCount-a.edgeCount||a.pattern.localeCompare(b.pattern)||a.subject.localeCompare(b.subject));
 return {schema:"sentinel.live-patterns.v1",method:"same-chain-and-token-counterparty-count",threshold:minCounterparties,
  signalCount:ordered.length,signals:ordered.slice(0,maxSignals),truncated:ordered.length>maxSignals,
  limitations:["Patterns are derived only from the transfer edges loaded in this investigation snapshot.","Counterparty counts are grouped by chain and token contract; missing or malformed edges are ignored.","A fan-in or fan-out topology is not a risk score, entity attribution or proof of intent.","No signal means no configured topology pattern was found in the supplied bounded evidence, not that no pattern exists."]};
}


/**
 * Detect local transfer concentration in a bounded block window.
 * Requires distinct transaction hashes so multiple logs in one transaction do not inflate a burst.
 */
export function deriveBlockWindowBursts(edges,{blockWindow=20,minEvents=4,minTransactions=3,maxSignals=20}={}){
 if(!Array.isArray(edges))throw new TypeError("A transfer edge array is required");
 if(!Number.isInteger(blockWindow)||blockWindow<1||blockWindow>100000)throw new RangeError("blockWindow must be between 1 and 100000");
 if(!Number.isInteger(minEvents)||minEvents<3||minEvents>1000)throw new RangeError("minEvents must be between 3 and 1000");
 if(!Number.isInteger(minTransactions)||minTransactions<2||minTransactions>minEvents)throw new RangeError("minTransactions must be between 2 and minEvents");
 if(!Number.isInteger(maxSignals)||maxSignals<1||maxSignals>100)throw new RangeError("maxSignals must be between 1 and 100");
 const groups=new Map();
 edges.forEach((edge,index)=>{
  const from=clean(edge?.from),to=clean(edge?.to),token=clean(edge?.token);
  if(!from||!to||!token||from===to||!HASH.test(edge?.transactionHash||""))return;
  let block;try{block=BigInt(edge.blockNumber);}catch{return;}
  if(block<0n)return;
  const chainId=typeof edge.chainId==="string"?edge.chainId.toLowerCase():"unknown";
  for(const [direction,subject] of [["outgoing",from],["incoming",to]]){
   const key=[chainId,token,subject,direction].join("|");
   if(!groups.has(key))groups.set(key,{chainId,token,subject,direction,records:[]});
   groups.get(key).records.push({index,block,transactionHash:edge.transactionHash.toLowerCase()});
  }
 });
 const signals=[];
 for(const group of groups.values()){
  const records=group.records.sort((a,b)=>a.block<b.block?-1:a.block>b.block?1:a.index-b.index);
  let lastEnd=-1;
  for(let start=0;start<records.length;start++){
   let end=start;
   while(end+1<records.length&&records[end+1].block-records[start].block<=BigInt(blockWindow))end++;
   if(end-start+1<minEvents)continue;
   const slice=records.slice(start,end+1),hashes=[...new Set(slice.map(item=>item.transactionHash))];
   if(hashes.length<minTransactions||end<=lastEnd)continue;
   signals.push({id:"block-burst:"+group.chainId+":"+group.token+":"+group.subject+":"+group.direction+":"+records[start].block.toString(),
    pattern:"block-window-burst",label:group.direction==="outgoing"?"Outgoing activity concentration":"Incoming activity concentration",
    chainId:group.chainId,token:group.token,subject:group.subject,direction:group.direction,
    blockFrom:"0x"+records[start].block.toString(16),blockTo:"0x"+records[end].block.toString(16),
    blockSpan:(records[end].block-records[start].block).toString(),blockWindow,
    edgeCount:slice.length,transactionCount:hashes.length,edgeIndexes:slice.map(item=>item.index).sort((a,b)=>a-b),
    transactionHashes:hashes,
    interpretation:"Observed event concentration inside a configured block window. Block distance is not elapsed time; this does not establish automation, coordination, ownership or malicious intent."
   });
   lastEnd=end;
  }
 }
 const ordered=signals.sort((a,b)=>b.transactionCount-a.transactionCount||b.edgeCount-a.edgeCount||a.subject.localeCompare(b.subject));
 return {schema:"sentinel.live-block-bursts.v1",method:"distinct-transactions-per-subject-token-block-window",
  blockWindow,minEvents,minTransactions,signalCount:ordered.length,signals:ordered.slice(0,maxSignals),truncated:ordered.length>maxSignals,
  limitations:["Only loaded edges with valid block numbers and transaction hashes are considered.","Block distance is not elapsed time; no timestamp-based velocity is inferred.","Distinct transactions are counted, but repeated transactions may still be ordinary batching, exchange, router or contract behavior.","A burst is a review prompt, not a risk score or proof of intent."]};
}
