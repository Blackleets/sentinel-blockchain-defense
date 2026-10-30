import {CHAINS,validateChainId} from "./chains.js";
const HASH=/^0x[0-9a-f]{64}$/i;
const ADDRESS=/^0x[0-9a-f]{40}$/i;
const TRANSFER_TOPIC="0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const lower=value=>typeof value==="string"?value.toLowerCase():null;
const toBigInt=value=>{if(typeof value==="number"&&Number.isSafeInteger(value)&&value>=0)return BigInt(value);if(typeof value==="string"&&/^(0x[0-9a-f]+|[0-9]+)$/i.test(value)){try{return BigInt(value);}catch{}}return null;};
const equalQuantity=(a,b)=>{const left=toBigInt(a),right=toBigInt(b);return left!==null&&right!==null&&left===right;};
const unique=values=>[...new Set(values)];
function decodeTransfer(log){
 if(!log||!Array.isArray(log.topics)||log.topics.length!==3||log.topics.some(topic=>typeof topic!=="string"||!/^0x[0-9a-f]{64}$/i.test(topic))||lower(log.topics[0])!==TRANSFER_TOPIC||typeof log.data!=="string"||!/^0x[0-9a-f]{64}$/i.test(log.data))return null;
 const from="0x"+log.topics[1].slice(-40),to="0x"+log.topics[2].slice(-40),token=lower(log.address);
 if(!ADDRESS.test(from)||!ADDRESS.test(to)||!ADDRESS.test(token||""))return null;
 return {token,from:lower(from),to:lower(to),amountRaw:BigInt(log.data).toString()};
}
async function rpc(fetchImpl,url,method,params,id){
 const response=await fetchImpl(url,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id,method,params})});
 if(!response?.ok)throw new Error("RPC HTTP "+(response?.status??"failure")+" for "+method);
 const payload=await response.json();
 if(payload?.error)throw new Error(payload.error.message||("RPC error for "+method));
 if(!payload||!("result" in payload))throw new Error("Malformed JSON-RPC response for "+method);
 return payload.result;
}
function checkTimelineEntry(item,tx,receipt){
 const problems=[];let checksPerformed=0;
 if(item.blockNumber!==null&&item.blockNumber!==undefined){checksPerformed++;if(!equalQuantity(item.blockNumber,tx.blockNumber))problems.push("timeline-block-does-not-match-transaction");}
 if(item.logIndex!==null&&item.logIndex!==undefined){
  const log=(Array.isArray(receipt.logs)?receipt.logs:[]).find(candidate=>equalQuantity(candidate.logIndex,item.logIndex));
  checksPerformed++;
  if(!log)problems.push("log-index-not-found-in-transaction-receipt");
  else{
   const expected=item.record?.evidence;
   if(expected?.token||item.kind==="observed-token-transfer-log"){
    const decoded=decodeTransfer(log);
    if(!decoded)problems.push("receipt-log-is-not-a-decodable-erc20-transfer");
    else{
     if(expected?.token){checksPerformed++;if(lower(expected.token)!==decoded.token)problems.push("token-contract-does-not-match-receipt-log");}
     if(item.record?.from){checksPerformed++;if(lower(item.record.from)!==decoded.from)problems.push("transfer-sender-does-not-match-receipt-log");}
     if(item.record?.to){checksPerformed++;if(lower(item.record.to)!==decoded.to)problems.push("transfer-recipient-does-not-match-receipt-log");}
     if(expected?.amountRaw!==undefined){checksPerformed++;if(String(expected.amountRaw)!==decoded.amountRaw)problems.push("transfer-amount-does-not-match-receipt-log");}
    }
   }
  }
 }
 if(item.kind==="observed-transaction-flow"||item.record?.edgeType==="observed-transaction-flow"){
  if(item.record?.from){checksPerformed++;if(lower(item.record.from)!==lower(tx.from))problems.push("transaction-sender-does-not-match-observed-flow");}
  if(item.record?.to){checksPerformed++;if(lower(item.record.to)!==lower(tx.to))problems.push("transaction-recipient-does-not-match-observed-flow");}
 }
 return {kind:item.kind,transactionHash:lower(item.transactionHash),blockNumber:item.blockNumber??null,logIndex:item.logIndex??null,
  status:problems.length?"mismatch":checksPerformed?"matched":"not-checkable",checksPerformed,problems};
}
/**
 * Verify dossier transaction references against one configured read-only JSON-RPC endpoint.
 * A confirmed receipt is a provider observation, not a consensus proof or token-legitimacy verdict.
 */
export async function verifyInvestigationDossierSources(dossier,{fetchImpl=globalThis.fetch,maxTransactions=50,observedAt=new Date().toISOString()}={}){
 if(!dossier||dossier.schema!=="sentinel.investigation-intelligence.v1")throw new TypeError("A SENTINEL investigation intelligence dossier is required");
 if(!dossier.subject||typeof dossier.subject.chainId!=="string")throw new TypeError("Dossier chain ID is missing");
 if(typeof fetchImpl!=="function")throw new TypeError("A fetch implementation is required");
 if(!Number.isInteger(maxTransactions)||maxTransactions<1||maxTransactions>100)throw new RangeError("maxTransactions must be an integer between 1 and 100");
 if(typeof observedAt!=="string"||Number.isNaN(Date.parse(observedAt)))throw new TypeError("observedAt must be a valid date string");
 const chainId=dossier.subject.chainId.toLowerCase(),chain=Object.values(CHAINS).find(item=>item.chainId.toLowerCase()===chainId);
 if(!chain)throw new Error("No configured RPC endpoint is available for chain "+chainId);
 const hashes=unique([...(dossier.timeline||[]).map(item=>item.transactionHash),...(dossier.sourceReferences||[]).filter(value=>HASH.test(value||""))].filter(value=>typeof value==="string"&&HASH.test(value)).map(value=>value.toLowerCase()));
 let requestId=1;
 const actualChainId=await rpc(fetchImpl,chain.rpc,"eth_chainId",[],requestId++);
 const chainCheck=validateChainId(chain.chainId,actualChainId);
 if(!chainCheck.ok)throw new Error("RPC chain mismatch: expected "+chain.chainId+" but endpoint returned "+String(actualChainId));
 const selected=hashes.slice(0,maxTransactions),results=[],blockCache=new Map();
 for(const hash of selected){
  const entries=(dossier.timeline||[]).filter(item=>lower(item.transactionHash)===hash);
  try{
   const tx=await rpc(fetchImpl,chain.rpc,"eth_getTransactionByHash",[hash],requestId++);
   if(!tx){results.push({transactionHash:hash,status:"not-found",blockNumber:null,receiptStatus:null,evidenceChecks:entries.map(item=>({kind:item.kind,status:"not-checked",problems:["transaction-not-returned-by-rpc"]}))});continue;}
   if(lower(tx.hash)!==hash){results.push({transactionHash:hash,status:"inconsistent",blockNumber:tx.blockNumber??null,receiptStatus:null,evidenceChecks:entries.map(item=>({kind:item.kind,status:"not-checked",problems:["rpc-returned-a-different-transaction-hash"]}))});continue;}
   if(!tx.blockNumber){results.push({transactionHash:hash,status:"pending",blockNumber:null,receiptStatus:null,evidenceChecks:entries.map(item=>({kind:item.kind,status:"not-checked",problems:["transaction-not-mined"]}))});continue;}
   const receipt=await rpc(fetchImpl,chain.rpc,"eth_getTransactionReceipt",[hash],requestId++);
   if(!receipt){results.push({transactionHash:hash,status:"receipt-unavailable",blockNumber:tx.blockNumber,receiptStatus:null,evidenceChecks:entries.map(item=>({kind:item.kind,status:"not-checked",problems:["mined-transaction-receipt-unavailable"]}))});continue;}
   const baseProblems=[];
   if(lower(receipt.transactionHash)!==hash)baseProblems.push("receipt-transaction-hash-mismatch");
   if(!equalQuantity(tx.blockNumber,receipt.blockNumber))baseProblems.push("transaction-and-receipt-block-number-mismatch");
   if(tx.blockHash&&receipt.blockHash&&lower(tx.blockHash)!==lower(receipt.blockHash))baseProblems.push("transaction-and-receipt-block-hash-mismatch");
   let canonicalBlock=null,canonicalityStatus="unavailable",canonicalityError=null;
   const blockNumber=receipt.blockNumber??tx.blockNumber;
   if(typeof receipt.blockHash==="string"&&blockNumber!==null&&blockNumber!==undefined){
    try{
     const key=String(blockNumber).toLowerCase();
     if(blockCache.has(key))canonicalBlock=blockCache.get(key);
     else{canonicalBlock=await rpc(fetchImpl,chain.rpc,"eth_getBlockByNumber",[blockNumber,false],requestId++);blockCache.set(key,canonicalBlock);}
     if(!canonicalBlock)canonicalityStatus="not-found";
     else if(!equalQuantity(canonicalBlock.number,blockNumber)||lower(canonicalBlock.hash)!==lower(receipt.blockHash)){
      canonicalityStatus="mismatch";baseProblems.push("receipt-block-hash-does-not-match-rpc-block-at-height");
     }else canonicalityStatus="matched";
    }catch(error){canonicalityStatus="unavailable";canonicalityError=error.message;}
   }
   const evidenceChecks=baseProblems.length?entries.map(item=>({kind:item.kind,status:"not-checked",problems:baseProblems})):entries.map(item=>checkTimelineEntry(item,tx,receipt));
   const status=baseProblems.length?"inconsistent":canonicalityStatus==="matched"?"confirmed":"canonicality-unavailable";
   results.push({transactionHash:hash,status,blockNumber:receipt.blockNumber,blockHash:receipt.blockHash||tx.blockHash||null,
    canonicalityStatus,canonicalBlockHash:canonicalBlock?.hash||null,canonicalityError,receiptStatus:receipt.status??null,
    from:lower(tx.from),to:lower(tx.to),logCount:Array.isArray(receipt.logs)?receipt.logs.length:0,evidenceChecks});
  }catch(error){results.push({transactionHash:hash,status:"rpc-error",blockNumber:null,receiptStatus:null,error:error.message,evidenceChecks:entries.map(item=>({kind:item.kind,status:"not-checked",problems:["rpc-request-failed"]}))});}
 }
 const evidenceChecks=results.flatMap(item=>item.evidenceChecks||[]);
 const count=status=>results.filter(item=>item.status===status).length;
 return {schema:"sentinel.investigation-source-verification.v1",subject:{chainId,address:dossier.subject.address.toLowerCase()},
  observedAt,provider:chain.rpc,providerName:chain.name,chainCheck:{expected:chain.chainId,actual:actualChainId,matched:true},
  coverage:{uniqueTransactionReferences:hashes.length,checkedTransactions:selected.length,notChecked:Math.max(0,hashes.length-selected.length),truncated:hashes.length>selected.length},
  summary:{confirmedTransactions:count("confirmed"),canonicalityUnavailableTransactions:count("canonicality-unavailable"),pendingTransactions:count("pending"),notFoundTransactions:count("not-found"),
   receiptUnavailableTransactions:count("receipt-unavailable"),inconsistentTransactions:count("inconsistent"),rpcErrors:count("rpc-error"),
   matchedEvidenceChecks:evidenceChecks.filter(item=>item.status==="matched").length,evidenceMismatches:evidenceChecks.filter(item=>item.status==="mismatch").length,notCheckableEvidenceChecks:evidenceChecks.filter(item=>item.status==="not-checkable").length},
  results,limitations:[
   "Verification queried one configured public RPC endpoint and records its point-in-time response; no independent provider quorum or consensus proof is performed.",
   "A transaction and receipt returned by the endpoint do not authenticate the identity or intent of any address, nor prove a token contract is legitimate.",
   "Receipt-log checks compare only the supplied timeline log index and available transfer fields; they do not prove token decimals, balances, fiat value or complete asset movement.",
   "Pending, not-found, receipt-unavailable and RPC-error results are provider observations; they are not proof that an event never occurred.",
   "Only transaction hashes present in the dossier timeline or 32-byte source references are checked. The configured limit may leave additional references unchecked.",
   "A matching block hash checks the provider current view at the queried height; it is not a finality proof. Reorg risk and historical provider completeness are not independently established."
  ]};
}
