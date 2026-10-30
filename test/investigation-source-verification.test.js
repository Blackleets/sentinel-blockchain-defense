import test from "node:test";
import assert from "node:assert/strict";
import {verifyInvestigationDossierSources} from "../src/investigation-source-verification.js";
const address="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",token="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const txHash="0x"+"1".repeat(64),blockHash="0x"+"2".repeat(64);
const fromTopic="0x"+"0".repeat(24)+address.slice(2),toTopic="0x"+"0".repeat(24)+token.slice(2);
const transferTopic="0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const transferLog={address:token,topics:[transferTopic,fromTopic,toTopic],data:"0x"+BigInt(42).toString(16).padStart(64,"0"),blockNumber:"0x10",transactionHash:txHash,transactionIndex:"0x0",logIndex:"0x0"};
const tx={hash:txHash,blockNumber:"0x10",blockHash,from:address,to:token};
const receipt={transactionHash:txHash,blockNumber:"0x10",blockHash,status:"0x1",logs:[transferLog]};
const dossier=()=>({schema:"sentinel.investigation-intelligence.v1",subject:{chainId:"0x1",address},
 timeline:[{kind:"observed-token-transfer-log",chainId:"0x1",blockNumber:"0x10",transactionHash:txHash,logIndex:"0x0",source:"receipt-log",record:{edgeType:"observed-token-transfer-log",from:address,to:token,evidence:{token,amountRaw:"42"}}}],
 sourceReferences:[txHash]});
function mockFetch({chainId="0x1",transaction=tx,transactionReceipt=receipt}={}){
 const calls=[];
 const fetchImpl=async(url,options)=>{const request=JSON.parse(options.body);calls.push(request.method);let result;
  if(request.method==="eth_chainId")result=chainId;
  else if(request.method==="eth_getTransactionByHash")result=transaction;
  else if(request.method==="eth_getTransactionReceipt")result=transactionReceipt;
  else throw new Error("Unexpected method "+request.method);
  return {ok:true,status:200,json:async()=>({jsonrpc:"2.0",id:request.id,result})};
 };
 return {fetchImpl,calls};
}
test("confirms transaction receipt and exact transfer-log provenance on the configured chain",async()=>{
 const mock=mockFetch(),result=await verifyInvestigationDossierSources(dossier(),{fetchImpl:mock.fetchImpl,observedAt:"2026-10-30T12:30:00Z"});
 assert.equal(result.chainCheck.matched,true);
 assert.equal(result.summary.confirmedTransactions,1);
 assert.equal(result.summary.matchedEvidenceChecks,1);
 assert.equal(result.summary.evidenceMismatches,0);
 assert.deepEqual(mock.calls,["eth_chainId","eth_getTransactionByHash","eth_getTransactionReceipt"]);
 assert.equal(result.limitations.some(item=>item.includes("one configured public RPC endpoint")),true);
});
test("flags a receipt log whose decoded amount differs from the dossier evidence",async()=>{
 const badReceipt={...receipt,logs:[{...transferLog,data:"0x"+BigInt(99).toString(16).padStart(64,"0")}]};
 const result=await verifyInvestigationDossierSources(dossier(),{fetchImpl:mockFetch({transactionReceipt:badReceipt}).fetchImpl});
 assert.equal(result.summary.confirmedTransactions,1);
 assert.equal(result.summary.evidenceMismatches,1);
 assert.ok(result.results[0].evidenceChecks[0].problems.includes("transfer-amount-does-not-match-receipt-log"));
});
test("rejects a mismatched RPC chain before querying transactions",async()=>{
 const mock=mockFetch({chainId:"0x89"});
 await assert.rejects(()=>verifyInvestigationDossierSources(dossier(),{fetchImpl:mock.fetchImpl}),/chain mismatch/);
 assert.deepEqual(mock.calls,["eth_chainId"]);
});
test("distinguishes not-found, pending and unavailable receipt states",async()=>{
 const notFound=await verifyInvestigationDossierSources(dossier(),{fetchImpl:mockFetch({transaction:null,transactionReceipt:null}).fetchImpl});
 assert.equal(notFound.results[0].status,"not-found");
 const pending=await verifyInvestigationDossierSources(dossier(),{fetchImpl:mockFetch({transaction:{...tx,blockNumber:null},transactionReceipt:null}).fetchImpl});
 assert.equal(pending.results[0].status,"pending");
 const noReceipt=await verifyInvestigationDossierSources(dossier(),{fetchImpl:mockFetch({transactionReceipt:null}).fetchImpl});
 assert.equal(noReceipt.results[0].status,"receipt-unavailable");
});
test("limits reference count and reports unchecked references",async()=>{
 const data=dossier();data.sourceReferences=[txHash,...Array.from({length:3},(_,i)=>"0x"+String(i+2).repeat(64))];
 const result=await verifyInvestigationDossierSources(data,{fetchImpl:mockFetch().fetchImpl,maxTransactions:2});
 assert.equal(result.coverage.checkedTransactions,2);
 assert.equal(result.coverage.notChecked,2);
 assert.equal(result.coverage.truncated,true);
});
test("rejects unsupported chains, invalid limits and malformed dossiers",async()=>{
 await assert.rejects(()=>verifyInvestigationDossierSources({...dossier(),subject:{chainId:"0x999",address}}, {fetchImpl:mockFetch().fetchImpl}),/No configured RPC endpoint/);
 await assert.rejects(()=>verifyInvestigationDossierSources(dossier(),{fetchImpl:mockFetch().fetchImpl,maxTransactions:101}),/between 1 and 100/);
 await assert.rejects(()=>verifyInvestigationDossierSources({}, {fetchImpl:mockFetch().fetchImpl}),/SENTINEL investigation intelligence dossier/);
});

test("treats malformed receipt topics as evidence mismatch rather than crashing",async()=>{
 const malformed={...transferLog,topics:[transferTopic,17,toTopic]};
 const result=await verifyInvestigationDossierSources(dossier(),{fetchImpl:mockFetch({transactionReceipt:{...receipt,logs:[malformed]}}).fetchImpl});
 assert.equal(result.summary.confirmedTransactions,1);
 assert.equal(result.summary.evidenceMismatches,1);
 assert.ok(result.results[0].evidenceChecks[0].problems.includes("receipt-log-is-not-a-decodable-erc20-transfer"));
});
test("checks transaction-flow endpoints against the RPC transaction",async()=>{
 const data=dossier();data.timeline=[{kind:"observed-transaction-flow",chainId:"0x1",blockNumber:"0x10",transactionHash:txHash,logIndex:null,source:"correlation-graph",record:{edgeType:"observed-transaction-flow",from:address,to:"0xcccccccccccccccccccccccccccccccccccccccc"}}];
 const result=await verifyInvestigationDossierSources(data,{fetchImpl:mockFetch().fetchImpl});
 assert.equal(result.summary.evidenceMismatches,1);
 assert.ok(result.results[0].evidenceChecks[0].problems.includes("transaction-recipient-does-not-match-observed-flow"));
});
