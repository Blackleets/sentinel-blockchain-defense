import test from "node:test";
import assert from "node:assert/strict";
import { fetchBlockscoutAddressTransfers, fetchBlockscoutAddressActivity, BLOCKSCOUT_ENDPOINTS } from "../src/blockscout-provider.js";
const address="0x1111111111111111111111111111111111111111",from="0x2222222222222222222222222222222222222222",to="0x4444444444444444444444444444444444444444",token="0x3333333333333333333333333333333333333333",hash="0x"+"a".repeat(64);
const transfer=(overrides={})=>({token_type:"ERC-20",transaction_hash:hash,block_number:100,log_index:2,from:{hash:from},to:{hash:address},token:{address_hash:token,symbol:"USDC",name:"USD Coin",decimals:"6"},total:{value:"1234500",decimals:"6"},timestamp:"2026-10-30T12:00:00.000000Z",...overrides});
const tx=(overrides={})=>({hash,block_number:100,position:3,from:{hash:address},to:{hash},value:"1000000000000000000",timestamp:"2026-10-30T12:00:00.000000Z",status:"ok",...overrides});
const internal=(overrides={})=>({transaction_hash:"0x"+"b".repeat(64),block_number:101,index:2,from:{hash:from},to:{hash:address},value:"500000000000000000",success:true,timestamp:"2026-10-30T12:00:00.000000Z",...overrides});
const response=(items,next_page_params=null)=>({ok:true,status:200,json:async()=>({items,next_page_params})});
test("normalizes paginated ERC20 records and keeps raw base units",async()=>{
 const calls=[];const result=await fetchBlockscoutAddressTransfers({address,chainId:"0x1",fetchImpl:async url=>{calls.push(new URL(url));return calls.length===1?response([transfer()],{block_number:99,index:1,items_count:50}):response([transfer({log_index:3,transaction_hash:"0x"+"c".repeat(64)})]);}});
 assert.equal(calls.length,3);assert.equal(result.transfers.length,2);assert.equal(result.transfers[0].amountRaw,"1234500");assert.equal(result.transfers[0].tokenMetadata.decimals,6);assert.equal(result.complete,true);assert.equal(result.truncated,false);assert.equal(calls[1].searchParams.get("block_number"),"99");assert.equal(calls[2].searchParams.get("filter"),"to");
});
test("deduplicates ERC20 direction overlap and rejects malformed records",async()=>{
 const bad=transfer({token_type:"ERC-721"}),invalid=transfer({from:{hash:"bad"}});
 const result=await fetchBlockscoutAddressTransfers({address,chainId:"0x1",fetchImpl:async url=>new URL(url).searchParams.get("filter")==="from"?response([transfer(),transfer(),bad]):response([transfer(),invalid])});
 assert.equal(result.transfers.length,1);assert.equal(result.malformedItems,2);
});
test("marks ERC20 history truncated at page cap",async()=>{
 const result=await fetchBlockscoutAddressTransfers({address,chainId:"0x1",maxPages:1,fetchImpl:async()=>response([transfer()],{block_number:99,index:1})});
 assert.equal(result.complete,false);assert.equal(result.truncated,true);assert.equal(result.directionCoverage.from.hasMore,true);
});
test("fetches native and successful internal value transfers with distinct provenance",async()=>{
 const seen=[];const result=await fetchBlockscoutAddressActivity({address,chainId:"0x1",fetchImpl:async url=>{const u=new URL(url);seen.push(u.pathname);if(u.pathname.endsWith("/transactions"))return response([tx(),tx({value:"0"}),tx({to:null})]);return response([internal(),internal({success:false}),internal({value:"0"})]);}});
 assert.equal(result.records.length,2);assert.equal(result.counts.nativeTransfers,1);assert.equal(result.counts.internalTransfers,1);assert.equal(result.records.find(x=>x.transferType==="native").tokenMetadata.symbol,"ETH");assert.equal(result.records.find(x=>x.transferType==="internal").token,"INTERNAL:ETH");assert.equal(seen.length,4);
});
test("keeps transaction and internal transfer pagination completeness separate",async()=>{
 const result=await fetchBlockscoutAddressActivity({address,chainId:"0x1",maxPages:1,fetchImpl:async url=>new URL(url).pathname.endsWith("/transactions")?response([tx()],{block_number:99,index:1}):response([internal()])});
 assert.equal(result.complete,false);assert.equal(result.truncated,true);assert.equal(result.coverage.transactions.from.hasMore,true);assert.equal(result.coverage.internalTransactions.to.complete,true);
});
test("rejects unsupported chains, invalid addresses and unsafe page limits",async()=>{
 await assert.rejects(()=>fetchBlockscoutAddressActivity({address,chainId:"0x38"}),/No validated/);await assert.rejects(()=>fetchBlockscoutAddressActivity({address:"bad",chainId:"0x1"}),/valid EVM/);await assert.rejects(()=>fetchBlockscoutAddressActivity({address,chainId:"0x1",maxPages:13}),/maxPages/);assert.equal(BLOCKSCOUT_ENDPOINTS["0x1"],"https://eth.blockscout.com/api/v2");
});
