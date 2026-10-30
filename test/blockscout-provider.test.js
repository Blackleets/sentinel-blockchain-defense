import test from "node:test";
import assert from "node:assert/strict";
import { fetchBlockscoutAddressTransfers, BLOCKSCOUT_ENDPOINTS } from "../src/blockscout-provider.js";

const address = "0x1111111111111111111111111111111111111111";
const from = "0x2222222222222222222222222222222222222222";
const token = "0x3333333333333333333333333333333333333333";
const hash = "0x" + "a".repeat(64);
const item = (overrides={}) => ({
  token_type:"ERC-20", transaction_hash:hash, block_number:100, log_index:2,
  from:{hash:from}, to:{hash:address},
  token:{address_hash:token,symbol:"USDC",name:"USD Coin",decimals:"6"},
  total:{value:"1234500",decimals:"6"}, timestamp:"2026-10-30T12:00:00.000000Z",
  ...overrides
});
const response = (items,next_page_params=null) => ({ok:true,status:200,json:async()=>({items,next_page_params})});

test("normalizes paginated Blockscout ERC-20 records and keeps exact base units",async()=>{
 const calls=[];
 const result=await fetchBlockscoutAddressTransfers({address,chainId:"0x1",fetchImpl:async url=>{
  calls.push(new URL(url));
  return calls.length===1?response([item()],{block_number:99,index:1,items_count:50}):response([item({log_index:3,transaction_hash:"0x"+"b".repeat(64)})]);
 }});
 assert.equal(calls.length,3); // from: two pages; to: one page
 assert.equal(result.transfers.length,2);
 assert.equal(result.transfers[0].amountRaw,"1234500");
 assert.equal(result.transfers[0].tokenMetadata.decimals,6);
 assert.equal(result.complete,true);
 assert.equal(result.truncated,false);
 assert.equal(calls[1].searchParams.get("block_number"),"99");
 assert.equal(calls[2].searchParams.get("filter"),"to");
});

test("deduplicates direction overlap and excludes malformed or non-ERC20 records",async()=>{
 const bad=item({token_type:"ERC-721"});
 const invalid=item({from:{hash:"not-an-address"}});
 const result=await fetchBlockscoutAddressTransfers({address,chainId:"0x1",fetchImpl:async()=>response([item(),item(),bad,invalid])});
 assert.equal(result.transfers.length,1);
 assert.equal(result.malformedItems,2);
});

test("marks results truncated when page cap is reached with a cursor",async()=>{
 const result=await fetchBlockscoutAddressTransfers({address,chainId:"0x1",maxPages:1,fetchImpl:async()=>response([item()],{block_number:99,index:1})});
 assert.equal(result.complete,false);
 assert.equal(result.truncated,true);
 assert.equal(result.directionCoverage.from.hasMore,true);
});

test("rejects unsupported chains, invalid addresses and unsafe page limits",async()=>{
 await assert.rejects(()=>fetchBlockscoutAddressTransfers({address,chainId:"0x38"}),/No validated/);
 await assert.rejects(()=>fetchBlockscoutAddressTransfers({address:"bad",chainId:"0x1"}),/valid EVM/);
 await assert.rejects(()=>fetchBlockscoutAddressTransfers({address,chainId:"0x1",maxPages:21}),/maxPages/);
 assert.equal(BLOCKSCOUT_ENDPOINTS["0x1"],"https://eth.blockscout.com/api/v2");
});
