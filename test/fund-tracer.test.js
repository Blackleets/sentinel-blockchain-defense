import test from "node:test";
import assert from "node:assert/strict";
import { traceFundPaths } from "../src/fund-tracer.js";

const a="0x"+"1".repeat(40), b="0x"+"2".repeat(40), c="0x"+"3".repeat(40), d="0x"+"4".repeat(40);
const token="0x"+"a".repeat(40), hash=n=>"0x"+String(n).repeat(64);
const edge=(from,to,amount,block,overrides={})=>({
 chainId:"0x1",token,from,to,amountRaw:String(amount),blockNumber:"0x"+block.toString(16),
 logIndex:"0x0",transactionHash:hash(block%10||1),...overrides
});

test("finds a directed same-asset, time-ordered, amount-compatible route",()=>{
 const result=traceFundPaths([edge(a,b,100,10),edge(b,c,70,11),edge(c,d,70,12)],{source:a,target:d,chainId:"0x1"});
 assert.equal(result.pathCount,1);assert.equal(result.paths[0].hopCount,3);
 assert.equal(result.paths[0].amountCompatibility,"partial-amount-compatible");
 assert.equal(result.paths[0].edges[2].to,d);
});
test("never joins different assets or chains",()=>{
 const result=traceFundPaths([edge(a,b,100,10),edge(b,d,100,11,{token:"0x"+"b".repeat(40)}),edge(b,d,100,11,{chainId:"0x38"})],{source:a,target:d,chainId:"0x1"});
 assert.equal(result.pathCount,0);
});
test("rejects amount increases and out-of-order transfers",()=>{
 const tooMuch=traceFundPaths([edge(a,b,50,10),edge(b,d,51,11)],{source:a,target:d,chainId:"0x1"});
 const earlier=traceFundPaths([edge(a,b,50,10),edge(b,d,40,9)],{source:a,target:d,chainId:"0x1"});
 assert.equal(tooMuch.pathCount,0);assert.equal(earlier.pathCount,0);
});
test("rejects cycles and excludes internal traces",()=>{
 const result=traceFundPaths([edge(a,b,100,10),edge(b,a,90,11),edge(b,d,80,12,{transferType:"internal"})],{source:a,target:d,chainId:"0x1"});
 assert.equal(result.pathCount,0);
});
test("bounds depth and path count and exposes truncation",()=>{
 const records=[edge(a,b,100,10),edge(b,d,90,11),edge(a,c,100,12),edge(c,d,90,13)];
 const shallow=traceFundPaths(records,{source:a,target:d,chainId:"0x1",maxDepth:1});
 const capped=traceFundPaths(records,{source:a,target:d,chainId:"0x1",maxPaths:1});
 assert.equal(shallow.pathCount,0);assert.equal(capped.pathCount,1);assert.equal(capped.truncated,true);
});
test("validates inputs and reports no path without inferring inactivity",()=>{
 assert.throws(()=>traceFundPaths([],{source:"bad",target:d,chainId:"0x1"}),/Valid source/);
 const result=traceFundPaths([],{source:a,target:d,chainId:"0x1"});
 assert.equal(result.interpretation.status,"no-candidate-path-found");
 assert.match(result.interpretation.notProof,/do not prove/);
});
