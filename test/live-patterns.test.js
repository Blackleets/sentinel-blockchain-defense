import test from "node:test";
import assert from "node:assert/strict";
import {deriveLivePatterns} from "../src/live-patterns.js";
const a="0x"+"1".repeat(40),b="0x"+"2".repeat(40),c="0x"+"3".repeat(40),d="0x"+"4".repeat(40),e="0x"+"5".repeat(40);
const token="0x"+"a".repeat(40),hash=n=>"0x"+String(n).repeat(64);
const edge=(from,to,n,overrides={})=>({chainId:"0x1",token,from,to,transactionHash:hash(n),...overrides});
test("detects fan-in topology with exact evidence references",()=>{
 const result=deriveLivePatterns([edge(b,a,1),edge(c,a,2),edge(d,a,3)],{origin:a});
 assert.equal(result.signalCount,1);assert.equal(result.signals[0].pattern,"fan-in");
 assert.equal(result.signals[0].counterpartyCount,3);assert.equal(result.signals[0].originRelated,true);
 assert.deepEqual(result.signals[0].transactionHashes,[hash(1),hash(2),hash(3)]);
 assert.match(result.signals[0].interpretation,/does not establish/);
});
test("detects fan-out and keeps different tokens and chains isolated",()=>{
 const result=deriveLivePatterns([edge(a,b,1),edge(a,c,2),edge(a,d,3),edge(a,e,4,{token:"0x"+"b".repeat(40)}),edge(a,e,5,{chainId:"0x38"})]);
 assert.equal(result.signalCount,1);assert.equal(result.signals[0].pattern,"fan-out");
});
test("does not flag below threshold or a single counterparty repeated",()=>{
 const result=deriveLivePatterns([edge(a,b,1),edge(a,b,2),edge(a,c,3)]);
 assert.equal(result.signalCount,0);
});
test("reports bounded output and rejects invalid options",()=>{
 const result=deriveLivePatterns([edge(a,b,1),edge(a,c,2),edge(a,d,3),edge(b,a,4),edge(c,a,5),edge(d,a,6)],{maxSignals:1});
 assert.equal(result.signals.length,1);assert.equal(result.truncated,true);
 assert.throws(()=>deriveLivePatterns([],{origin:"bad"}),/valid EVM/);
 assert.throws(()=>deriveLivePatterns([],{minCounterparties:1}),/minCounterparties/);
});
