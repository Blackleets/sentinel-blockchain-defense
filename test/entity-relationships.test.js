import test from "node:test";
import assert from "node:assert/strict";
import {buildEntityNeighborhood} from "../src/entity-relationships.js";
const a="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",b="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",c="0xcccccccccccccccccccccccccccccccccccccccc",d="0xdddddddddddddddddddddddddddddddddddddddd";
const graph={schema:"sentinel.correlation-graph.v1",edges:[{chainId:"0x1",type:"observed-transaction-flow",from:a,to:b,evidence:[{caseSubjects:["case-a"]}]},{chainId:"0x38",type:"observed-transaction-flow",from:a,to:d,evidence:[]}]};
const intel={schema:"sentinel.threat-intelligence.v1",tokenTransfers:[{chainId:"0x1",from:b,to:c,token:d,transactionHash:"0x1",blockNumber:"0x10",logIndex:"0x0",amountRaw:"100"}],transactionLinks:[{chainId:"0x1",from:c,via:d,to:a,transactionHashes:["0x2"]}]};
test("expands deterministic observed neighborhood and preserves provenance",()=>{const r=buildEntityNeighborhood({graph,threatIntelligence:intel,chainId:"0x1",address:a,maxDepth:2});assert.equal(r.schema,"sentinel.entity-neighborhood.v1");assert.ok(r.nodes.some(n=>n.address===b));assert.ok(r.nodes.some(n=>n.address===d));assert.ok(r.edges.some(e=>e.source==="receipt-log"));assert.equal(r.assessment.verdict,"not-assessed");});
test("keeps graph relationships chain scoped",()=>{const r=buildEntityNeighborhood({graph,threatIntelligence:{...intel,transactionLinks:[],tokenTransfers:[]},chainId:"0x1",address:a,maxDepth:3});assert.deepEqual(r.nodes.map(n=>n.address),[a,b]);});
test("bounds expansion depth for handoff trails",()=>{const r=buildEntityNeighborhood({graph:{schema:"sentinel.correlation-graph.v1",edges:[]},threatIntelligence:intel,chainId:"0x1",address:a,maxDepth:1});assert.equal(r.edges.length,1);assert.ok(r.nodes.some(n=>n.address===d));assert.ok(!r.nodes.some(n=>n.address===c));});
test("marks node truncation and validates inputs",()=>{const many=Array.from({length:4},(_,i)=>({chainId:"0x1",type:"observed-transaction-flow",from:a,to:"0x"+String(i+1).repeat(40),evidence:[]}));const r=buildEntityNeighborhood({graph:{schema:"sentinel.correlation-graph.v1",edges:many},threatIntelligence:intel,chainId:"0x1",address:a,maxNodes:2});assert.equal(r.summary.truncated,true);assert.equal(r.summary.nodeCount,2);assert.throws(()=>buildEntityNeighborhood({graph,threatIntelligence:intel,chainId:"0x1",address:"bad"}),/valid EVM address/);assert.throws(()=>buildEntityNeighborhood({graph,threatIntelligence:intel,chainId:"0x1",address:a,maxDepth:4}),/between 1 and 3/);assert.throws(()=>buildEntityNeighborhood({graph,threatIntelligence:intel,chainId:"0x1",address:a,maxNodes:501}),/between 1 and 500/);});

test("expands every shared-infrastructure address recorded across edge evidence",()=>{
 const sharedA="0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
 const sharedB="0xffffffffffffffffffffffffffffffffffffffff";
 const sharedGraph={schema:"sentinel.correlation-graph.v1",edges:[{chainId:"0x1",type:"shared-erc1967-implementation",from:a,to:b,evidence:[{sharedAddress:sharedA,role:"proxy-implementation",caseSubjects:["case-a","case-b"]},{sharedAddress:sharedB,role:"effective-implementation",caseSubjects:["case-a","case-b"]}]}]};
 const result=buildEntityNeighborhood({graph:sharedGraph,threatIntelligence:{schema:"sentinel.threat-intelligence.v1",tokenTransfers:[],transactionLinks:[]},chainId:"0x1",address:a,maxDepth:1});
 assert.ok(result.nodes.some(node=>node.address===sharedA));
 assert.ok(result.nodes.some(node=>node.address===sharedB));
 assert.equal(result.edges.filter(edge=>edge.source==="shared-infrastructure").length,2);
 assert.ok(result.edges.every(edge=>edge.evidence.some(item=>item.sharedAddress===sharedA||item.sharedAddress===sharedB)));
});
