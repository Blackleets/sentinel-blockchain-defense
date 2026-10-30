import test from "node:test";
import assert from "node:assert/strict";
import {layoutEntityNeighborhood} from "../src/entity-layout.js";
const a="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",b="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",c="0xcccccccccccccccccccccccccccccccccccccccc";
const sample={schema:"sentinel.entity-neighborhood.v1",nodes:[{address:a,distance:0,origin:true},{address:b,distance:1,origin:false},{address:c,distance:2,origin:false}],edges:[{from:a,to:b},{from:b,to:c}]};
test("places origin at center and produces deterministic hop rings",()=>{const first=layoutEntityNeighborhood(sample),second=layoutEntityNeighborhood(sample);assert.deepEqual(first,second);assert.deepEqual(first.positions[a],{x:550,y:410,depth:0,degree:1,origin:true});assert.equal(first.positions[b].depth,1);assert.equal(first.positions[c].depth,2);});
test("keeps all generated coordinates inside the canvas",()=>{const nodes=Array.from({length:100},(_,i)=>({address:"0x"+(i+1).toString(16).padStart(40,"0"),distance:i%3+1,origin:false}));nodes.push({address:a,distance:0,origin:true});const result=layoutEntityNeighborhood({...sample,nodes});for(const node of result.nodes){assert.ok(node.x>=0&&node.x<=result.width);assert.ok(node.y>=0&&node.y<=result.height);}});
test("rejects invalid schema and dimensions",()=>{assert.throws(()=>layoutEntityNeighborhood({}),/neighborhood/);assert.throws(()=>layoutEntityNeighborhood(sample,{width:200}),/dimensions/);});
