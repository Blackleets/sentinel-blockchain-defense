import test from "node:test";
import assert from "node:assert/strict";
import { layoutEntityNeighborhood } from "../src/entity-layout.js";

const a="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const b="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const c="0xcccccccccccccccccccccccccccccccccccccccc";
const sample={schema:"sentinel.entity-neighborhood.v1",subject:{address:a},nodes:[{address:a,distance:0,origin:true},{address:b,distance:1,origin:false},{address:c,distance:2,origin:false}],edges:[{from:a,to:b},{from:b,to:c}]};

test("relationship UI layout dependency places origin at center",()=>{
 const result=layoutEntityNeighborhood(sample);
 assert.deepEqual(result.positions[a],{x:550,y:410,depth:0,degree:1,origin:true});
 assert.equal(result.positions[b].depth,1);
 assert.equal(result.positions[c].depth,2);
});
test("relationship UI layout dependency stays within the graph canvas",()=>{
 const nodes=Array.from({length:100},(_,i)=>({address:"0x"+(i+1).toString(16).padStart(40,"0"),distance:i%3+1,origin:false}));
 nodes.push({address:a,distance:0,origin:true});
 const result=layoutEntityNeighborhood({...sample,nodes});
 for(const node of result.nodes){assert.ok(node.x>=0&&node.x<=result.width);assert.ok(node.y>=0&&node.y<=result.height);}
});
