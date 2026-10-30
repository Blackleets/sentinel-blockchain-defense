import test from "node:test";
import assert from "node:assert/strict";
import {layoutEntityNeighborhood} from "../src/entity-layout.js";
const a="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",b="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",c="0xcccccccccccccccccccccccccccccccccccccccc";
const input={schema:"sentinel.entity-neighborhood.v1",nodes:[{address:a,distance:0,origin:true},{address:b,distance:1},{address:c,distance:2}],edges:[{from:a,to:b},{from:b,to:c}]};
test("lays out origin at center and neighbors in deterministic rings",()=>{const first=layoutEntityNeighborhood(input),second=layoutEntityNeighborhood(input);assert.deepEqual(first,second);assert.deepEqual(first.positions[a],{x:550,y:410,depth:0,degree:1,origin:true});assert.ok(first.positions[b].x!==550||first.positions[b].y!==410);assert.ok(first.positions[c].x!==550||first.positions[c].y!==410);});
test("rejects malformed graph layouts",()=>assert.throws(()=>layoutEntityNeighborhood(null),/neighborhood/));
