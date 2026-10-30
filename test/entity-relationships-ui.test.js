import test from "node:test";
import assert from "node:assert/strict";
import { layoutEntityNeighborhood } from "../src/entity-relationships-ui.js";

const a="0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const b="0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const c="0xcccccccccccccccccccccccccccccccccccccccc";

test("lays out origin at center and neighbors in deterministic rings",()=>{
 const input={subject:{address:a},nodes:[{address:a,distance:0,origin:true},{address:b,distance:1},{address:c,distance:2}],edges:[{from:a,to:b},{from:b,to:c}]};
 const first=layoutEntityNeighborhood(input),second=layoutEntityNeighborhood(input);
 assert.deepEqual(first,second);
 assert.deepEqual(first.nodes[0].position,{x:500,y:340});
 assert.ok(first.nodes[1].position.x!==500||first.nodes[1].position.y!==340);
 assert.ok(first.edges.every(edge=>edge.path.startsWith("M ")));
});
test("rejects malformed graph layouts",()=>assert.throws(()=>layoutEntityNeighborhood(null),/neighborhood/));
