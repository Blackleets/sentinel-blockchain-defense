import test from "node:test";
import assert from "node:assert/strict";
import { sealEvidenceArtifact, verifyEvidenceArtifactSeal } from "../src/evidence-integrity.js";

test("creates and verifies a deterministic SHA-256 seal independent of object key order",async()=>{
 const first=await sealEvidenceArtifact({schema:"sentinel.test.v1",summary:{b:2,a:1},items:[{to:"0xbb",from:"0xaa"}]});
 const second=await sealEvidenceArtifact({items:[{from:"0xaa",to:"0xbb"}],summary:{a:1,b:2},schema:"sentinel.test.v1"});
 assert.equal(first.digest,second.digest);
 assert.equal(await verifyEvidenceArtifactSeal(first),true);
});
test("detects artifact modification and malformed seals",async()=>{
 const seal=await sealEvidenceArtifact({schema:"sentinel.test.v1",count:2});
 const altered={...seal,artifact:{...seal.artifact,count:3}};
 assert.equal(await verifyEvidenceArtifactSeal(altered),false);
 assert.equal(await verifyEvidenceArtifactSeal({...seal,digest:"bad"}),false);
 assert.equal(await verifyEvidenceArtifactSeal(null),false);
});
test("rejects non-JSON values and circular evidence",async()=>{
 await assert.rejects(()=>sealEvidenceArtifact({amount:Infinity}),/non-finite/);
 const circular={};circular.self=circular;
 await assert.rejects(()=>sealEvidenceArtifact(circular),/circular/);
});
