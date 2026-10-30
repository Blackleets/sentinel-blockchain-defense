import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { createIntegrityEnvelope, verifyIntegrityEnvelope } from "../src/integrity.js";

test("creates and verifies a stable SHA-256 envelope independent of object key order",async()=>{
 const first=await createIntegrityEnvelope({z:1,a:{y:true,x:"evidence"}},{subtle:webcrypto.subtle});
 const second=await createIntegrityEnvelope({a:{x:"evidence",y:true},z:1},{subtle:webcrypto.subtle});
 assert.equal(first.digest,second.digest);
 assert.deepEqual(await verifyIntegrityEnvelope(first,{subtle:webcrypto.subtle}),{valid:true,algorithm:"SHA-256",expectedDigest:first.digest,actualDigest:first.digest});
});
test("detects payload modification after export",async()=>{
 const envelope=await createIntegrityEnvelope({schema:"sentinel.case.v1",observations:[1,2,3]},{subtle:webcrypto.subtle});
 envelope.payload.observations.push(4);
 const result=await verifyIntegrityEnvelope(envelope,{subtle:webcrypto.subtle});
 assert.equal(result.valid,false);
 assert.notEqual(result.actualDigest,result.expectedDigest);
});
test("rejects non-JSON and malformed envelopes",async()=>{
 await assert.rejects(()=>createIntegrityEnvelope({bad:undefined},{subtle:webcrypto.subtle}),/JSON-compatible/);
 await assert.rejects(()=>createIntegrityEnvelope({bad:NaN},{subtle:webcrypto.subtle}),/non-finite/);
 await assert.rejects(()=>verifyIntegrityEnvelope({schema:"bad"},{subtle:webcrypto.subtle}),/malformed/);
});
