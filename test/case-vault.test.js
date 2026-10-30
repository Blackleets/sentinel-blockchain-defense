import test from "node:test";
import assert from "node:assert/strict";
import {createCaseVault,createCaseVaultRecord} from "../src/case-vault.js";
const subject={chainId:"0x1",address:"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
const dossier={schema:"sentinel.investigation-intelligence.v1",caseId:"case-1",generatedAt:"2026-10-30T12:00:00.000Z",subject};
const seal={schema:"sentinel.evidence-integrity-seal.v1",algorithm:"SHA-256",canonicalization:"sorted-object-keys-v1",digest:"a".repeat(64),artifact:dossier};
function memoryStore(){
 const records=new Map();
 return {add:async record=>{if(records.has(record.id)){const error=new Error("duplicate");error.name="ConstraintError";throw error;}records.set(record.id,structuredClone(record));},
  get:async id=>records.get(id)||null,getAll:async()=>[...records.values()]};
}
const validate=value=>({valid:value?.schema==="sentinel.investigation-intelligence.v1",errors:["invalid"]});
test("creates stable subject-scoped archive metadata without changing the sealed artifact",()=>{
 const record=createCaseVaultRecord(seal,{savedAt:"2026-10-30T12:01:00.000Z"});
 assert.equal(record.schema,"sentinel.case-vault-record.v1");
 assert.equal(record.subject.chainId,"0x1");
 assert.equal(record.subject.address,subject.address);
 assert.equal(record.envelope.artifact.caseId,"case-1");
 assert.match(record.id,/case-1/);
});
test("archives only integrity-valid and structurally valid dossiers",async()=>{
 const store=memoryStore(),vault=createCaseVault({store,verifySeal:async value=>value===seal,validateDossier:validate,clock:()=>"2026-10-30T12:01:00.000Z"});
 const saved=await vault.save(seal);
 assert.equal(saved.saved,true);
 assert.equal((await vault.get(saved.record.id)).digest,"a".repeat(64));
 await assert.rejects(()=>vault.save({...seal,digest:"b".repeat(64)}),/integrity verification failed/);
 await assert.rejects(()=>vault.save({...seal,artifact:{schema:"wrong"}}),/integrity verification failed/);
});
test("prevents duplicate archive entries and filters/sorts metadata",async()=>{
 const store=memoryStore(),vault=createCaseVault({store,verifySeal:async()=>true,validateDossier:validate,clock:()=>"2026-10-30T12:01:00.000Z"});
 const first=await vault.save(seal),duplicate=await vault.save(seal);
 assert.equal(first.saved,true);
 assert.deepEqual(duplicate,{saved:false,reason:"already-archived",id:first.record.id});
 const list=await vault.list({chainId:"0x1",address:subject.address});
 assert.equal(list.length,1);
 assert.equal("envelope" in list[0],false);
 assert.equal((await vault.list({chainId:"0x89"})).length,0);
});
test("rejects malformed metadata and invalid adapter configuration",()=>{
 assert.throws(()=>createCaseVaultRecord({...seal,digest:"bad"}),/sealed SENTINEL/);
 assert.throws(()=>createCaseVault({}),/storage adapter/);
});
