const clone=value=>JSON.parse(JSON.stringify(value));
const validDigest=value=>typeof value==="string"&&/^[0-9a-f]{64}$/i.test(value);
const validDate=value=>typeof value==="string"&&!Number.isNaN(Date.parse(value));
export function createCaseVaultRecord(seal,{savedAt=new Date().toISOString()}={}){
 if(!seal||seal.schema!=="sentinel.evidence-integrity-seal.v1"||seal.algorithm!=="SHA-256"||seal.canonicalization!=="sorted-object-keys-v1"||!validDigest(seal.digest)||!seal.artifact||seal.artifact.schema!=="sentinel.investigation-intelligence.v1")throw new TypeError("A sealed SENTINEL investigation dossier is required");
 const dossier=seal.artifact;
 if(!dossier.subject||typeof dossier.subject.chainId!=="string"||typeof dossier.subject.address!=="string"||typeof dossier.caseId!=="string"||!validDate(dossier.generatedAt))throw new TypeError("Sealed dossier metadata is incomplete");
 if(!validDate(savedAt))throw new TypeError("savedAt must be a valid date string");
 const subject={chainId:dossier.subject.chainId.toLowerCase(),address:dossier.subject.address.toLowerCase()};
 const id=[subject.chainId,subject.address,dossier.caseId,dossier.generatedAt,seal.digest.toLowerCase()].join("|");
 return {schema:"sentinel.case-vault-record.v1",id,caseId:dossier.caseId,subject,generatedAt:dossier.generatedAt,savedAt,digest:seal.digest.toLowerCase(),envelope:clone(seal)};
}
/** Local-first archive orchestration; storage is injected to keep the core testable. */
export function createCaseVault({store,verifySeal,validateDossier,clock=()=>new Date().toISOString()}={}){
 if(!store||typeof store.add!=="function"||typeof store.get!=="function"||typeof store.getAll!=="function")throw new TypeError("A case vault storage adapter is required");
 if(typeof verifySeal!=="function"||typeof validateDossier!=="function")throw new TypeError("Seal verification and dossier validation functions are required");
 async function save(seal){
  if(!await verifySeal(seal))throw new Error("Dossier integrity verification failed; archive rejected.");
  const validation=validateDossier(seal.artifact);
  if(!validation?.valid)throw new Error("Dossier structure validation failed: "+(validation?.errors||["unknown validation error"]).join(" · "));
  const record=createCaseVaultRecord(seal,{savedAt:clock()});
  try{await store.add(record);return {saved:true,record:clone(record)};}
  catch(error){if(error?.name==="ConstraintError"||error?.code==="DUPLICATE")return {saved:false,reason:"already-archived",id:record.id};throw error;}
 }
 async function list({chainId,address,caseId}={}){
  const records=await store.getAll();
  return records.filter(record=>(!chainId||record.subject.chainId===chainId.toLowerCase())&&(!address||record.subject.address===address.toLowerCase())&&(!caseId||record.caseId===caseId))
   .sort((a,b)=>b.savedAt.localeCompare(a.savedAt)||b.id.localeCompare(a.id))
   .map(({envelope,...metadata})=>clone(metadata));
 }
 async function get(id){
  const record=await store.get(id);
  return record?clone(record):null;
 }
 async function exportBackup(){
  const records=await store.getAll();
  return {schema:"sentinel.case-vault-backup.v1",createdAt:clock(),recordCount:records.length,
   records:clone(records),limitations:[
    "This backup contains browser-local sealed dossier snapshots and their metadata.",
    "Each inner dossier seal must be verified independently; the outer backup seal protects the backup envelope as a whole.",
    "SHA-256 integrity does not authenticate authorship or establish evidence truth."
   ]};
 }
 async function importBackup(backupSeal){
  if(!await verifySeal(backupSeal))throw new Error("Case vault backup integrity verification failed; import rejected.");
  const backup=backupSeal.artifact;
  if(!backup||backup.schema!=="sentinel.case-vault-backup.v1"||!validDate(backup.createdAt)||!Array.isArray(backup.records)||backup.recordCount!==backup.records.length)throw new TypeError("Unsupported or malformed SENTINEL case vault backup.");
  const prepared=[];
  for(const item of backup.records){
   if(!item||item.schema!=="sentinel.case-vault-record.v1"||!item.envelope)throw new TypeError("Backup contains a malformed archive record.");
   if(!await verifySeal(item.envelope))throw new Error("An archived dossier failed its inner integrity check; import rejected.");
   const validation=validateDossier(item.envelope.artifact);
   if(!validation?.valid)throw new Error("An archived dossier failed structural validation: "+(validation?.errors||["unknown validation error"]).join(" · "));
   const normalized=createCaseVaultRecord(item.envelope,{savedAt:item.savedAt});
   if(normalized.id!==item.id||normalized.digest!==item.digest||normalized.caseId!==item.caseId||normalized.subject.chainId!==item.subject?.chainId||normalized.subject.address!==item.subject?.address)throw new Error("Archive record metadata does not match its sealed dossier.");
   prepared.push(normalized);
  }
  const summary={added:0,duplicates:0};
  for(const record of prepared){
   try{await store.add(record);summary.added++;}
   catch(error){if(error?.name==="ConstraintError"||error?.code==="DUPLICATE")summary.duplicates++;else throw error;}
  }
  return summary;
 }
 return {save,list,get,exportBackup,importBackup};
}
/** IndexedDB adapter. The archive remains on this browser and is never uploaded. */
export function createIndexedDbCaseVaultStore({indexedDB=globalThis.indexedDB,databaseName="sentinel-case-vault",storeName="snapshots"}={}){
 if(!indexedDB||typeof indexedDB.open!=="function")throw new Error("IndexedDB is unavailable in this browser.");
 let databasePromise;
 const open=()=>databasePromise||(databasePromise=new Promise((resolve,reject)=>{
  const request=indexedDB.open(databaseName,1);
  request.onupgradeneeded=()=>{const db=request.result;if(!db.objectStoreNames.contains(storeName))db.createObjectStore(storeName,{keyPath:"id"});};
  request.onsuccess=()=>resolve(request.result);
  request.onerror=()=>reject(request.error||new Error("Could not open the local case vault."));
  request.onblocked=()=>reject(new Error("The local case vault is blocked by another database connection."));
 }));
 const operation=(mode,run)=>open().then(db=>new Promise((resolve,reject)=>{
  const transaction=db.transaction(storeName,mode),store=transaction.objectStore(storeName);
  let result;
  try{result=run(store);}catch(error){reject(error);return;}
  transaction.oncomplete=()=>resolve(result?.result??result);
  transaction.onerror=()=>reject(transaction.error||new Error("Local case vault transaction failed."));
  transaction.onabort=()=>reject(transaction.error||new Error("Local case vault transaction was aborted."));
 }));
 return {
  add:record=>operation("readwrite",store=>store.add(record)),
  get:id=>operation("readonly",store=>store.get(id)),
  getAll:()=>operation("readonly",store=>store.getAll())
 };
}
