const isObject=value=>value!==null&&typeof value==="object"&&!Array.isArray(value);
function canonicalize(value,seen=new Set()){
 if(value===null)return "null";
 if(typeof value==="string"||typeof value==="boolean")return JSON.stringify(value);
 if(typeof value==="number"){if(!Number.isFinite(value))throw new TypeError("Evidence artifacts cannot contain non-finite numbers");return JSON.stringify(value);}
 if(Array.isArray(value)){if(seen.has(value))throw new TypeError("Evidence artifacts cannot contain circular references");seen.add(value);const output="["+value.map(item=>item===undefined?"null":canonicalize(item,seen)).join(",")+"]";seen.delete(value);return output;}
 if(isObject(value)){if(seen.has(value))throw new TypeError("Evidence artifacts cannot contain circular references");seen.add(value);const keys=Object.keys(value).filter(key=>value[key]!==undefined).sort();const output="{"+keys.map(key=>JSON.stringify(key)+":"+canonicalize(value[key],seen)).join(",")+"}";seen.delete(value);return output;}
 throw new TypeError("Evidence artifacts must contain only JSON-compatible values");
}
async function sha256(text){
 const subtle=globalThis.crypto?.subtle;
 if(!subtle)throw new Error("Web Crypto SHA-256 is unavailable in this environment");
 const bytes=new TextEncoder().encode(text),digest=await subtle.digest("SHA-256",bytes);
 return [...new Uint8Array(digest)].map(value=>value.toString(16).padStart(2,"0")).join("");
}
/** Create a portable SHA-256 integrity seal. This detects changes, not authorship. */
export async function sealEvidenceArtifact(artifact){
 if(!isObject(artifact))throw new TypeError("A JSON object evidence artifact is required");
 const canonical=canonicalize(artifact),digest=await sha256(canonical);
 return {schema:"sentinel.evidence-integrity-seal.v1",algorithm:"SHA-256",canonicalization:"sorted-object-keys-v1",digest,artifact};
}
/** Verify a seal after import; returns false for malformed or modified artifacts. */
export async function verifyEvidenceArtifactSeal(seal){
 if(!isObject(seal)||seal.schema!=="sentinel.evidence-integrity-seal.v1"||seal.algorithm!=="SHA-256"||seal.canonicalization!=="sorted-object-keys-v1"||typeof seal.digest!=="string"||!isObject(seal.artifact))return false;
 try{const expected=await sha256(canonicalize(seal.artifact));if(expected.length!==seal.digest.length)return false;let difference=0;for(let index=0;index<expected.length;index++)difference|=expected.charCodeAt(index)^seal.digest.charCodeAt(index);return difference===0;}catch{return false;}
}
