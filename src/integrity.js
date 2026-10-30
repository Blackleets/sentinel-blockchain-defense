function canonicalJson(value,seen=new Set()){
 if(value===null)return "null";
 if(typeof value==="string"||typeof value==="boolean")return JSON.stringify(value);
 if(typeof value==="number"){if(!Number.isFinite(value))throw new TypeError("Integrity payload contains a non-finite number");return JSON.stringify(value);}
 if(typeof value!=="object")throw new TypeError("Integrity payload must contain JSON-compatible values only");
 if(seen.has(value))throw new TypeError("Integrity payload must not contain circular references");
 seen.add(value);
 let output;
 if(Array.isArray(value))output="["+value.map(item=>canonicalJson(item,seen)).join(",")+"]";
 else{
  const prototype=Object.getPrototypeOf(value);
  if(prototype!==Object.prototype&&prototype!==null)throw new TypeError("Integrity payload must contain plain JSON objects");
  const keys=Object.keys(value).sort();
  output="{"+keys.map(key=>JSON.stringify(key)+":"+canonicalJson(value[key],seen)).join(",")+"}";
 }
 seen.delete(value);
 return output;
}
const hex=bytes=>[...new Uint8Array(bytes)].map(value=>value.toString(16).padStart(2,"0")).join("");
async function digest(payload,subtle){
 if(!subtle||typeof subtle.digest!=="function")throw new Error("SHA-256 integrity requires Web Crypto in a secure browser context");
 const bytes=new TextEncoder().encode(canonicalJson(payload));
 return hex(await subtle.digest("SHA-256",bytes));
}
export async function createIntegrityEnvelope(payload,{subtle=globalThis.crypto?.subtle}={}){
 if(!payload||typeof payload!=="object"||Array.isArray(payload))throw new TypeError("An object payload is required");
 return {schema:"sentinel.integrity-envelope.v1",algorithm:"SHA-256",canonicalization:"sentinel-json-c14n.v1",digest:await digest(payload,subtle),payload};
}
export async function verifyIntegrityEnvelope(envelope,{subtle=globalThis.crypto?.subtle}={}){
 if(!envelope||envelope.schema!=="sentinel.integrity-envelope.v1"||envelope.algorithm!=="SHA-256"||envelope.canonicalization!=="sentinel-json-c14n.v1"||typeof envelope.digest!=="string"||!envelope.payload||typeof envelope.payload!=="object")throw new TypeError("Unsupported or malformed SENTINEL integrity envelope");
 const actual=await digest(envelope.payload,subtle);
 return {valid:actual===envelope.digest,algorithm:envelope.algorithm,expectedDigest:envelope.digest,actualDigest:actual};
}
