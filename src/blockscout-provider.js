const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;
export const BLOCKSCOUT_ENDPOINTS = Object.freeze({
  "0x1": "https://eth.blockscout.com/api/v2"
});
function normalizeAddress(value) {
  return typeof value === "string" && ADDRESS.test(value) ? value.toLowerCase() : null;
}
function asHex(value) {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return "0x" + value.toString(16);
  if (typeof value === "string" && /^(0x[0-9a-f]+|\d+)$/i.test(value)) {
    try { return "0x" + BigInt(value).toString(16); } catch {}
  }
  return null;
}
function normalizeTransfer(item, chainId) {
  if (!item || item.token_type !== "ERC-20" || !HASH.test(item.transaction_hash || "")) return null;
  const from = normalizeAddress(item.from?.hash), to = normalizeAddress(item.to?.hash);
  const token = normalizeAddress(item.token?.address_hash || item.token?.address);
  const amount = item.total?.value;
  const blockNumber = asHex(item.block_number), logIndex = asHex(item.log_index);
  if (!from || !to || !token || typeof amount !== "string" || !/^\d+$/.test(amount) || !blockNumber || !logIndex) return null;
  const rawDecimals = item.total?.decimals ?? item.token?.decimals;
  const decimals = rawDecimals == null || !/^\d+$/.test(String(rawDecimals)) ? null : Number(rawDecimals);
  return {
    chainId, token, from, to, amountRaw: amount,
    transactionHash: item.transaction_hash.toLowerCase(), blockNumber, logIndex,
    timestamp: typeof item.timestamp === "string" ? item.timestamp : null,
    tokenMetadata: {
      symbol: typeof item.token?.symbol === "string" ? item.token.symbol : null,
      name: typeof item.token?.name === "string" ? item.token.name : null,
      decimals: Number.isInteger(decimals) && decimals >= 0 && decimals <= 36 ? decimals : null
    },
    tokenType: "ERC-20"
  };
}
function normalizeNativeTransaction(item, chainId) {
  if (!item || !HASH.test(item.hash || "")) return null;
  const from = normalizeAddress(item.from?.hash), to = normalizeAddress(item.to?.hash);
  const value = item.value;
  const blockNumber = asHex(item.block_number), position = asHex(item.position);
  if (!from || !to || typeof value !== "string" || !/^\d+$/.test(value) || value === "0" || !blockNumber || !position) return null;
  return {
    chainId, token: "NATIVE:ETH", from, to, amountRaw: value,
    transactionHash: item.hash.toLowerCase(), blockNumber, logIndex: position,
    timestamp: typeof item.timestamp === "string" ? item.timestamp : null,
    tokenMetadata: { symbol: "ETH", name: "Ether", decimals: 18 },
    transferType: "native",
    transactionStatus: typeof item.status === "string" ? item.status : null,
    method: typeof item.method === "string" ? item.method : null
  };
}
function normalizeInternalTransaction(item, chainId) {
  if (!item || !HASH.test(item.transaction_hash || "") || item.success !== true) return null;
  const from = normalizeAddress(item.from?.hash), to = normalizeAddress(item.to?.hash);
  const value = item.value, blockNumber = asHex(item.block_number), index = asHex(item.index);
  if (!from || !to || typeof value !== "string" || !/^\d+$/.test(value) || value === "0" || !blockNumber || !index) return null;
  return {
    chainId, token: "INTERNAL:ETH", from, to, amountRaw: value,
    transactionHash: item.transaction_hash.toLowerCase(), blockNumber,
    logIndex: "0x" + (BigInt(index) + 0x100000000n).toString(16),
    timestamp: typeof item.timestamp === "string" ? item.timestamp : null,
    tokenMetadata: { symbol: "ETH", name: "Ether (internal call)", decimals: 18 },
    transferType: "internal",
    internalIndex: index
  };
}
async function fetchPaged({base,address,endpoint,direction,maxPages,fetchImpl}) {
  const items = []; let cursor = null, complete = false, pages = 0;
  while (pages < maxPages) {
    const url = new URL(base + "/addresses/" + address + "/" + endpoint);
    if (direction) url.searchParams.set("filter", direction);
    if (cursor) for (const [key,value] of Object.entries(cursor)) {
      if (value !== null && value !== undefined && ["string","number","boolean"].includes(typeof value)) url.searchParams.set(key,String(value));
    }
    const response = await fetchImpl(url.toString(),{headers:{accept:"application/json"}});
    if (!response || !response.ok) throw new Error("Blockscout "+endpoint+" "+(direction||"all")+" request failed"+(response?.status?" (HTTP "+response.status+")":""));
    const payload = await response.json();
    if (!payload || !Array.isArray(payload.items)) throw new Error("Blockscout returned an invalid "+endpoint+" page");
    pages++; items.push(...payload.items);
    cursor = payload.next_page_params && Object.keys(payload.next_page_params).length ? payload.next_page_params : null;
    if (!cursor || payload.items.length===0) { complete=true; cursor=null; break; }
  }
  return {items,pages,complete,hasMore:Boolean(cursor)};
}
async function fetchDirections({base,address,endpoint,maxPages,fetchImpl}) {
  const [from,to] = await Promise.all(["from","to"].map(direction=>fetchPaged({base,address,endpoint,direction,maxPages,fetchImpl})));
  return {
    items:[...from.items,...to.items],
    pages:from.pages+to.pages,
    complete:from.complete&&to.complete,
    truncated:from.hasMore||to.hasMore,
    directionCoverage:{from:{pages:from.pages,complete:from.complete,hasMore:from.hasMore},to:{pages:to.pages,complete:to.complete,hasMore:to.hasMore}}
  };
}
export async function fetchBlockscoutAddressTransfers({address,chainId,maxPages=8,fetchImpl=globalThis.fetch}={}) {
  const normalized=normalizeAddress(address),chain=typeof chainId==="string"?chainId.toLowerCase():"";
  if(!normalized)throw new TypeError("A valid EVM address is required");
  if(!BLOCKSCOUT_ENDPOINTS[chain])throw new Error("No validated Blockscout history provider is configured for this chain");
  if(!Number.isInteger(maxPages)||maxPages<1||maxPages>20)throw new RangeError("maxPages must be between 1 and 20");
  if(typeof fetchImpl!=="function")throw new TypeError("A fetch implementation is required");
  const base=BLOCKSCOUT_ENDPOINTS[chain],result=await fetchDirections({base,address:normalized,endpoint:"token-transfers",maxPages,fetchImpl});
  const all=new Map();let malformedItems=0;
  for(const item of result.items){const transfer=normalizeTransfer(item,chain);if(!transfer){malformedItems++;continue;}all.set(transfer.transactionHash+"|"+transfer.logIndex,transfer);}
  const transfers=[...all.values()].sort((a,b)=>BigInt(a.blockNumber)<BigInt(b.blockNumber)?-1:BigInt(a.blockNumber)>BigInt(b.blockNumber)?1:BigInt(a.logIndex)<BigInt(b.logIndex)?-1:BigInt(a.logIndex)>BigInt(b.logIndex)?1:a.transactionHash.localeCompare(b.transactionHash));
  const blockNumbers=transfers.map(item=>BigInt(item.blockNumber));
  return {
    schema:"sentinel.address-history.v1",provider:"Blockscout REST API v2",providerBase:base,chainId:chain,address:normalized,transfers,
    tokenMetadata:Object.fromEntries([...new Map(transfers.map(item=>[item.token,item.tokenMetadata])).entries()]),
    pagesFetched:result.pages,itemCount:transfers.length,malformedItems,complete:result.complete,truncated:result.truncated,directionCoverage:result.directionCoverage,
    blockRange:blockNumbers.length?{from:blockNumbers.reduce((a,b)=>a<b?a:b).toString(),to:blockNumbers.reduce((a,b)=>a>b?a:b).toString()}:null,
    limitations:["Coverage is limited to the provider's indexed ERC-20 transfer records for this address.","Native transfers, internal calls, arbitrary event logs and cross-chain activity are not included.","Provider indexing, availability, pagination and metadata are not independently guaranteed by SENTINEL.","Address labels, token metadata and reputation fields are not used as ownership or risk verdicts."]
  };
}
export async function fetchBlockscoutAddressActivity({address,chainId,maxPages=4,fetchImpl=globalThis.fetch}={}) {
  const normalized=normalizeAddress(address),chain=typeof chainId==="string"?chainId.toLowerCase():"";
  if(!normalized)throw new TypeError("A valid EVM address is required");
  if(!BLOCKSCOUT_ENDPOINTS[chain])throw new Error("No validated Blockscout activity provider is configured for this chain");
  if(!Number.isInteger(maxPages)||maxPages<1||maxPages>12)throw new RangeError("maxPages must be between 1 and 12");
  if(typeof fetchImpl!=="function")throw new TypeError("A fetch implementation is required");
  const base=BLOCKSCOUT_ENDPOINTS[chain];
  const [transactions,internal]=await Promise.all([
    fetchDirections({base,address:normalized,endpoint:"transactions",maxPages,fetchImpl}),
    fetchDirections({base,address:normalized,endpoint:"internal-transactions",maxPages,fetchImpl})
  ]);
  const nativeTransfers=new Map(),internalTransfers=new Map();let malformedTransactions=0,malformedInternal=0;
  for(const item of transactions.items){const record=normalizeNativeTransaction(item,chain);if(!record){malformedTransactions++;continue;}nativeTransfers.set(record.transactionHash+"|"+record.logIndex,record);}
  for(const item of internal.items){const record=normalizeInternalTransaction(item,chain);if(!record){malformedInternal++;continue;}internalTransfers.set(record.transactionHash+"|"+record.logIndex,record);}
  const records=[...nativeTransfers.values(),...internalTransfers.values()].sort((a,b)=>BigInt(a.blockNumber)<BigInt(b.blockNumber)?-1:BigInt(a.blockNumber)>BigInt(b.blockNumber)?1:BigInt(a.logIndex)<BigInt(b.logIndex)?-1:BigInt(a.logIndex)>BigInt(b.logIndex)?1:a.transactionHash.localeCompare(b.transactionHash));
  return {
    schema:"sentinel.address-activity.v1",provider:"Blockscout REST API v2",providerBase:base,chainId:chain,address:normalized,records,
    counts:{nativeTransfers:nativeTransfers.size,internalTransfers:internalTransfers.size,malformedTransactions,malformedInternal},
    pagesFetched:transactions.pages+internal.pages,
    complete:transactions.complete&&internal.complete,
    truncated:transactions.truncated||internal.truncated,
    coverage:{transactions:transactions.directionCoverage,internalTransactions:internal.directionCoverage},
    limitations:["Only provider-indexed transaction and successful internal-transaction records are included.","Zero-value transactions are not represented as value-flow edges.","Internal call records are separate execution traces and can coexist with the parent transaction; do not sum them as independent wallet balance changes.","Failed or reverted internal calls are excluded from value-flow edges.","Provider pagination, indexing and metadata are not independently guaranteed by SENTINEL."]
  };
}
