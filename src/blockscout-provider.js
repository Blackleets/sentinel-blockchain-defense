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
    transactionHash: item.transaction_hash.toLowerCase(),
    blockNumber, logIndex, timestamp: typeof item.timestamp === "string" ? item.timestamp : null,
    tokenMetadata: {
      symbol: typeof item.token?.symbol === "string" ? item.token.symbol : null,
      name: typeof item.token?.name === "string" ? item.token.name : null,
      decimals: Number.isInteger(decimals) && decimals >= 0 && decimals <= 36 ? decimals : null
    },
    tokenType: "ERC-20"
  };
}

/**
 * Read paginated ERC-20 transfer history for one address from Blockscout.
 * The adapter is intentionally allowlisted to Ethereum Mainnet until each
 * additional chain endpoint has been validated independently.
 */
export async function fetchBlockscoutAddressTransfers({
  address, chainId, maxPages = 8, fetchImpl = globalThis.fetch
} = {}) {
  const normalized = normalizeAddress(address);
  const chain = typeof chainId === "string" ? chainId.toLowerCase() : "";
  if (!normalized) throw new TypeError("A valid EVM address is required");
  if (!BLOCKSCOUT_ENDPOINTS[chain]) throw new Error("No validated Blockscout history provider is configured for this chain");
  if (!Number.isInteger(maxPages) || maxPages < 1 || maxPages > 20) throw new RangeError("maxPages must be between 1 and 20");
  if (typeof fetchImpl !== "function") throw new TypeError("A fetch implementation is required");

  const base = BLOCKSCOUT_ENDPOINTS[chain];
  const all = new Map();
  const directionCoverage = {};
  let pagesFetched = 0, malformedItems = 0;
  for (const direction of ["from", "to"]) {
    let cursor = null, complete = false, pages = 0;
    while (pages < maxPages) {
      const url = new URL(base + "/addresses/" + normalized + "/token-transfers");
      url.searchParams.set("type", "ERC-20");
      url.searchParams.set("filter", direction);
      if (cursor && typeof cursor === "object") {
        for (const [key, value] of Object.entries(cursor)) {
          if (value !== null && value !== undefined && ["string","number","boolean"].includes(typeof value)) {
            url.searchParams.set(key, String(value));
          }
        }
      }
      const response = await fetchImpl(url.toString(), { headers: { accept: "application/json" } });
      if (!response || !response.ok) throw new Error("Blockscout " + direction + " history request failed" + (response?.status ? " (HTTP " + response.status + ")" : ""));
      const payload = await response.json();
      if (!payload || !Array.isArray(payload.items)) throw new Error("Blockscout returned an invalid transfer page");
      pages++; pagesFetched++;
      for (const item of payload.items) {
        const transfer = normalizeTransfer(item, chain);
        if (!transfer) { malformedItems++; continue; }
        all.set(transfer.transactionHash + "|" + transfer.logIndex, transfer);
      }
      cursor = payload.next_page_params && Object.keys(payload.next_page_params).length
        ? payload.next_page_params : null;
      if (!cursor) { complete = true; break; }
      if (payload.items.length === 0) { complete = true; cursor = null; break; }
    }
    directionCoverage[direction] = { pages, complete, hasMore: Boolean(cursor) };
  }
  const transfers = [...all.values()].sort((a,b) =>
    BigInt(a.blockNumber) < BigInt(b.blockNumber) ? -1 :
    BigInt(a.blockNumber) > BigInt(b.blockNumber) ? 1 :
    BigInt(a.logIndex) < BigInt(b.logIndex) ? -1 :
    BigInt(a.logIndex) > BigInt(b.logIndex) ? 1 : a.transactionHash.localeCompare(b.transactionHash));
  const blockNumbers = transfers.map(item => BigInt(item.blockNumber));
  return {
    schema: "sentinel.address-history.v1",
    provider: "Blockscout REST API v2",
    providerBase: base,
    chainId: chain,
    address: normalized,
    transfers,
    tokenMetadata: Object.fromEntries([...new Map(transfers.map(item => [item.token, item.tokenMetadata])).entries()]),
    pagesFetched,
    itemCount: transfers.length,
    malformedItems,
    complete: Object.values(directionCoverage).every(item => item.complete),
    truncated: Object.values(directionCoverage).some(item => item.hasMore),
    directionCoverage,
    blockRange: blockNumbers.length ? {
      from: blockNumbers.reduce((a,b)=>a<b?a:b).toString(),
      to: blockNumbers.reduce((a,b)=>a>b?a:b).toString()
    } : null,
    limitations: [
      "Coverage is limited to the provider's indexed ERC-20 transfer records for this address.",
      "Native transfers, internal calls, arbitrary event logs and cross-chain activity are not included.",
      "Provider indexing, availability, pagination and metadata are not independently guaranteed by SENTINEL.",
      "Address labels, token metadata and reputation fields are not used as ownership or risk verdicts."
    ]
  };
}
