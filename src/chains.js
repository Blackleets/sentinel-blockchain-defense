export const CHAINS = Object.freeze({
  ethereum: Object.freeze({ key: "ethereum", name: "Ethereum Mainnet", chainId: "0x1", chainIdDecimal: 1, rpc: "https://cloudflare-eth.com", explorer: "https://etherscan.io", nativeCurrency: "ETH" }),
  bnb: Object.freeze({ key: "bnb", name: "BNB Smart Chain", chainId: "0x38", chainIdDecimal: 56, rpc: "https://bsc-dataseed.binance.org", explorer: "https://bscscan.com", nativeCurrency: "BNB" }),
  polygon: Object.freeze({ key: "polygon", name: "Polygon PoS", chainId: "0x89", chainIdDecimal: 137, rpc: "https://polygon-rpc.com", explorer: "https://polygonscan.com", nativeCurrency: "POL" })
});

export function getChain(key) {
  return CHAINS[key] || null;
}

export function validateChainId(expectedChainId, actualChainId) {
  if (typeof expectedChainId !== "string" || typeof actualChainId !== "string" || !/^0x[0-9a-f]+$/i.test(expectedChainId) || !/^0x[0-9a-f]+$/i.test(actualChainId)) {
    return { ok: false, expected: expectedChainId ?? null, actual: actualChainId ?? null, reason: "invalid-chain-id" };
  }
  const expected = expectedChainId.toLowerCase();
  const actual = actualChainId.toLowerCase();
  return { ok: expected === actual, expected, actual, reason: expected === actual ? null : "chain-id-mismatch" };
}
