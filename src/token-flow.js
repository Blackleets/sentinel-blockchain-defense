const ADDRESS = /^0x[0-9a-f]{40}$/i;

function normalizeAddress(value) {
  return typeof value === "string" && ADDRESS.test(value) ? value.toLowerCase() : null;
}

function compareHex(a, b) {
  const left = BigInt(a), right = BigInt(b);
  return left < right ? -1 : left > right ? 1 : 0;
}

export function buildTokenFlowGraph(transfers, options = {}) {
  if (!Array.isArray(transfers)) throw new TypeError("Token transfers must be an array");
  const { chainId = null, token = null, address = null, maxTransfers = 100 } = options;
  if (!Number.isInteger(maxTransfers) || maxTransfers < 1 || maxTransfers > 500) {
    throw new RangeError("maxTransfers must be an integer between 1 and 500");
  }
  const selectedAddress = address === null ? null : normalizeAddress(address);
  if (address !== null && !selectedAddress) throw new TypeError("Selected address must be a valid EVM address");
  const seen = new Set();
  const accepted = [];
  for (const item of transfers) {
    if (!item || typeof item !== "object") continue;
    const from = normalizeAddress(item.from), to = normalizeAddress(item.to), contract = normalizeAddress(item.token);
    if (!from || !to || !contract || typeof item.chainId !== "string" ||
        typeof item.transactionHash !== "string" || !/^0x[0-9a-f]{64}$/i.test(item.transactionHash) ||
        typeof item.blockNumber !== "string" || !/^0x[0-9a-f]+$/i.test(item.blockNumber) ||
        typeof item.logIndex !== "string" || !/^0x[0-9a-f]+$/i.test(item.logIndex) ||
        typeof item.amountRaw !== "string" || !/^\d+$/.test(item.amountRaw)) continue;
    if (chainId !== null && item.chainId.toLowerCase() !== String(chainId).toLowerCase()) continue;
    if (token !== null && contract !== normalizeAddress(token)) continue;
    if (selectedAddress && from !== selectedAddress && to !== selectedAddress) continue;
    const key = item.chainId.toLowerCase() + "|" + item.transactionHash.toLowerCase() + "|" + item.logIndex.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    accepted.push({ ...item, from, to, token: contract, transactionHash: item.transactionHash.toLowerCase() });
  }
  accepted.sort((a, b) => a.chainId.localeCompare(b.chainId) ||
    compareHex(a.blockNumber, b.blockNumber) ||
    compareHex(a.logIndex, b.logIndex) ||
    a.transactionHash.localeCompare(b.transactionHash));
  const totalMatched = accepted.length;
  const edges = accepted.slice(0, maxTransfers).map((item, index) => ({
    id: item.chainId + ":" + item.transactionHash + ":" + item.logIndex,
    index,
    chainId: item.chainId,
    token: item.token,
    from: item.from,
    to: item.to,
    amountRaw: item.amountRaw,
    blockNumber: item.blockNumber,
    transactionHash: item.transactionHash,
    logIndex: item.logIndex,
    caseSubject: item.caseSubject || null,
    interpretation: "observed-token-transfer-event"
  }));
  const nodeMap = new Map();
  for (const edge of edges) {
    for (const [addressValue, role] of [[edge.from, "sender"], [edge.to, "recipient"]]) {
      if (!nodeMap.has(addressValue)) nodeMap.set(addressValue, { address: addressValue, incomingTransferCount: 0, outgoingTransferCount: 0, counterparties: new Set() });
      const node = nodeMap.get(addressValue);
      if (role === "sender") node.outgoingTransferCount++;
      else node.incomingTransferCount++;
      node.counterparties.add(role === "sender" ? edge.to : edge.from);
    }
  }
  const nodes = [...nodeMap.values()].map(node => ({
    address: node.address,
    incomingTransferCount: node.incomingTransferCount,
    outgoingTransferCount: node.outgoingTransferCount,
    uniqueCounterpartyCount: node.counterparties.size
  })).sort((a, b) => (b.incomingTransferCount + b.outgoingTransferCount) - (a.incomingTransferCount + a.outgoingTransferCount) || a.address.localeCompare(b.address));
  return {
    schema: "sentinel.token-flow-graph.v1",
    coverage: "imported-receipt-logs-only",
    chainId: chainId === null ? null : String(chainId).toLowerCase(),
    token: token === null ? null : normalizeAddress(token),
    selectedAddress,
    totalMatchedTransferCount: totalMatched,
    includedTransferCount: edges.length,
    truncated: totalMatched > edges.length,
    nodeCount: nodes.length,
    edgeCount: edges.length,
    nodes,
    edges,
    limitations: [
      "Edges represent decoded Transfer-shaped receipt logs, not independently verified token legitimacy.",
      "The graph covers imported receipt evidence only and is not a complete historical token flow.",
      "A sequence of edges does not prove common ownership, control, intent, or off-chain identity."
    ]
  };
}
