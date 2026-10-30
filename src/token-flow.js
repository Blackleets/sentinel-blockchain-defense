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


export function findObservedTokenPaths(graph, options = {}) {
  if (!graph || graph.schema !== "sentinel.token-flow-graph.v1" || !Array.isArray(graph.edges)) {
    throw new TypeError("A SENTINEL token flow graph is required");
  }
  const { from, to, maxHops = 3, maxPaths = 20 } = options;
  const start = normalizeAddress(from), target = normalizeAddress(to);
  if (!start || !target) throw new TypeError("Both path endpoints must be valid EVM addresses");
  if (!Number.isInteger(maxHops) || maxHops < 1 || maxHops > 5) throw new RangeError("maxHops must be between 1 and 5");
  if (!Number.isInteger(maxPaths) || maxPaths < 1 || maxPaths > 50) throw new RangeError("maxPaths must be between 1 and 50");
  if (start === target) return { schema: "sentinel.observed-token-paths.v1", from: start, to: target, maxHops, pathCount: 0, truncated: false, paths: [], interpretation: "no-hop-path-requested" };
  const adjacency = new Map();
  for (const edge of graph.edges) {
    if (!edge || !normalizeAddress(edge.from) || !normalizeAddress(edge.to) || !normalizeAddress(edge.token)) continue;
    const key = edge.chainId + "|" + edge.token;
    if (!adjacency.has(key)) adjacency.set(key, new Map());
    const byAddress = adjacency.get(key);
    const source = normalizeAddress(edge.from);
    if (!byAddress.has(source)) byAddress.set(source, []);
    byAddress.get(source).push(edge);
  }
  for (const byAddress of adjacency.values()) for (const list of byAddress.values()) {
    list.sort((a,b) => compareHex(a.blockNumber,b.blockNumber) || compareHex(a.logIndex,b.logIndex) || a.transactionHash.localeCompare(b.transactionHash));
  }
  const results = [];
  let truncated = false;
  const keys = [...adjacency.keys()].sort();
  for (const key of keys) {
    const byAddress = adjacency.get(key);
    const visit = (current, visited, pathEdges) => {
      if (results.length > maxPaths) { truncated = true; return; }
      if (pathEdges.length >= maxHops) return;
      for (const edge of byAddress.get(current) || []) {
        const next = normalizeAddress(edge.to);
        if (visited.has(next)) continue;
        const nextEdges = [...pathEdges, edge];
        if (next === target) {
          results.push({
            chainId: edge.chainId,
            token: edge.token,
            hopCount: nextEdges.length,
            addresses: [start, ...nextEdges.map(item => item.to)],
            edges: nextEdges.map(item => ({
              transactionHash: item.transactionHash,
              logIndex: item.logIndex,
              blockNumber: item.blockNumber,
              from: item.from,
              to: item.to,
              amountRaw: item.amountRaw,
              caseSubject: item.caseSubject || null
            }))
          });
          if (results.length > maxPaths) { truncated = true; return; }
        } else {
          const nextVisited = new Set(visited);
          nextVisited.add(next);
          visit(next, nextVisited, nextEdges);
        }
      }
    };
    visit(start, new Set([start]), []);
    if (truncated) break;
  }
  results.sort((a,b) => a.hopCount-b.hopCount || a.chainId.localeCompare(b.chainId) || a.token.localeCompare(b.token) || a.edges.map(e=>e.transactionHash+e.logIndex).join("|").localeCompare(b.edges.map(e=>e.transactionHash+e.logIndex).join("|")));
  const boundedResults = results.slice(0, maxPaths);
  return {
    schema: "sentinel.observed-token-paths.v1",
    from: start,
    to: target,
    maxHops,
    pathCount: boundedResults.length,
    truncated,
    paths: boundedResults,
    interpretation: "observed-directed-event-sequences-only",
    limitation: "A path is a sequence of observed Transfer-shaped logs for one chain and token contract. It does not prove that funds were forwarded, that the same assets moved between events, or that addresses share an owner."
  };
}
