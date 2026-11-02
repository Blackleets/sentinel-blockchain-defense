const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;

function normalizeAddress(value) {
  return typeof value === "string" && ADDRESS.test(value) ? value.toLowerCase() : null;
}
function comparePosition(a, b) {
  const blockA = BigInt(a.blockNumber), blockB = BigInt(b.blockNumber);
  if (blockA !== blockB) return blockA < blockB ? -1 : 1;
  const indexA = BigInt(a.logIndex ?? "0x0"), indexB = BigInt(b.logIndex ?? "0x0");
  if (indexA !== indexB) return indexA < indexB ? -1 : 1;
  return String(a.transactionHash).localeCompare(String(b.transactionHash));
}
function normalizeRecord(record) {
  if (!record || typeof record !== "object") return null;
  const from = normalizeAddress(record.from), to = normalizeAddress(record.to);
  if (!from || !to || from === to || typeof record.chainId !== "string" ||
      typeof record.token !== "string" || !record.token ||
      typeof record.amountRaw !== "string" || !/^\d+$/.test(record.amountRaw) ||
      !record.amountRaw.length || !/^0x[0-9a-f]+$/i.test(record.blockNumber || "") ||
      !HASH.test(record.transactionHash || "") ||
      (record.logIndex != null && !/^0x[0-9a-f]+$/i.test(record.logIndex))) return null;
  if (record.amountRaw === "0" || record.transferType === "internal") return null;
  return { ...record, from, to, chainId: record.chainId.toLowerCase(),
    token: record.token.toLowerCase(), transactionHash: record.transactionHash.toLowerCase(),
    amount: BigInt(record.amountRaw) };
}

/**
 * Reconstructs bounded, amount-compatible candidate paths from observed value-flow edges.
 * It does not establish that the same units of an asset moved between hops.
 */
export function traceFundPaths(records, {
  source, target, chainId, assetKey = null, maxDepth = 3, maxPaths = 20,
  maxBlockGap = 100000
} = {}) {
  const origin = normalizeAddress(source), destination = normalizeAddress(target);
  if (!origin || !destination) throw new TypeError("Valid source and target EVM addresses are required");
  if (origin === destination) throw new RangeError("Source and target must be different addresses");
  if (!Array.isArray(records)) throw new TypeError("Value-flow records must be an array");
  if (typeof chainId !== "string" || !/^0x[0-9a-f]+$/i.test(chainId)) throw new TypeError("A valid hexadecimal chain ID is required");
  if (!Number.isInteger(maxDepth) || maxDepth < 1 || maxDepth > 3) throw new RangeError("maxDepth must be between 1 and 3");
  if (!Number.isInteger(maxPaths) || maxPaths < 1 || maxPaths > 20) throw new RangeError("maxPaths must be between 1 and 20");
  if (!Number.isSafeInteger(maxBlockGap) || maxBlockGap < 0) throw new RangeError("maxBlockGap must be a non-negative safe integer");

  const chain = chainId.toLowerCase();
  const normalized = records.map(normalizeRecord).filter(Boolean)
    .filter(edge => edge.chainId === chain && (!assetKey || edge.token === assetKey.toLowerCase()))
    .sort(comparePosition);
  const adjacency = new Map();
  for (const edge of normalized) {
    if (!adjacency.has(edge.from)) adjacency.set(edge.from, []);
    adjacency.get(edge.from).push(edge);
  }

  const paths = [], seenPaths = new Set();
  let exploredEdges = 0, capped = false;
  function visit(current, path, visited, previous) {
    if (paths.length >= maxPaths) { capped = true; return; }
    if (path.length >= maxDepth) return;
    for (const edge of adjacency.get(current) || []) {
      exploredEdges++;
      if (visited.has(edge.to)) continue;
      if (previous) {
        if (edge.token !== previous.token) continue;
        if (comparePosition(edge, previous) <= 0) continue;
        const gap = BigInt(edge.blockNumber) - BigInt(previous.blockNumber);
        if (gap > BigInt(maxBlockGap)) continue;
        if (edge.amount > previous.amount) continue;
      }
      const nextPath = [...path, edge];
      if (edge.to === destination) {
        const key = nextPath.map(item => item.transactionHash + ":" + item.logIndex).join("|");
        if (!seenPaths.has(key)) {
          seenPaths.add(key);
          const exact = nextPath.every((item, index) => index === 0 || item.amount === nextPath[index - 1].amount);
          paths.push({
            pathId: "candidate-" + (paths.length + 1),
            chainId: chain,
            assetKey: edge.token,
            source: origin,
            target: destination,
            hopCount: nextPath.length,
            amountCompatibility: exact ? "exact-amount-match" : "partial-amount-compatible",
            firstObservedAmountRaw: nextPath[0].amountRaw,
            finalObservedAmountRaw: edge.amountRaw,
            edges: nextPath.map(item => ({
              from: item.from, to: item.to, token: item.token, amountRaw: item.amountRaw,
              transactionHash: item.transactionHash, blockNumber: item.blockNumber,
              logIndex: item.logIndex ?? null, timestamp: item.timestamp ?? null,
              transferType: item.transferType ?? "ERC-20"
            }))
          });
        }
        if (paths.length >= maxPaths) { capped = true; return; }
      } else {
        const nextVisited = new Set(visited); nextVisited.add(edge.to);
        visit(edge.to, nextPath, nextVisited, edge);
      }
      if (paths.length >= maxPaths) { capped = true; return; }
    }
  }
  visit(origin, [], new Set([origin]), null);
  return {
    schema: "sentinel.fund-trace-candidates.v1",
    chainId: chain, source: origin, target: destination, assetKey: assetKey ? assetKey.toLowerCase() : null,
    maxDepth, maxPaths, pathCount: paths.length, exploredEdges, truncated: capped,
    paths,
    interpretation: {
      status: paths.length ? "candidate-paths-found" : "no-candidate-path-found",
      meaning: "Paths are directed, same-chain, same-asset, time-ordered observations with amount compatibility.",
      notProof: "Amount compatibility and address sequence do not prove that the same units moved between hops; balances may be pooled, replenished or commingled.",
      exclusions: ["Internal traces are excluded because they can coexist with parent transactions.",
        "Different tokens and chains are never joined.", "Cycles are rejected within each candidate path.",
        "Only supplied, bounded provider records are searched; missing records can hide paths."]
    }
  };
}
