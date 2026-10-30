const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;

function addressOf(value) {
  return typeof value === "string" && ADDRESS.test(value) ? value.toLowerCase() : null;
}
function hashOf(value) {
  return typeof value === "string" && HASH.test(value) ? value.toLowerCase() : null;
}
function chainOf(report) {
  const value = report?.chainId ?? report?.network?.chainId;
  return typeof value === "string" && /^0x[0-9a-f]+$/i.test(value) ? value.toLowerCase() : "unknown";
}
function blockOf(value) {
  if (typeof value === "bigint" && value >= 0n) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value !== "string" || !/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value)) return null;
  try { return BigInt(value); } catch { return null; }
}
function blockHex(value) {
  const block = blockOf(value);
  return block === null ? null : "0x" + block.toString(16);
}
function unique(values) {
  return [...new Set(values.filter(Boolean))].sort();
}

/**
 * Build an address-centric investigation from imported reports and their derived evidence.
 * All relationships remain chain-scoped and explicitly observational.
 */
export function buildAddressInvestigation({ reports, graph, threatIntelligence, chainId, address, maxTransactions = 100 }) {
  if (!Array.isArray(reports)) throw new TypeError("Reports must be an array");
  if (!graph || graph.schema !== "sentinel.correlation-graph.v1") throw new TypeError("A SENTINEL correlation graph is required");
  if (!threatIntelligence || threatIntelligence.schema !== "sentinel.threat-intelligence.v1") throw new TypeError("SENTINEL threat intelligence is required");
  const selectedAddress = addressOf(address);
  if (!selectedAddress) throw new TypeError("A valid EVM address is required");
  const selectedChain = typeof chainId === "string" && chainId ? chainId.toLowerCase() : "unknown";
  if (!Number.isInteger(maxTransactions) || maxTransactions < 1 || maxTransactions > 500) throw new RangeError("maxTransactions must be an integer between 1 and 500");

  const transactionMap = new Map();
  const caseSubjects = new Set();
  const sourceKinds = new Set();
  const relatedAddresses = new Set();
  const roles = new Set();
  let firstSeen = null, lastSeen = null;
  const addBlock = value => {
    const block = blockOf(value);
    if (block === null) return;
    if (firstSeen === null || block < firstSeen) firstSeen = block;
    if (lastSeen === null || block > lastSeen) lastSeen = block;
  };

  for (const report of reports) {
    if (!report || report.schema !== "sentinel.case-report.v1" || !Array.isArray(report.observations) || chainOf(report) !== selectedChain) continue;
    const subject = typeof report.subject === "string" ? report.subject.toLowerCase() : null;
    let reportRelated = addressOf(report.subject) === selectedAddress;
    for (const observation of report.observations) {
      if (!observation || typeof observation !== "object") continue;
      if (observation.kind === "transaction" && observation.value && typeof observation.value === "object") {
        const tx = observation.value;
        const from = addressOf(tx.from), to = addressOf(tx.to);
        if (from === selectedAddress || to === selectedAddress) {
          reportRelated = true;
          const hash = hashOf(tx.hash) || (report.subjectType === "transaction" ? hashOf(report.subject) : null);
          const blockNumber = blockHex(tx.blockNumber ?? report.provenance?.blockNumber);
          if (from) relatedAddresses.add(from);
          if (to) relatedAddresses.add(to);
          if (hash) {
            const key = selectedChain + "|" + hash;
            if (!transactionMap.has(key)) transactionMap.set(key, {
              chainId: selectedChain, hash, blockNumber,
              transactionIndex: blockHex(tx.transactionIndex),
              from, to, caseSubjects: new Set(), evidenceSources: new Set()
            });
            const item = transactionMap.get(key);
            if (subject) item.caseSubjects.add(subject);
            item.evidenceSources.add("case-report.transaction");
            if (item.blockNumber === null && blockNumber !== null) item.blockNumber = blockNumber;
          }
          addBlock(blockNumber);
          sourceKinds.add("transaction");
        }
      }
      if (observation.kind === "erc1967-slots") {
        const matches = ["implementation", "admin", "beacon"].filter(role => addressOf(observation[role]) === selectedAddress);
        for (const role of matches) { roles.add("proxy-" + role); sourceKinds.add("erc1967-slots"); }
        if (matches.length) reportRelated = true;
      }
      if (observation.kind === "eip7702" && observation.delegated === true && addressOf(observation.implementationAddress) === selectedAddress) {
        roles.add("delegation-target"); sourceKinds.add("eip7702"); reportRelated = true;
      }
      if (observation.kind === "effective-implementation" && addressOf(observation.address) === selectedAddress) {
        roles.add("effective-implementation"); sourceKinds.add("effective-implementation"); reportRelated = true;
      }
      if (observation.kind === "beacon-implementation" && addressOf(observation.address) === selectedAddress) {
        roles.add("beacon-implementation"); sourceKinds.add("beacon-implementation"); reportRelated = true;
      }
      if (observation.kind === "erc1967-events") {
        for (const event of Array.isArray(observation.events) ? observation.events : []) {
          if (addressOf(event?.address) === selectedAddress || addressOf(event?.changes?.implementation) === selectedAddress ||
              addressOf(event?.changes?.beacon) === selectedAddress || addressOf(event?.changes?.newAdmin) === selectedAddress ||
              addressOf(event?.changes?.previousAdmin) === selectedAddress) {
            roles.add("proxy-event-participant"); sourceKinds.add("erc1967-events"); reportRelated = true;
            addBlock(event.blockNumber);
          }
        }
      }
    }
    if (reportRelated && subject) caseSubjects.add(subject);
  }

  const transactions = [...transactionMap.values()].map(item => ({
    chainId: item.chainId, hash: item.hash, blockNumber: item.blockNumber,
    transactionIndex: item.transactionIndex, from: item.from, to: item.to,
    caseSubjects: [...item.caseSubjects].sort(), evidenceSources: [...item.evidenceSources].sort()
  })).sort((a, b) => {
    const left = blockOf(a.blockNumber), right = blockOf(b.blockNumber);
    if (left !== null && right !== null && left !== right) return left < right ? -1 : 1;
    if (left === null && right !== null) return 1;
    if (right === null && left !== null) return -1;
    return a.hash.localeCompare(b.hash);
  });

  const tokenTransfers = (threatIntelligence.tokenTransfers || []).filter(item =>
    item.chainId === selectedChain && (item.from === selectedAddress || item.to === selectedAddress)
  ).map(item => {
    relatedAddresses.add(item.from); relatedAddresses.add(item.to);
    if (item.caseSubject) caseSubjects.add(item.caseSubject.toLowerCase());
    addBlock(item.blockNumber);
    return { ...item, direction: item.from === selectedAddress && item.to === selectedAddress ? "self" : item.from === selectedAddress ? "outgoing" : "incoming" };
  }).sort((a, b) => {
    const left = blockOf(a.blockNumber), right = blockOf(b.blockNumber);
    if (left !== null && right !== null && left !== right) return left < right ? -1 : 1;
    return (a.logIndex || "").localeCompare(b.logIndex || "");
  });

  const transactionLinks = (threatIntelligence.transactionLinks || []).filter(link =>
    link.chainId === selectedChain && [link.from, link.via, link.to].includes(selectedAddress)
  );
  for (const link of transactionLinks) {
    relatedAddresses.add(link.from); relatedAddresses.add(link.via); relatedAddresses.add(link.to);
  }

  const correlationNode = (graph.nodes || []).find(node => node.chainId === selectedChain && node.address === selectedAddress) || null;
  if (correlationNode) {
    for (const role of correlationNode.roles || []) roles.add(role);
    for (const subject of correlationNode.cases || []) caseSubjects.add(subject);
  }
  const correlationEdges = (graph.edges || []).filter(edge => edge.chainId === selectedChain &&
    (edge.from === selectedAddress || edge.to === selectedAddress || edge.evidence?.some(item => item.sharedAddress === selectedAddress)));
  for (const edge of correlationEdges) {
    relatedAddresses.add(edge.from); relatedAddresses.add(edge.to);
    for (const subject of edge.evidence?.flatMap(item => item.caseSubjects || []) || []) caseSubjects.add(subject);
  }

  const threatSignals = (threatIntelligence.signals || []).filter(signal => signal.chainId === selectedChain &&
    (signal.entities || []).includes(selectedAddress) || signal.chainId === selectedChain && (signal.evidence || []).some(item =>
      item.address === selectedAddress || item.from === selectedAddress || item.to === selectedAddress ||
      item.implementation === selectedAddress
    ));
  const addressProfile = (threatIntelligence.addressProfiles || []).find(profile => profile.chainId === selectedChain && profile.address === selectedAddress) || null;
  const tokenProfiles = (threatIntelligence.tokenAddressProfiles || []).filter(profile => profile.chainId === selectedChain && profile.address === selectedAddress);
  relatedAddresses.delete(selectedAddress);

  const includedTransactions = transactions.slice(0, maxTransactions);
  return {
    schema: "sentinel.address-investigation.v1",
    subject: { chainId: selectedChain, address: selectedAddress },
    coverage: "imported-case-reports-and-receipt-logs-only",
    summary: {
      relatedCaseCount: caseSubjects.size,
      observedTransactionCount: transactions.length,
      includedTransactionCount: includedTransactions.length,
      tokenTransferCount: tokenTransfers.length,
      transactionHandoffCount: transactionLinks.length,
      correlationEdgeCount: correlationEdges.length,
      threatSignalCount: threatSignals.length,
      uniqueObservedRelatedAddressCount: relatedAddresses.size,
      truncatedTransactions: transactions.length > includedTransactions.length,
      firstSeenBlock: firstSeen === null ? null : "0x" + firstSeen.toString(16),
      lastSeenBlock: lastSeen === null ? null : "0x" + lastSeen.toString(16)
    },
    roles: unique([...roles]),
    caseSubjects: unique([...caseSubjects]),
    relatedAddresses: unique([...relatedAddresses]),
    addressProfile,
    tokenProfiles,
    transactions: includedTransactions,
    tokenTransfers,
    transactionLinks,
    correlationEdges,
    threatSignals,
    limitations: [
      "This investigation is limited to imported case reports and decoded receipt logs supplied to SENTINEL.",
      "Observed counterparties, graph edges and transaction handoffs do not prove common ownership, control, coordination or direct movement of the same funds.",
      "Transfer-shaped logs do not establish that a contract is a legitimate ERC-20 token; amounts remain raw base units without verified decimals.",
      "Missing transactions, blocks, logs or cases must not be interpreted as proof that no activity occurred.",
      "Threat signals are review prompts, not attribution, maliciousness findings, exploitability proof or a safety verdict."
    ],
    assessment: { verdict: "not-assessed", riskScore: null }
  };
}

export function listInvestigableAddresses({ graph, threatIntelligence }) {
  const entries = new Map();
  for (const node of graph?.nodes || []) entries.set(node.chainId + "|" + node.address, { chainId: node.chainId, address: node.address, roles: [...(node.roles || [])] });
  for (const edge of graph?.edges || []) {
    for (const address of [edge.from, edge.to]) {
      if (!addressOf(address)) continue;
      const key = edge.chainId + "|" + address.toLowerCase();
      if (!entries.has(key)) entries.set(key, { chainId: edge.chainId, address: address.toLowerCase(), roles: ["correlation-edge-endpoint"] });
    }
  }
  for (const profile of threatIntelligence?.addressProfiles || []) {
    const key = profile.chainId + "|" + profile.address;
    const item = entries.get(key) || { chainId: profile.chainId, address: profile.address, roles: [] };
    item.transactionCount = profile.observedTransactionCount;
    entries.set(key, item);
  }
  for (const profile of threatIntelligence?.tokenAddressProfiles || []) {
    const key = profile.chainId + "|" + profile.address;
    const item = entries.get(key) || { chainId: profile.chainId, address: profile.address, roles: [] };
    item.tokenTransferCount = (item.tokenTransferCount || 0) + profile.incomingTransferCount + profile.outgoingTransferCount;
    entries.set(key, item);
  }
  return [...entries.values()].sort((a, b) => a.chainId.localeCompare(b.chainId) || a.address.localeCompare(b.address));
}
