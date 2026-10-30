const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;

function normalizeAddress(value) {
  return typeof value === "string" && ADDRESS.test(value) ? value.toLowerCase() : null;
}

function normalizeHash(value) {
  return typeof value === "string" && HASH.test(value) ? value.toLowerCase() : null;
}

function parseBlock(value) {
  if (typeof value === "bigint" && value >= 0n) return value;
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) return BigInt(value);
  if (typeof value !== "string" || !/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(value)) return null;
  try { return BigInt(value); } catch { return null; }
}

function blockHex(value) {
  const block = parseBlock(value);
  return block === null ? null : "0x" + block.toString(16);
}

function timestampIso(value) {
  if (typeof value !== "string" || !/^0x[0-9a-f]+$/i.test(value)) return null;
  const seconds = Number(BigInt(value));
  if (!Number.isSafeInteger(seconds) || seconds < 0) return null;
  const date = new Date(seconds * 1000);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function validReport(report) {
  return report && report.schema === "sentinel.case-report.v1" &&
    typeof report.subject === "string" && Array.isArray(report.observations);
}

/**
 * Build a deterministic, bounded timeline from imported case reports.
 * Only explicit transaction, ERC-1967 event and decoded Transfer-log evidence is included.
 */
export function buildEvidenceTimeline(reports, options = {}) {
  if (!Array.isArray(reports)) throw new TypeError("Reports must be an array");
  const {
    tokenTransfers = [],
    chainId = null,
    address = null,
    fromBlock = null,
    toBlock = null,
    maxEvents = 500
  } = options;
  if (!Array.isArray(tokenTransfers)) throw new TypeError("Token transfers must be an array");
  if (!Number.isInteger(maxEvents) || maxEvents < 1 || maxEvents > 1000) {
    throw new RangeError("maxEvents must be an integer between 1 and 1000");
  }
  const selectedAddress = address === null || address === "" ? null : normalizeAddress(address);
  if (address !== null && address !== "" && !selectedAddress) throw new TypeError("Selected address must be a valid EVM address");
  const lowerBlock = fromBlock === null || fromBlock === "" ? null : parseBlock(fromBlock);
  const upperBlock = toBlock === null || toBlock === "" ? null : parseBlock(toBlock);
  if (fromBlock !== null && fromBlock !== "" && lowerBlock === null) throw new TypeError("fromBlock must be a decimal or hexadecimal block number");
  if (toBlock !== null && toBlock !== "" && upperBlock === null) throw new TypeError("toBlock must be a decimal or hexadecimal block number");
  if (lowerBlock !== null && upperBlock !== null && lowerBlock > upperBlock) throw new RangeError("fromBlock must not exceed toBlock");

  const candidates = [];
  const timestampByTransaction = new Map();
  for (const report of reports.filter(validReport)) {
    const rawChain = report.chainId ?? report.network?.chainId ?? "unknown";
    const currentChain = typeof rawChain === "string" ? rawChain.toLowerCase() : String(rawChain);
    const subject = report.subject.toLowerCase();
    for (const observation of report.observations) {
      if (!observation || typeof observation !== "object") continue;
      if (observation.kind === "blockTimestamp" && typeof observation.value === "string") {
        const txObservation = report.observations.find(item => item?.kind === "transaction" && item.value);
        const hash = normalizeHash(txObservation?.value?.hash);
        if (hash) timestampByTransaction.set(currentChain + "|" + hash, timestampIso(observation.value));
      }
    }
  }

  for (const report of reports.filter(validReport)) {
    const rawChain = report.chainId ?? report.network?.chainId ?? "unknown";
    const currentChain = typeof rawChain === "string" ? rawChain.toLowerCase() : String(rawChain);
    const subject = report.subject.toLowerCase();
    for (const observation of report.observations) {
      if (!observation || typeof observation !== "object") continue;
      if (observation.kind === "transaction" && observation.value && typeof observation.value === "object") {
        const tx = observation.value;
        const hash = normalizeHash(tx.hash) || (report.subjectType === "transaction" ? normalizeHash(report.subject) : null);
        const blockNumber = blockHex(tx.blockNumber || report.provenance?.blockNumber);
        if (!hash && !blockNumber) continue;
        candidates.push({
          eventType: "transaction",
          chainId: currentChain,
          blockNumber,
          transactionIndex: blockHex(tx.transactionIndex),
          logIndex: null,
          timestamp: hash ? timestampByTransaction.get(currentChain + "|" + hash) || null : null,
          transactionHash: hash,
          address: null,
          from: normalizeAddress(tx.from),
          to: normalizeAddress(tx.to),
          contract: null,
          caseSubject: subject,
          evidence: { source: "case-report.transaction", subjectType: report.subjectType || null }
        });
      }
      if (observation.kind === "erc1967-events") {
        for (const event of Array.isArray(observation.events) ? observation.events : []) {
          if (!event || typeof event !== "object") continue;
          const blockNumber = blockHex(event.blockNumber);
          const hash = normalizeHash(event.transactionHash);
          if (!blockNumber && !hash) continue;
          candidates.push({
            eventType: "proxy-" + String(event.event || "unknown").toLowerCase(),
            chainId: currentChain,
            blockNumber,
            transactionIndex: blockHex(event.transactionIndex),
            logIndex: blockHex(event.logIndex),
            timestamp: hash ? timestampByTransaction.get(currentChain + "|" + hash) || null : null,
            transactionHash: hash,
            address: normalizeAddress(event.address),
            from: normalizeAddress(event.changes?.previousAdmin),
            to: normalizeAddress(event.changes?.newAdmin),
            contract: normalizeAddress(event.changes?.implementation || event.changes?.beacon),
            caseSubject: subject,
            evidence: { source: "case-report.erc1967-events", event: event.event || "unknown", changes: event.changes || {} }
          });
        }
      }
    }
  }

  for (const transfer of tokenTransfers) {
    if (!transfer || typeof transfer !== "object") continue;
    const currentChain = typeof transfer.chainId === "string" ? transfer.chainId.toLowerCase() : "unknown";
    const blockNumber = blockHex(transfer.blockNumber);
    const hash = normalizeHash(transfer.transactionHash);
    const logIndex = blockHex(transfer.logIndex);
    const from = normalizeAddress(transfer.from), to = normalizeAddress(transfer.to), token = normalizeAddress(transfer.token);
    if (!blockNumber || !hash || logIndex === null || !from || !to || !token) continue;
    candidates.push({
      eventType: "token-transfer",
      chainId: currentChain,
      blockNumber,
      transactionIndex: null,
      logIndex,
      timestamp: timestampByTransaction.get(currentChain + "|" + hash) || null,
      transactionHash: hash,
      address: null,
      from,
      to,
      contract: token,
      caseSubject: typeof transfer.caseSubject === "string" ? transfer.caseSubject.toLowerCase() : null,
      evidence: { source: "imported-receipt-log", amountRaw: typeof transfer.amountRaw === "string" ? transfer.amountRaw : null }
    });
  }

  const seen = new Set();
  const filtered = [];
  for (const event of candidates) {
    if (chainId !== null && event.chainId !== String(chainId).toLowerCase()) continue;
    if (selectedAddress && ![event.address, event.from, event.to, event.contract].includes(selectedAddress)) continue;
    const block = parseBlock(event.blockNumber);
    if (lowerBlock !== null && (block === null || block < lowerBlock)) continue;
    if (upperBlock !== null && (block === null || block > upperBlock)) continue;
    const key = [event.eventType, event.chainId, event.transactionHash || "", event.logIndex || "", event.address || "", event.caseSubject || ""].join("|");
    if (seen.has(key)) continue;
    seen.add(key);
    filtered.push(event);
  }

  filtered.sort((a, b) => {
    const chain = a.chainId.localeCompare(b.chainId);
    if (chain) return chain;
    const left = parseBlock(a.blockNumber), right = parseBlock(b.blockNumber);
    if (left === null && right !== null) return 1;
    if (right === null && left !== null) return -1;
    if (left !== null && right !== null && left !== right) return left < right ? -1 : 1;
    const txLeft = parseBlock(a.transactionIndex), txRight = parseBlock(b.transactionIndex);
    if (txLeft !== null && txRight !== null && txLeft !== txRight) return txLeft < txRight ? -1 : 1;
    const logLeft = parseBlock(a.logIndex), logRight = parseBlock(b.logIndex);
    if (logLeft !== null && logRight !== null && logLeft !== logRight) return logLeft < logRight ? -1 : 1;
    return a.eventType.localeCompare(b.eventType) || (a.transactionHash || "").localeCompare(b.transactionHash || "");
  });

  const events = filtered.slice(0, maxEvents);
  return {
    schema: "sentinel.evidence-timeline.v1",
    coverage: "imported-case-reports-and-receipt-logs-only",
    filters: { chainId: chainId === null ? null : String(chainId).toLowerCase(), address: selectedAddress, fromBlock: lowerBlock === null ? null : "0x" + lowerBlock.toString(16), toBlock: upperBlock === null ? null : "0x" + upperBlock.toString(16) },
    totalMatchedEventCount: filtered.length,
    includedEventCount: events.length,
    truncated: filtered.length > events.length,
    events,
    limitations: [
      "The timeline contains only events explicitly present in imported case reports and decoded receipt logs.",
      "Missing timestamps are left null; block and log ordering is not a wall-clock reconstruction.",
      "Repeated observations may describe the same on-chain event; deduplication uses event type, chain, transaction and log context.",
      "This timeline does not establish ownership, causation, intent, token continuity, maliciousness or a safety verdict."
    ]
  };
}
