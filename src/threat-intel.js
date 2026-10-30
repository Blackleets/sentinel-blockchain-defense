const DEFAULT_RULES = Object.freeze({
  repeatedSenderMinCases: 2,
  repeatedRecipientMinCases: 2,
  sharedProxyMinCases: 2,
  upgradeBurstMinEvents: 2,
  upgradeWindowBlocks: 7200,
  transactionBurstMinEvents: 3,
  transactionBurstWindowBlocks: 7200
});

function chainIdOf(report) {
  const value = report?.chainId ?? report?.network?.chainId;
  return typeof value === "string" && /^0x[0-9a-f]+$/i.test(value) ? value.toLowerCase() : "unknown";
}

function addressOf(value) {
  return typeof value === "string" && /^0x[0-9a-f]{40}$/i.test(value) ? value.toLowerCase() : null;
}

function unique(values) {
  return [...new Set(values)];
}

function addGroupedSignal(signals, { id, rule, chainId, address, cases, evidence, detail }) {
  const distinctCases = unique(cases).sort();
  if (distinctCases.length < 2) return;
  signals.push({
    id: id + ":" + chainId + ":" + address,
    rule,
    chainId,
    severity: "review",
    confidence: "observed-pattern",
    title: detail.title,
    detail: detail.description,
    entities: [address],
    caseSubjects: distinctCases,
    evidence
  });
}

const ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

function indexedAddress(topic) {
  if (typeof topic !== "string" || !/^0x[0-9a-f]{64}$/i.test(topic) || !/^0{24}/i.test(topic.slice(2, 26))) return null;
  return addressOf("0x" + topic.slice(-40));
}

export function decodeErc20TransferLog(log) {
  if (!log || typeof log !== "object" || !Array.isArray(log.topics) || log.topics.length !== 3) return null;
  if (typeof log.topics[0] !== "string" || log.topics[0].toLowerCase() !== ERC20_TRANSFER_TOPIC) return null;
  const token = addressOf(log.address);
  const from = indexedAddress(log.topics[1]);
  const to = indexedAddress(log.topics[2]);
  if (!token || !from || !to || typeof log.data !== "string" || !/^0x[0-9a-f]{64}$/i.test(log.data)) return null;
  return { token, from, to, amountRaw: BigInt(log.data).toString() };
}

export function analyzeThreatIntelligence(reports, overrides = {}) {
  if (!Array.isArray(reports)) throw new TypeError("Reports must be an array");
  const rules = { ...DEFAULT_RULES, ...overrides };
  for (const key of Object.keys(DEFAULT_RULES)) {
    if (!Number.isInteger(rules[key]) || rules[key] < 1) throw new RangeError("Rule " + key + " must be a positive integer");
  }

  const validReports = reports.filter(report => report && report.schema === "sentinel.case-report.v1" && typeof report.subject === "string" && Array.isArray(report.observations));
  const signals = [];
  const timelines = [];
  const warnings = [];
  const grouped = new Map();
  const upgradesByChain = new Map();
  const senderActivity = new Map();
  const transactionObservations = [];\n  const tokenTransferCandidates = [];

  for (const report of validReports) {
    const chainId = chainIdOf(report);
    const subject = report.subject.toLowerCase();
    const caseKey = chainId + ":" + subject;
    for (const observation of report.observations) {
      if (!observation || typeof observation !== "object") continue;

      if (observation.kind === "transaction" && observation.value && typeof observation.value === "object") {
        for (const [role, rawAddress] of [["sender", observation.value.from], ["recipient", observation.value.to]]) {
          const address = addressOf(rawAddress);
          if (!address) continue;
          const key = chainId + "|" + role + "|" + address;
          if (!grouped.has(key)) grouped.set(key, { chainId, role, address, cases: new Set(), evidence: [] });
          const group = grouped.get(key);
          group.cases.add(caseKey);
          group.evidence.push({
            caseSubject: subject,
            transactionHash: observation.value.hash || null,
            blockNumber: observation.value.blockNumber || report.provenance?.blockNumber || null,
            address
          });
          if (role === "sender") {
            const rawBlock = observation.value.blockNumber || report.provenance?.blockNumber;
            const block = typeof rawBlock === "string" && /^0x[0-9a-f]+$/i.test(rawBlock) ? BigInt(rawBlock) : null;
            if (block === null) warnings.push({ caseSubject: subject, reason: "transaction-sender-event-missing-valid-block-number" });
            else {
              const activityKey = chainId + "|" + address;
              if (!senderActivity.has(activityKey)) senderActivity.set(activityKey, []);
              senderActivity.get(activityKey).push({ chainId, address, subject, blockNumber: block.toString(), transactionHash: observation.value.hash || null });
            }
          }
        }
        timelines.push({
          chainId,
          kind: "transaction",
          subject,
          blockNumber: observation.value.blockNumber || report.provenance?.blockNumber || null,
          transactionHash: observation.value.hash || null,
          from: addressOf(observation.value.from),
          to: addressOf(observation.value.to)
        });
        transactionObservations.push({
          chainId,
          subject,
          transactionHash: typeof observation.value.hash === "string" ? observation.value.hash.toLowerCase() : null,
          blockNumber: typeof observation.value.blockNumber === "string" && /^0x[0-9a-f]+$/i.test(observation.value.blockNumber) ? observation.value.blockNumber.toLowerCase() : null,
          transactionIndex: typeof observation.value.transactionIndex === "string" && /^0x[0-9a-f]+$/i.test(observation.value.transactionIndex) ? observation.value.transactionIndex.toLowerCase() : null,
          from: addressOf(observation.value.from),
          to: addressOf(observation.value.to)
        });
      }

      if (observation.kind === "receipt" && observation.value && Array.isArray(observation.value.logs)) {
        const receipt = observation.value;
        for (const log of receipt.logs) {
          const decoded = decodeErc20TransferLog(log);
          if (!decoded) continue;
          const blockNumber = log.blockNumber || receipt.blockNumber || report.provenance?.blockNumber || null;
          const txHash = log.transactionHash || receipt.transactionHash || (report.subjectType === "transaction" ? report.subject : null);
          tokenTransferCandidates.push({
            chainId, caseSubject: subject, transactionHash: typeof txHash === "string" ? txHash.toLowerCase() : null,
            blockNumber: typeof blockNumber === "string" && /^0x[0-9a-f]+$/i.test(blockNumber) ? blockNumber.toLowerCase() : null,
            logIndex: typeof log.logIndex === "string" && /^0x[0-9a-f]+$/i.test(log.logIndex) ? log.logIndex.toLowerCase() : null,
            ...decoded
          });
        }
      }

      if (observation.kind === "erc1967-slots") {
        for (const role of ["implementation", "admin", "beacon"]) {
          const address = addressOf(observation[role]);
          if (!address) continue;
          const key = chainId + "|proxy-" + role + "|" + address;
          if (!grouped.has(key)) grouped.set(key, { chainId, role: "proxy-" + role, address, cases: new Set(), evidence: [] });
          const group = grouped.get(key);
          group.cases.add(caseKey);
          group.evidence.push({ caseSubject: subject, slotRole: role, address });
        }
      }

      if (observation.kind === "erc1967-events") {
        for (const event of Array.isArray(observation.events) ? observation.events : []) {
          if (!event || event.event !== "Upgraded") continue;
          const block = typeof event.blockNumber === "string" && /^0x[0-9a-f]+$/i.test(event.blockNumber) ? BigInt(event.blockNumber) : null;
          if (block === null) {
            warnings.push({ caseSubject: subject, reason: "upgrade-event-missing-valid-block-number" });
            continue;
          }
          if (!upgradesByChain.has(chainId)) upgradesByChain.set(chainId, []);
          upgradesByChain.get(chainId).push({
            chainId,
            subject,
            blockNumber: block.toString(),
            transactionHash: event.transactionHash || null,
            implementation: addressOf(event.changes?.implementation)
          });
          timelines.push({
            chainId,
            kind: "proxy-upgrade",
            subject,
            blockNumber: block.toString(),
            transactionHash: event.transactionHash || null,
            implementation: addressOf(event.changes?.implementation)
          });
        }
      }
    }
  }

  for (const group of grouped.values()) {
    const cases = [...group.cases];
    if (group.role === "sender" && cases.length >= rules.repeatedSenderMinCases) {
      addGroupedSignal(signals, {
        id: "repeated-sender", rule: "repeated-sender", chainId: group.chainId, address: group.address,
        cases, evidence: group.evidence,
        detail: { title: "Sender appears across multiple cases", description: "The same sender address is present in transaction observations from distinct case reports on this chain. This is a recurrence pattern, not attribution." }
      });
    }
    if (group.role === "recipient" && cases.length >= rules.repeatedRecipientMinCases) {
      addGroupedSignal(signals, {
        id: "repeated-recipient", rule: "repeated-recipient", chainId: group.chainId, address: group.address,
        cases, evidence: group.evidence,
        detail: { title: "Recipient appears across multiple cases", description: "The same recipient address appears in transaction observations from distinct case reports on this chain. This alone does not establish control or intent." }
      });
    }
    if (group.role.startsWith("proxy-") && cases.length >= rules.sharedProxyMinCases) {
      addGroupedSignal(signals, {
        id: "shared-proxy-infrastructure", rule: "shared-proxy-infrastructure", chainId: group.chainId, address: group.address,
        cases, evidence: group.evidence,
        detail: { title: "Proxy infrastructure is reused across cases", description: "The same ERC-1967 slot address is referenced by distinct case reports on this chain. Shared infrastructure can be legitimate; review the role and context." }
      });
    }
  }

  for (const events of senderActivity.values()) {
    events.sort((a, b) => BigInt(a.blockNumber) < BigInt(b.blockNumber) ? -1 : BigInt(a.blockNumber) > BigInt(b.blockNumber) ? 1 : a.subject.localeCompare(b.subject));
    let start = 0;
    while (start < events.length) {
      const first = BigInt(events[start].blockNumber);
      let end = start;
      while (end < events.length && BigInt(events[end].blockNumber) - first <= BigInt(rules.transactionBurstWindowBlocks)) end++;
      const window = events.slice(start, end);
      const distinctSubjects = unique(window.map(event => event.subject));
      if (window.length >= rules.transactionBurstMinEvents && distinctSubjects.length >= 2) {
        const last = BigInt(window[window.length - 1].blockNumber);
        signals.push({
          id: "transaction-sender-burst:" + window[0].chainId + ":" + window[0].address + ":" + first.toString(),
          rule: "transaction-sender-burst",
          chainId: window[0].chainId,
          severity: "review",
          confidence: "observed-pattern",
          title: "Repeated sender activity in a bounded block window",
          detail: "The same sender appears in multiple imported transaction observations across distinct cases inside the configured block window. This is a temporal recurrence, not attribution or proof of coordination.",
          entities: [window[0].address],
          caseSubjects: distinctSubjects,
          window: { fromBlock: "0x" + first.toString(16), toBlock: "0x" + last.toString(16), maxBlocks: rules.transactionBurstWindowBlocks },
          evidence: window.map(event => ({ ...event, blockNumber: "0x" + BigInt(event.blockNumber).toString(16) }))
        });
        start = end;
      } else start++;
    }
  }

  for (const [chainId, events] of upgradesByChain) {
    events.sort((a, b) => BigInt(a.blockNumber) < BigInt(b.blockNumber) ? -1 : BigInt(a.blockNumber) > BigInt(b.blockNumber) ? 1 : a.subject.localeCompare(b.subject));
    let start = 0;
    while (start < events.length) {
      const first = BigInt(events[start].blockNumber);
      let end = start;
      while (end < events.length && BigInt(events[end].blockNumber) - first <= BigInt(rules.upgradeWindowBlocks)) end++;
      const window = events.slice(start, end);
      const distinctSubjects = unique(window.map(event => event.subject));
      if (window.length >= rules.upgradeBurstMinEvents && distinctSubjects.length >= 2) {
        const last = BigInt(window[window.length - 1].blockNumber);
        const evidence = window.map(event => ({ ...event, blockNumber: "0x" + BigInt(event.blockNumber).toString(16) }));
        signals.push({
          id: "upgrade-burst:" + chainId + ":" + first.toString() + ":" + last.toString(),
          rule: "upgrade-burst",
          chainId,
          severity: "review",
          confidence: "observed-pattern",
          title: "Multiple proxy upgrades in a bounded block window",
          detail: "Distinct case subjects have ERC-1967 Upgraded events within the configured block window. This temporal cluster merits review but does not establish a coordinated or malicious event.",
          entities: distinctSubjects,
          caseSubjects: distinctSubjects,
          window: { fromBlock: "0x" + first.toString(16), toBlock: "0x" + last.toString(16), maxBlocks: rules.upgradeWindowBlocks },
          evidence
        });
        start = end;
      } else {
        start++;
      }
    }
  }

  timelines.sort((a, b) => {
    if (a.chainId !== b.chainId) return a.chainId.localeCompare(b.chainId);
    if (a.blockNumber === null) return 1;
    if (b.blockNumber === null) return -1;
    const left = /^0x/i.test(a.blockNumber) ? BigInt(a.blockNumber) : BigInt(a.blockNumber);
    const right = /^0x/i.test(b.blockNumber) ? BigInt(b.blockNumber) : BigInt(b.blockNumber);
    return left < right ? -1 : left > right ? 1 : 0;
  });


  const deduplicatedTransactions = new Map();
  for (const tx of transactionObservations) {
    if (!tx.transactionHash || !tx.from || !tx.to || !tx.blockNumber) continue;
    const key = tx.chainId + "|" + tx.transactionHash;
    if (!deduplicatedTransactions.has(key)) deduplicatedTransactions.set(key, tx);
  }
  const profileMap = new Map();
  const ensureProfile = (chainId, address) => {
    const key = chainId + "|" + address;
    if (!profileMap.has(key)) profileMap.set(key, {
      chainId, address, outgoingCount: 0, incomingCount: 0,
      counterparties: new Set(), cases: new Set(), firstSeenBlock: null, lastSeenBlock: null, transactionHashes: []
    });
    return profileMap.get(key);
  };
  for (const tx of deduplicatedTransactions.values()) {
    const block = BigInt(tx.blockNumber);
    const sender = ensureProfile(tx.chainId, tx.from);
    const recipient = ensureProfile(tx.chainId, tx.to);
    sender.outgoingCount++;
    recipient.incomingCount++;
    sender.counterparties.add(tx.to);
    recipient.counterparties.add(tx.from);
    sender.cases.add(tx.subject);
    recipient.cases.add(tx.subject);
    for (const profile of [sender, recipient]) {
      if (profile.firstSeenBlock === null || block < BigInt(profile.firstSeenBlock)) profile.firstSeenBlock = "0x" + block.toString(16);
      if (profile.lastSeenBlock === null || block > BigInt(profile.lastSeenBlock)) profile.lastSeenBlock = "0x" + block.toString(16);
      if (profile.transactionHashes.length < 25 && !profile.transactionHashes.includes(tx.transactionHash)) profile.transactionHashes.push(tx.transactionHash);
    }
  }
  const transferMap = new Map();
  for (const transfer of tokenTransferCandidates) {
    if (!transfer.transactionHash || !transfer.logIndex || !transfer.blockNumber) continue;
    const key = transfer.chainId + "|" + transfer.transactionHash + "|" + transfer.logIndex;
    if (!transferMap.has(key)) transferMap.set(key, transfer);
  }
  const tokenTransfers = [...transferMap.values()].sort((a, b) =>
    a.chainId.localeCompare(b.chainId) ||
    (BigInt(a.blockNumber) < BigInt(b.blockNumber) ? -1 : BigInt(a.blockNumber) > BigInt(b.blockNumber) ? 1 : 0) ||
    (BigInt(a.logIndex) < BigInt(b.logIndex) ? -1 : BigInt(a.logIndex) > BigInt(b.logIndex) ? 1 : 0)
  );

  const addressProfiles = [...profileMap.values()].map(profile => ({
    chainId: profile.chainId,
    address: profile.address,
    outgoingTransactionCount: profile.outgoingCount,
    incomingTransactionCount: profile.incomingCount,
    observedTransactionCount: profile.outgoingCount + profile.incomingCount,
    uniqueObservedCounterpartyCount: profile.counterparties.size,
    observedCounterparties: [...profile.counterparties].sort(),
    distinctCaseCount: profile.cases.size,
    caseSubjects: [...profile.cases].sort(),
    firstSeenBlock: profile.firstSeenBlock,
    lastSeenBlock: profile.lastSeenBlock,
    transactionHashes: profile.transactionHashes,
    coverage: "imported-evidence-only"
  })).sort((a, b) => b.observedTransactionCount - a.observedTransactionCount || a.chainId.localeCompare(b.chainId) || a.address.localeCompare(b.address));

  const orderedTransactions = [...deduplicatedTransactions.values()].sort((a, b) => {
    if (a.chainId !== b.chainId) return a.chainId.localeCompare(b.chainId);
    const blockA = BigInt(a.blockNumber), blockB = BigInt(b.blockNumber);
    if (blockA !== blockB) return blockA < blockB ? -1 : 1;
    if (a.transactionIndex && b.transactionIndex) {
      const indexA = BigInt(a.transactionIndex), indexB = BigInt(b.transactionIndex);
      if (indexA !== indexB) return indexA < indexB ? -1 : 1;
    }
    return (a.transactionHash || "").localeCompare(b.transactionHash || "");
  });
  const transactionLinks = [];
  for (let i = 0; i < orderedTransactions.length; i++) {
    const first = orderedTransactions[i];
    for (let j = i + 1; j < orderedTransactions.length; j++) {
      const next = orderedTransactions[j];
      if (next.chainId !== first.chainId) {
        if (next.chainId > first.chainId) break;
        continue;
      }
      if (BigInt(next.blockNumber) - BigInt(first.blockNumber) > BigInt(rules.transactionBurstWindowBlocks)) break;
      if (first.to !== next.from) continue;
      transactionLinks.push({
        chainId: first.chainId,
        from: first.from,
        via: first.to,
        to: next.to,
        firstTransaction: { hash: first.transactionHash, blockNumber: first.blockNumber, caseSubject: first.subject },
        nextTransaction: { hash: next.transactionHash, blockNumber: next.blockNumber, caseSubject: next.subject },
        interpretation: "observed-transaction-handoff"
      });
    }
  }

  return {
    schema: "sentinel.threat-intelligence.v1",
    reportCount: validReports.length,
    rules,
    signalCount: signals.length,
    signals: signals.sort((a, b) => a.chainId.localeCompare(b.chainId) || a.rule.localeCompare(b.rule) || a.id.localeCompare(b.id)),
    timeline: timelines,
    transactionLinks,
    addressProfiles,
    warnings,
    assessment: {
      verdict: "not-assessed",
      riskScore: null,
      note: "Signals describe repeated or temporally clustered observations in supplied evidence. They are not threat attribution, proof of common ownership, malicious intent, exploitability, or a safety verdict."
    }
  };
}

export { DEFAULT_RULES as DEFAULT_THREAT_RULES };
