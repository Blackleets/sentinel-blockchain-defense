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

  return {
    schema: "sentinel.threat-intelligence.v1",
    reportCount: validReports.length,
    rules,
    signalCount: signals.length,
    signals: signals.sort((a, b) => a.chainId.localeCompare(b.chainId) || a.rule.localeCompare(b.rule) || a.id.localeCompare(b.id)),
    timeline: timelines,
    warnings,
    assessment: {
      verdict: "not-assessed",
      riskScore: null,
      note: "Signals describe repeated or temporally clustered observations in supplied evidence. They are not threat attribution, proof of common ownership, malicious intent, exploitability, or a safety verdict."
    }
  };
}

export { DEFAULT_RULES as DEFAULT_THREAT_RULES };
