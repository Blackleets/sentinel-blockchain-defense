const ADDRESS = /^0x[0-9a-f]{40}$/i;

function normalizeAddress(value) {
  return typeof value === "string" && ADDRESS.test(value) ? value.toLowerCase() : null;
}

function normalizeChainId(value) {
  return typeof value === "string" && /^0x[0-9a-f]+$/i.test(value) ? value.toLowerCase() : "unknown";
}

function addNode(nodes, chainId, address, role, caseSubject) {
  const normalized = normalizeAddress(address);
  if (!normalized) return null;
  const id = chainId + ":" + normalized;
  if (!nodes.has(id)) nodes.set(id, { id, chainId, address: normalized, roles: new Set(), cases: new Set() });
  const node = nodes.get(id);
  if (role) node.roles.add(role);
  if (caseSubject) node.cases.add(caseSubject);
  return id;
}

function observationFacts(report) {
  const facts = [];
  const chainId = normalizeChainId(report.chainId ?? report.network?.chainId);
  const subject = normalizeAddress(report.subject);
  if (subject) facts.push({ address: subject, role: "subject", kind: "case-subject", chainId });
  for (const observation of Array.isArray(report.observations) ? report.observations : []) {
    if (!observation || typeof observation !== "object") continue;
    if (observation.kind === "eip7702" && observation.delegated === true) {
      facts.push({ address: observation.implementationAddress, role: "delegation-target", kind: "eip7702", chainId });
    }
    if (observation.kind === "erc1967-slots") {
      for (const role of ["implementation", "admin", "beacon"]) {
        if (observation[role]) facts.push({ address: observation[role], role: "proxy-" + role, kind: "erc1967-slots", chainId });
      }
    }
    if (observation.kind === "beacon-implementation" && observation.address) {
      facts.push({ address: observation.address, role: "beacon-implementation", kind: "beacon-implementation", chainId });
    }
    if (observation.kind === "effective-implementation" && observation.address) {
      facts.push({ address: observation.address, role: "effective-implementation", kind: "effective-implementation", chainId });
    }
    if (observation.kind === "transaction" && observation.value && typeof observation.value === "object") {
      facts.push({ address: observation.value.from, role: "transaction-sender", kind: "transaction", chainId });
      facts.push({ address: observation.value.to, role: "transaction-recipient", kind: "transaction", chainId });
    }
  }
  return facts.filter(fact => normalizeAddress(fact.address)).map(fact => ({ ...fact, address: normalizeAddress(fact.address) }));
}

export function correlateCases(reports) {
  if (!Array.isArray(reports)) throw new TypeError("Reports must be an array");
  const nodes = new Map();
  const factsByCase = [];
  const warnings = [];

  reports.forEach((report, index) => {
    if (!report || typeof report !== "object" || !Array.isArray(report.observations)) {
      warnings.push({ index, reason: "invalid-or-incomplete-case-report" });
      return;
    }
    const caseSubject = normalizeAddress(report.subject) || "case-" + index;
    const facts = observationFacts(report);
    for (const fact of facts) addNode(nodes, fact.chainId, fact.address, fact.role, caseSubject);
    factsByCase.push({ caseSubject, facts });
  });

  const edges = new Map();
  const addEdge = (type, chainId, left, right, evidence) => {
    if (!left || !right || left === right) return;
    const [from, to] = type === "observed-transaction-flow" ? [left, right] : [left, right].sort();
    const key = [chainId, type, from, to].join("|");
    if (!edges.has(key)) edges.set(key, { id: key, type, chainId, from, to, evidence: [] });
    const edge = edges.get(key);
    if (!edge.evidence.some(item => item.caseSubjects.join("|") === evidence.caseSubjects.join("|") && item.observationKind === evidence.observationKind && item.role === evidence.role)) {
      edge.evidence.push(evidence);
    }
  };

  const sharedRoles = new Map([
    ["delegation-target", "shared-eip7702-delegation-target"],
    ["proxy-implementation", "shared-erc1967-implementation"],
    ["proxy-admin", "shared-erc1967-admin-slot"],
    ["proxy-beacon", "shared-erc1967-beacon"],
    ["beacon-implementation", "shared-beacon-implementation"],
    ["effective-implementation", "shared-effective-implementation"]
  ]);

  for (const [role, edgeType] of sharedRoles) {
    const groups = new Map();
    for (const item of factsByCase) {
      const subjects = [...new Set(item.facts.filter(f => f.role === "subject").map(f => f.address))];
      for (const fact of item.facts.filter(f => f.role === role)) {
        for (const subject of subjects) {
          const groupKey = fact.chainId + "|" + fact.address;
          if (!groups.has(groupKey)) groups.set(groupKey, { chainId: fact.chainId, address: fact.address, subjects: new Map() });
          const group = groups.get(groupKey);
          if (!group.subjects.has(subject)) group.subjects.set(subject, new Set());
          group.subjects.get(subject).add(fact.kind);
        }
      }
    }
    for (const group of groups.values()) {
      const entries = [...group.subjects.entries()];
      for (let i = 0; i < entries.length; i++) for (let j = i + 1; j < entries.length; j++) {
        const [left, leftKinds] = entries[i], [right, rightKinds] = entries[j];
        addEdge(edgeType, group.chainId, left, right, {
          sharedAddress: group.address,
          role,
          observationKind: [...new Set([...leftKinds, ...rightKinds])].sort().join(","),
          caseSubjects: [left, right].sort()
        });
      }
    }
  }

  for (const item of factsByCase) {
    const senders = item.facts.filter(f => f.role === "transaction-sender");
    const recipients = item.facts.filter(f => f.role === "transaction-recipient");
    for (const sender of senders) for (const recipient of recipients) {
      addEdge("observed-transaction-flow", sender.chainId, sender.address, recipient.address, {
        role: "transaction-participants",
        observationKind: "transaction",
        caseSubjects: [item.caseSubject]
      });
    }
  }

  return {
    schema: "sentinel.correlation-graph.v1",
    reportCount: factsByCase.length,
    nodeCount: nodes.size,
    edgeCount: edges.size,
    nodes: [...nodes.values()].map(node => ({ ...node, roles: [...node.roles].sort(), cases: [...node.cases].sort() })).sort((a, b) => a.id.localeCompare(b.id)),
    edges: [...edges.values()].sort((a, b) => a.chainId.localeCompare(b.chainId) || a.type.localeCompare(b.type) || a.from.localeCompare(b.from) || a.to.localeCompare(b.to)),
    warnings,
    interpretation: {
      verdict: "not-assessed",
      note: "Edges represent exact address matches within the same chain ID or observed transaction participants in supplied evidence. They do not establish common ownership, coordination, malicious intent, causation, or exploitability. Reports without a chain ID are isolated under unknown and are not cross-correlated with identified networks."
    }
  };
}
