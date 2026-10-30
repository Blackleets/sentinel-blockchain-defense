const ADDRESS = /^0x[0-9a-f]{40}$/i;

function normalizeAddress(value) {
  return typeof value === "string" && ADDRESS.test(value) ? value.toLowerCase() : null;
}

function addNode(nodes, address, role, caseSubject) {
  const normalized = normalizeAddress(address);
  if (!normalized) return null;
  if (!nodes.has(normalized)) nodes.set(normalized, { id: normalized, address: normalized, roles: new Set(), cases: new Set() });
  const node = nodes.get(normalized);
  if (role) node.roles.add(role);
  if (caseSubject) node.cases.add(caseSubject);
  return normalized;
}

function observationFacts(report) {
  const facts = [];
  const subject = normalizeAddress(report?.subject);
  if (subject) facts.push({ address: subject, role: "subject", kind: "case-subject" });
  for (const observation of Array.isArray(report?.observations) ? report.observations : []) {
    if (!observation || typeof observation !== "object") continue;
    if (observation.kind === "eip7702" && observation.delegated === true) {
      facts.push({ address: observation.implementationAddress, role: "delegation-target", kind: "eip7702" });
    }
    if (observation.kind === "erc1967-slots") {
      for (const role of ["implementation", "admin", "beacon"]) {
        if (observation[role]) facts.push({ address: observation[role], role: "proxy-" + role, kind: "erc1967-slots" });
      }
    }
    if (observation.kind === "beacon-implementation" && observation.address) {
      facts.push({ address: observation.address, role: "beacon-implementation", kind: "beacon-implementation" });
    }
    if (observation.kind === "effective-implementation" && observation.address) {
      facts.push({ address: observation.address, role: "effective-implementation", kind: "effective-implementation" });
    }
    if (observation.kind === "transaction" && observation.value && typeof observation.value === "object") {
      facts.push({ address: observation.value.from, role: "transaction-sender", kind: "transaction" });
      facts.push({ address: observation.value.to, role: "transaction-recipient", kind: "transaction" });
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
    for (const fact of facts) addNode(nodes, fact.address, fact.role, caseSubject);
    factsByCase.push({ caseSubject, facts });
  });

  const edges = new Map();
  const addEdge = (type, left, right, evidence) => {
    if (!left || !right || left === right) return;
    const [from, to] = type === "observed-transaction-flow" ? [left, right] : [left, right].sort();
    const key = [type, from, to].join("|");
    if (!edges.has(key)) edges.set(key, { id: key, type, from, to, evidence: [] });
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
          if (!groups.has(fact.address)) groups.set(fact.address, new Map());
          const group = groups.get(fact.address);
          if (!group.has(subject)) group.set(subject, new Set());
          group.get(subject).add(fact.kind);
        }
      }
    }
    for (const [sharedAddress, subjects] of groups) {
      const entries = [...subjects.entries()];
      for (let i = 0; i < entries.length; i++) for (let j = i + 1; j < entries.length; j++) {
        const [left, leftKinds] = entries[i], [right, rightKinds] = entries[j];
        addEdge(edgeType, left, right, {
          sharedAddress,
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
      addEdge("observed-transaction-flow", sender.address, recipient.address, {
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
    edges: [...edges.values()].sort((a, b) => a.type.localeCompare(b.type) || a.from.localeCompare(b.from) || a.to.localeCompare(b.to)),
    warnings,
    interpretation: {
      verdict: "not-assessed",
      note: "Edges represent exact address matches or observed transaction participants in supplied evidence. They do not establish common ownership, coordination, malicious intent, causation, or exploitability."
    }
  };
}
