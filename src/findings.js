const REVIEW_OPCODES = new Set(["DELEGATECALL", "CALLCODE", "SELFDESTRUCT"]);

function finding(id, category, severity, title, detail, evidence) {
  return { id, category, severity, title, detail, evidence };
}

export function analyzeCaseFindings(report) {
  if (!report || report.schema !== "sentinel.case-report.v1" || !Array.isArray(report.observations)) {
    throw new TypeError("Expected a SENTINEL case report");
  }
  const findings = [];
  const timeline = [];
  for (const observation of report.observations) {
    if (!observation || typeof observation !== "object") continue;
    if (observation.kind === "eip7702" && observation.delegated === true) {
      findings.push(finding("eip7702-delegation-present", "account-control", "review", "Delegated execution code is present", "The account contains an EIP-7702 delegation designation. Review the delegate target, authorization context and transaction history; this is not proof of compromise.", { implementationAddress: observation.implementationAddress || null }));
    }
    if (observation.kind === "erc1967-slots") {
      if (observation.implementation || observation.beacon) findings.push(finding("erc1967-proxy-metadata", "proxy-configuration", "info", "ERC-1967 proxy metadata detected", "Standard implementation or beacon metadata is populated. This describes configuration, not whether its upgrade path is safe or exploitable.", { implementation: observation.implementation || null, beacon: observation.beacon || null }));
      if (observation.admin) findings.push(finding("erc1967-admin-slot-populated", "privileged-control", "review", "ERC-1967 admin slot is populated", "A non-zero admin address is stored in the standard admin slot. The slot alone does not establish the effective authorization path or who controls it.", { admin: observation.admin }));
    }
    if (observation.kind === "beacon-implementation" && observation.status && observation.status !== "present" && observation.status !== "not-applicable") {
      findings.push(finding("beacon-resolution-incomplete", "data-completeness", "review", "Beacon implementation could not be resolved", "The beacon implementation lookup did not return a confirmed address. Treat proxy analysis as incomplete until independently resolved.", { status: observation.status, beaconImplementation: observation.address || null }));
    }
    if (observation.kind === "effective-implementation" && observation.address && observation.code === "0x") {
      findings.push(finding("implementation-code-empty", "implementation-integrity", "review", "Resolved implementation has no runtime code", "The observed effective implementation address returned empty runtime bytecode at inspection time. Verify the block context and resolution path.", { implementation: observation.address }));
    }
    if (observation.kind === "bytecode-analysis" && observation.analysis && Array.isArray(observation.analysis.evidence)) {
      for (const item of observation.analysis.evidence) if (REVIEW_OPCODES.has(item.capability)) findings.push(finding("bytecode-opcode-" + item.capability.toLowerCase(), "bytecode-capability", "review", item.capability + " capability present in bytecode", item.explanation, { opcode: item.capability, count: item.count }));
      if (observation.analysis.truncatedPushCount > 0) findings.push(finding("bytecode-truncated-push", "analysis-quality", "review", "Bytecode contains truncated PUSH instruction data", "The disassembler encountered incomplete PUSH immediate data. Opcode-level conclusions may be incomplete.", { count: observation.analysis.truncatedPushCount }));
    }
    if (observation.kind === "erc1967-events") {
      for (const event of Array.isArray(observation.events) ? observation.events : []) {
        if (!event || !event.event) continue;
        const entry = { event: event.event, blockNumber: event.blockNumber || null, transactionHash: event.transactionHash || null, address: event.address || null, changes: event.changes || {} };
        timeline.push(entry);
        if (event.event === "Upgraded") findings.push(finding("erc1967-upgrade-event", "upgrade-history", "review", "Implementation upgrade event observed", "An ERC-1967 Upgraded event appears in the scanned log window. Confirm the transaction, implementation code and authorized change process.", entry));
        if (event.event === "AdminChanged") findings.push(finding("erc1967-admin-change-event", "privileged-control", "review", "Proxy admin change event observed", "An ERC-1967 AdminChanged event appears in the scanned log window. Verify both addresses and transaction context.", entry));
      }
      if (observation.status !== "ok") findings.push(finding("erc1967-history-unavailable", "data-completeness", "review", "Proxy event history is incomplete", "The bounded ERC-1967 event query did not complete successfully. Missing events are not proof that no changes occurred.", { status: observation.status, fromBlock: observation.fromBlock || null, toBlock: observation.toBlock || null }));
    }
    if (observation.kind === "receipt" && observation.value && observation.value.status === "0x0") findings.push(finding("transaction-reverted", "transaction-outcome", "info", "Transaction execution reverted", "The supplied receipt reports failed execution. A revert does not identify the cause or indicate malicious activity.", { transactionHash: report.subject, blockNumber: report.provenance?.blockNumber || null }));
  }
  const unique = new Map();
  for (const item of findings) {
    const key = item.id + "|" + JSON.stringify(item.evidence);
    if (!unique.has(key)) unique.set(key, item);
  }
  timeline.sort((a, b) => {
    const left = a.blockNumber ? BigInt(a.blockNumber) : 0n;
    const right = b.blockNumber ? BigInt(b.blockNumber) : 0n;
    return left < right ? -1 : left > right ? 1 : 0;
  });
  const result = [...unique.values()];
  return {
    schema: "sentinel.findings.v1",
    subject: report.subject,
    findingCount: result.length,
    reviewCount: result.filter(item => item.severity === "review").length,
    infoCount: result.filter(item => item.severity === "info").length,
    findings: result,
    timeline,
    assessment: { verdict: "not-assessed", riskScore: null, note: "Findings are rule-based prompts for human review, not vulnerability confirmations, threat attribution, or a safety verdict. No numeric risk score is generated." }
  };
}
