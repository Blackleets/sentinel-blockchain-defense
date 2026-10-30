export const MAX_CASE_OBSERVATIONS = 5000;

function validChainId(value) {
  return typeof value === "string" && /^0x[0-9a-f]+$/i.test(value);
}

function validSubject(value) {
  return typeof value === "string" && /^0x(?:[0-9a-f]{40}|[0-9a-f]{64})$/i.test(value);
}

export function validateCaseReport(report) {
  const errors = [];
  if (!report || typeof report !== "object" || Array.isArray(report)) {
    return { ok: false, errors: ["report-must-be-an-object"] };
  }
  if (report.schema !== "sentinel.case-report.v1") errors.push("unsupported-case-report-schema");
  if (!validSubject(report.subject)) errors.push("subject-must-be-an-EVM-address-or-transaction-hash");
  if (!Array.isArray(report.observations)) errors.push("observations-must-be-an-array");
  else {
    if (report.observations.length > MAX_CASE_OBSERVATIONS) errors.push("observation-limit-exceeded");
    if (report.observations.some(item => !item || typeof item !== "object" || Array.isArray(item))) errors.push("observations-must-contain-objects-only");
  }

  const topLevelChain = report.chainId;
  const nestedChain = report.network?.chainId;
  if (topLevelChain !== undefined && !validChainId(topLevelChain)) errors.push("invalid-top-level-chain-id");
  if (nestedChain !== undefined && !validChainId(nestedChain)) errors.push("invalid-network-chain-id");
  if (topLevelChain !== undefined && nestedChain !== undefined && topLevelChain.toLowerCase() !== nestedChain.toLowerCase()) {
    errors.push("conflicting-chain-identifiers");
  }
  if (topLevelChain === undefined && nestedChain === undefined) errors.push("missing-chain-identifier");

  return {
    ok: errors.length === 0,
    errors,
    normalizedChainId: validChainId(topLevelChain) ? topLevelChain.toLowerCase() : validChainId(nestedChain) ? nestedChain.toLowerCase() : null,
    normalizedSubject: validSubject(report.subject) ? report.subject.toLowerCase() : null,
    observationCount: Array.isArray(report.observations) ? report.observations.length : 0
  };
}
