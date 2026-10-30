export const CASE_REPORT_SCHEMA = "sentinel.case-report.v1";

export function buildCaseReport({
  subject,
  subjectType,
  chainId,
  provider,
  observedAt,
  blockNumber,
  observations
}) {
  if (typeof subject !== "string" || !subject.trim()) throw new TypeError("Case subject is required");
  if (typeof subjectType !== "string" || !subjectType.trim()) throw new TypeError("Subject type is required");
  if (!Array.isArray(observations)) throw new TypeError("Observations must be an array");
  return {
    schema: CASE_REPORT_SCHEMA,
    product: "SENTINEL",
    reportType: "read-only-evidence-snapshot",
    subject: subject.trim().toLowerCase(),
    subjectType,
    network: {
      name: "Ethereum Mainnet",
      chainId: chainId ?? "0x1",
      provider: provider || null
    },
    provenance: {
      observedAt: observedAt || new Date().toISOString(),
      blockNumber: blockNumber ?? null,
      completeness: "point-in-time snapshot; not a complete historical record"
    },
    observations,
    interpretation: {
      verdict: "not-assessed",
      note: "This report preserves technical observations. It does not establish malicious intent, exploitability, ownership, or safety."
    }
  };
}
