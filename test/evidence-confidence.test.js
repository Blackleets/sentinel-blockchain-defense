import test from "node:test";
import assert from "node:assert/strict";
import { buildEvidenceConfidenceAssessment } from "../src/evidence-confidence.js";

const hash = "0x" + "a".repeat(64);
const matched = () => ({
  schema: "sentinel.investigation-source-verification.v1",
  observedAt: "2026-10-30T12:00:00.000Z",
  provider: "https://rpc.example",
  providerName: "Example chain",
  subject: { chainId: "0x1", address: "0x" + "b".repeat(40) },
  chainCheck: { expected: "0x1", actual: "0x1", matched: true },
  coverage: { uniqueTransactionReferences: 1, checkedTransactions: 1, notChecked: 0, truncated: false },
  summary: {},
  results: [{
    transactionHash: hash,
    status: "confirmed",
    canonicalityStatus: "matched",
    evidenceChecks: [{ kind: "observed-token-transfer-log", status: "matched", problems: [] }]
  }]
});

test("corroborates a complete set of consistent source observations without numeric scoring", () => {
  const result = buildEvidenceConfidenceAssessment(matched());
  assert.equal(result.assessment, "corroborated");
  assert.equal(result.summary.verifiedDimensions, 5);
  assert.equal(result.summary.conflictingDimensions, 0);
  assert.equal(result.summary.unknownDimensions, 0);
  assert.equal(result.transactions[0].status, "corroborated");
  assert.equal("score" in result, false);
  assert.equal(result.checks.every(item => item.status === "verified"), true);
});

test("keeps incomplete coverage unknown instead of treating it as a pass", () => {
  const source = matched();
  source.coverage = { uniqueTransactionReferences: 4, checkedTransactions: 1, notChecked: 3, truncated: true };
  const result = buildEvidenceConfidenceAssessment(source);
  assert.equal(result.assessment, "partially-corroborated");
  assert.equal(result.checks.find(item => item.id === "reference-coverage").status, "unknown");
  assert.equal(result.summary.uncheckedTransactions, 3);
});

test("marks a canonical block mismatch as conflicting evidence", () => {
  const source = matched();
  source.results[0].canonicalityStatus = "mismatch";
  source.results[0].status = "inconsistent";
  const result = buildEvidenceConfidenceAssessment(source);
  assert.equal(result.assessment, "conflicting");
  assert.equal(result.checks.find(item => item.id === "canonical-block").status, "conflicting");
  assert.match(result.checks.find(item => item.id === "canonical-block").detail, /differs/);
});

test("does not call absent or uncheckable observations verified", () => {
  const source = matched();
  source.results[0].evidenceChecks = [{ kind: "raw-reference", status: "not-checkable", problems: [] }];
  const result = buildEvidenceConfidenceAssessment(source);
  assert.equal(result.checks.find(item => item.id === "dossier-observation-correlation").status, "unknown");
  assert.equal(result.assessment, "partially-corroborated");
});

test("keeps an empty verification run inconclusive", () => {
  const source = matched();
  source.results = [];
  source.coverage = { uniqueTransactionReferences: 0, checkedTransactions: 0, notChecked: 0, truncated: false };
  const result = buildEvidenceConfidenceAssessment(source);
  assert.equal(result.assessment, "partially-corroborated");
  assert.equal(result.checks.find(item => item.id === "transaction-receipt-consistency").status, "unknown");
  assert.equal(result.checks.find(item => item.id === "canonical-block").status, "unknown");
  assert.equal(result.checks.find(item => item.id === "reference-coverage").status, "verified");
});

test("treats chain ID mismatch as a conflict", () => {
  const source = matched();
  source.chainCheck.matched = false;
  const result = buildEvidenceConfidenceAssessment(source);
  assert.equal(result.checks[0].status, "conflicting");
  assert.equal(result.assessment, "conflicting");
});

test("rejects non-source-verification input", () => {
  assert.throws(() => buildEvidenceConfidenceAssessment({}), /source-verification result/);
});

test("retains evidence references on checks for analyst traceability", () => {
  const result = buildEvidenceConfidenceAssessment(matched());
  assert.deepEqual(result.checks.find(item => item.id === "transaction-receipt-consistency").references, [hash]);
  assert.equal(result.provider, "https://rpc.example");
});
