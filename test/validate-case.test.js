import test from "node:test";
import assert from "node:assert/strict";
import { validateCaseReport, MAX_CASE_OBSERVATIONS } from "../src/validate-case.js";

const address = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const valid = overrides => ({ schema: "sentinel.case-report.v1", subject: address, chainId: "0x1", network: { chainId: "0x1" }, observations: [], ...overrides });

test("accepts a valid address case report and normalizes its identity", () => {
  const result = validateCaseReport(valid({ subject: address.toUpperCase(), chainId: "0X1" }));
  assert.equal(result.ok, true);
  assert.equal(result.normalizedChainId, "0x1");
  assert.equal(result.normalizedSubject, address);
});

test("accepts legacy nested chain identity when top-level chainId is absent", () => {
  const report = valid({});
  delete report.chainId;
  const result = validateCaseReport(report);
  assert.equal(result.ok, true);
  assert.equal(result.normalizedChainId, "0x1");
});

test("rejects conflicting top-level and nested chain IDs", () => {
  const result = validateCaseReport(valid({ network: { chainId: "0x38" } }));
  assert.equal(result.ok, false);
  assert.ok(result.errors.includes("conflicting-chain-identifiers"));
});

test("rejects malformed subjects, missing chain identity and non-object observations", () => {
  const report = valid({ subject: "0x123", chainId: undefined, network: {}, observations: [null] });
  const result = validateCaseReport(report);
  assert.equal(result.ok, false);
  assert.ok(result.errors.includes("subject-must-be-an-EVM-address-or-transaction-hash"));
  assert.ok(result.errors.includes("missing-chain-identifier"));
  assert.ok(result.errors.includes("observations-must-contain-objects-only"));
});

test("rejects unsupported schema and excessive observations", () => {
  const report = valid({ schema: "other", observations: Array(MAX_CASE_OBSERVATIONS + 1).fill({ kind: "x" }) });
  const result = validateCaseReport(report);
  assert.equal(result.ok, false);
  assert.ok(result.errors.includes("unsupported-case-report-schema"));
  assert.ok(result.errors.includes("observation-limit-exceeded"));
});

test("rejects non-object input", () => {
  assert.deepEqual(validateCaseReport(null), { ok: false, errors: ["report-must-be-an-object"] });
});
