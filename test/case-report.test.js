import test from "node:test";
import assert from "node:assert/strict";
import { buildCaseReport, CASE_REPORT_SCHEMA } from "../src/case-report.js";

test("builds a provenance-labelled read-only evidence snapshot", () => {
  const report = buildCaseReport({
    subject: "0xABCDEF",
    subjectType: "address",
    chainId: "0x1",
    provider: "https://rpc.example",
    observedAt: "2026-10-30T00:00:00.000Z",
    blockNumber: "0x123",
    observations: [{ kind: "code", value: "0x6000" }]
  });
  assert.equal(report.schema, CASE_REPORT_SCHEMA);
  assert.equal(report.subject, "0xabcdef");
  assert.equal(report.network.chainId, "0x1");
  assert.equal(report.provenance.blockNumber, "0x123");
  assert.equal(report.interpretation.verdict, "not-assessed");
  assert.equal(report.observations.length, 1);
});

test("rejects missing subjects and non-array observations", () => {
  assert.throws(() => buildCaseReport({ subject: "", subjectType: "address", observations: [] }), TypeError);
  assert.throws(() => buildCaseReport({ subject: "0xabc", subjectType: "address", observations: {} }), TypeError);
});
