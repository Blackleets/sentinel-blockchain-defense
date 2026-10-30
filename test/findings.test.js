import test from "node:test";
import assert from "node:assert/strict";
import { analyzeCaseFindings } from "../src/findings.js";

const subject = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const report = observations => ({ schema: "sentinel.case-report.v1", subject, provenance: { blockNumber: "0x100" }, observations });

test("flags EIP-7702 delegation as a review item, not a compromise verdict", () => {
  const result = analyzeCaseFindings(report([{ kind: "eip7702", delegated: true, implementationAddress: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }]));
  assert.equal(result.findings[0].id, "eip7702-delegation-present");
  assert.equal(result.assessment.verdict, "not-assessed");
  assert.equal(result.assessment.riskScore, null);
});

test("identifies proxy metadata and populated admin slot separately", () => {
  const result = analyzeCaseFindings(report([{ kind: "erc1967-slots", implementation: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", admin: "0xcccccccccccccccccccccccccccccccccccccccc" }]));
  assert.deepEqual(result.findings.map(item => item.id).sort(), ["erc1967-admin-slot-populated", "erc1967-proxy-metadata"]);
});

test("creates an evidence-backed upgrade timeline and review finding", () => {
  const result = analyzeCaseFindings(report([{ kind: "erc1967-events", status: "ok", events: [
    { event: "AdminChanged", blockNumber: "0x12", transactionHash: "0xabc", changes: { previousAdmin: null, newAdmin: subject } },
    { event: "Upgraded", blockNumber: "0x10", transactionHash: "0xdef", changes: { implementation: subject } }
  ] }]));
  assert.equal(result.timeline.length, 2);
  assert.equal(result.timeline[0].event, "Upgraded");
  assert.equal(result.findings.length, 2);
});

test("surfaces incomplete history and truncated bytecode without inventing a score", () => {
  const result = analyzeCaseFindings(report([
    { kind: "erc1967-events", status: "rpc-timeout", events: [] },
    { kind: "bytecode-analysis", analysis: { evidence: [], truncatedPushCount: 2 } }
  ]));
  assert.equal(result.reviewCount, 2);
  assert.equal(result.assessment.riskScore, null);
});

test("ignores ordinary opcodes and reports sensitive static capabilities as review prompts", () => {
  const result = analyzeCaseFindings(report([{ kind: "bytecode-analysis", analysis: {
    evidence: [
      { capability: "SSTORE", count: 2, explanation: "Normal state writes" },
      { capability: "DELEGATECALL", count: 1, explanation: "Delegated execution" }
    ], truncatedPushCount: 0
  } }]));
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].id, "bytecode-opcode-delegatecall");
});

test("rejects reports outside the supported schema", () => {
  assert.throws(() => analyzeCaseFindings({ subject, observations: [] }), /Expected a SENTINEL case report/);
});
