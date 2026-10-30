import test from "node:test";
import assert from "node:assert/strict";
import { correlateCases } from "../src/correlation.js";

const a = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const b = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const recipient = "0x1111111111111111111111111111111111111111";
const impl = "0x3333333333333333333333333333333333333333";
const admin = "0x2222222222222222222222222222222222222222";
const report = (subject, observations = [], chainId = "0x1") => ({ schema: "sentinel.case-report.v1", subject, chainId, observations });

test("correlates two cases that reference the same ERC-1967 implementation on the same chain", () => {
  const graph = correlateCases([report(a, [{ kind: "erc1967-slots", implementation: impl }]), report(b, [{ kind: "erc1967-slots", implementation: impl }])]);
  assert.equal(graph.edgeCount, 1);
  assert.equal(graph.edges[0].type, "shared-erc1967-implementation");
  assert.equal(graph.edges[0].chainId, "0x1");
  assert.equal(graph.edges[0].evidence[0].sharedAddress, impl);
  assert.equal(graph.interpretation.verdict, "not-assessed");
});

test("does not correlate identical addresses across different chain IDs", () => {
  const graph = correlateCases([report(a, [{ kind: "erc1967-slots", implementation: impl }], "0x1"), report(b, [{ kind: "erc1967-slots", implementation: impl }], "0x38")]);
  assert.equal(graph.edgeCount, 0);
  assert.equal(graph.nodeCount, 4);
  assert.deepEqual(graph.nodes.map(node => node.chainId).sort(), ["0x1", "0x1", "0x38", "0x38"]);
});

test("correlates shared proxy admin and EIP-7702 delegation target independently", () => {
  const graph = correlateCases([
    report(a, [{ kind: "erc1967-slots", admin }, { kind: "eip7702", delegated: true, implementationAddress: impl }]),
    report(b, [{ kind: "erc1967-slots", admin }, { kind: "eip7702", delegated: true, implementationAddress: impl }])
  ]);
  assert.deepEqual(graph.edges.map(edge => edge.type).sort(), ["shared-eip7702-delegation-target", "shared-erc1967-admin-slot"]);
});

test("records transaction participants and chain without inferring a relationship verdict", () => {
  const graph = correlateCases([report("0xcccccccccccccccccccccccccccccccccccccccc", [{ kind: "transaction", value: { from: a, to: recipient } }], "0x89")]);
  assert.equal(graph.edgeCount, 1);
  assert.equal(graph.edges[0].type, "observed-transaction-flow");
  assert.equal(graph.edges[0].chainId, "0x89");
  assert.deepEqual([graph.edges[0].from, graph.edges[0].to], [a, recipient]);
});

test("deduplicates repeated evidence and ignores malformed addresses", () => {
  const graph = correlateCases([report(a, [{ kind: "erc1967-slots", implementation: impl }, { kind: "erc1967-slots", implementation: impl, admin: "not-an-address" }]), report(b, [{ kind: "erc1967-slots", implementation: impl }])]);
  assert.equal(graph.edgeCount, 1);
  assert.equal(graph.nodeCount, 3);
});

test("handles invalid reports with a warning and rejects non-array input", () => {
  const graph = correlateCases([null, { subject: a, observations: [] }]);
  assert.equal(graph.reportCount, 1);
  assert.equal(graph.warnings.length, 1);
  assert.throws(() => correlateCases({}), /Reports must be an array/);
});

test("does not create self-links from a report that repeats its own subject as implementation", () => {
  const graph = correlateCases([report(a, [{ kind: "erc1967-slots", implementation: a }])]);
  assert.equal(graph.edgeCount, 0);
});
