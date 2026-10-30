import test from "node:test";
import assert from "node:assert/strict";
import { analyzeThreatIntelligence } from "../src/threat-intel.js";

const a = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const b = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const shared = "0xcccccccccccccccccccccccccccccccccccccccc";
const tx = (hash, from, to, block) => ({ kind: "transaction", value: { hash, from, to, blockNumber: block } });
const report = (subject, observations, chainId = "0x1") => ({ schema: "sentinel.case-report.v1", subject, chainId, observations, provenance: { blockNumber: "0x100" } });

test("detects a repeated sender across distinct case reports on the same chain", () => {
  const result = analyzeThreatIntelligence([report(a, [tx("0x1", shared, b, "0x10")]), report(b, [tx("0x2", shared, a, "0x11")])]);
  assert.equal(result.signalCount, 1);
  assert.equal(result.signals[0].rule, "repeated-sender");
  assert.equal(result.signals[0].confidence, "observed-pattern");
  assert.equal(result.assessment.verdict, "not-assessed");
});

test("does not combine repeated addresses across different chain IDs", () => {
  const result = analyzeThreatIntelligence([report(a, [tx("0x1", shared, b, "0x10")], "0x1"), report(b, [tx("0x2", shared, a, "0x11")], "0x38")]);
  assert.equal(result.signalCount, 0);
});

test("detects repeated recipients and reused proxy slot infrastructure", () => {
  const result = analyzeThreatIntelligence([
    report(a, [tx("0x1", a, shared, "0x10"), { kind: "erc1967-slots", implementation: shared }]),
    report(b, [tx("0x2", b, shared, "0x11"), { kind: "erc1967-slots", implementation: shared }])
  ]);
  assert.deepEqual(result.signals.map(signal => signal.rule).sort(), ["repeated-recipient", "shared-proxy-infrastructure"]);
});

test("detects distinct proxy upgrades inside a configurable block window", () => {
  const event = (blockNumber, hash) => ({ event: "Upgraded", blockNumber, transactionHash: hash, changes: { implementation: shared } });
  const result = analyzeThreatIntelligence([
    report(a, [{ kind: "erc1967-events", events: [event("0x100", "0xaaa")] }]),
    report(b, [{ kind: "erc1967-events", events: [event("0x110", "0xbbb")] }])
  ], { upgradeWindowBlocks: 32 });
  assert.equal(result.signalCount, 1);
  assert.equal(result.signals[0].rule, "upgrade-burst");
  assert.equal(result.signals[0].window.maxBlocks, 32);
  assert.equal(result.timeline.length, 2);
});

test("does not produce an upgrade burst when events fall outside the configured window", () => {
  const event = blockNumber => ({ event: "Upgraded", blockNumber });
  const result = analyzeThreatIntelligence([
    report(a, [{ kind: "erc1967-events", events: [event("0x100")] }]),
    report(b, [{ kind: "erc1967-events", events: [event("0x1000")] }])
  ], { upgradeWindowBlocks: 32 });
  assert.equal(result.signalCount, 0);
});

test("rejects invalid rule configuration and invalid input", () => {
  assert.throws(() => analyzeThreatIntelligence({}, {}), /array/);
  assert.throws(() => analyzeThreatIntelligence([], { repeatedSenderMinCases: 0 }), /positive integer/);
});

test("reports multiple separate upgrade bursts on the same chain", () => {
  const event = blockNumber => ({ event: "Upgraded", blockNumber });
  const result = analyzeThreatIntelligence([
    report(a, [{ kind: "erc1967-events", events: [event("0x100")] }]),
    report(b, [{ kind: "erc1967-events", events: [event("0x110")] }]),
    report("0xdddddddddddddddddddddddddddddddddddddddd", [{ kind: "erc1967-events", events: [event("0x1000")] }]),
    report("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", [{ kind: "erc1967-events", events: [event("0x1010")] }])
  ], { upgradeWindowBlocks: 32 });
  assert.equal(result.signals.filter(signal => signal.rule === "upgrade-burst").length, 2);
});

test("detects repeated sender activity in a configurable block window", () => {
  const result = analyzeThreatIntelligence([
    report(a, [tx("0x1", shared, b, "0x100")]),
    report(b, [tx("0x2", shared, a, "0x110")]),
    report("0xdddddddddddddddddddddddddddddddddddddddd", [tx("0x3", shared, a, "0x118")])
  ], { transactionBurstMinEvents: 3, transactionBurstWindowBlocks: 32 });
  const signal = result.signals.find(item => item.rule === "transaction-sender-burst");
  assert.ok(signal);
  assert.equal(signal.window.maxBlocks, 32);
  assert.equal(signal.evidence.length, 3);
});

test("does not detect sender bursts across different chains", () => {
  const result = analyzeThreatIntelligence([
    report(a, [tx("0x1", shared, b, "0x100")], "0x1"),
    report(b, [tx("0x2", shared, a, "0x110")], "0x38"),
    report("0xdddddddddddddddddddddddddddddddddddddddd", [tx("0x3", shared, a, "0x118")], "0x89")
  ], { transactionBurstMinEvents: 3, transactionBurstWindowBlocks: 32 });
  assert.equal(result.signals.some(item => item.rule === "transaction-sender-burst"), false);
});

test("links consecutive observed transaction handoffs on the same chain", () => {
  const result = analyzeThreatIntelligence([
    report("0x1111111111111111111111111111111111111111", [tx("0xaaa", a, shared, "0x100")]),
    report("0x2222222222222222222222222222222222222222", [tx("0xbbb", shared, b, "0x101")])
  ]);
  assert.equal(result.transactionLinks.length, 1);
  assert.equal(result.transactionLinks[0].from, a);
  assert.equal(result.transactionLinks[0].via, shared);
  assert.equal(result.transactionLinks[0].to, b);
  assert.equal(result.transactionLinks[0].interpretation, "observed-transaction-handoff");
});

test("does not link transaction handoffs across chains or backwards in block order", () => {
  const result = analyzeThreatIntelligence([
    report("0x1111111111111111111111111111111111111111", [tx("0xaaa", a, shared, "0x100")], "0x1"),
    report("0x2222222222222222222222222222222222222222", [tx("0xbbb", shared, b, "0x101")], "0x38"),
    report("0x3333333333333333333333333333333333333333", [tx("0xccc", shared, b, "0x90")], "0x1")
  ]);
  assert.equal(result.transactionLinks.length, 0);
});

test("deduplicates repeated imports of the same transaction hash", () => {
  const reportA = report("0x1111111111111111111111111111111111111111", [tx("0xaaa", a, shared, "0x100")]);
  const reportB = report("0x2222222222222222222222222222222222222222", [tx("0xaaa", a, shared, "0x100")]);
  const reportC = report("0x3333333333333333333333333333333333333333", [tx("0xbbb", shared, b, "0x101")]);
  const result = analyzeThreatIntelligence([reportA, reportB, reportC]);
  assert.equal(result.transactionLinks.length, 1);
  assert.equal(result.transactionLinks[0].firstTransaction.hash, "0xaaa");
});
