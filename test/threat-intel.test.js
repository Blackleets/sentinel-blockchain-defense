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
