import test from "node:test";
import assert from "node:assert/strict";
import { buildEvidenceTimeline } from "../src/timeline.js";

const a = "0x1111111111111111111111111111111111111111";
const b = "0x2222222222222222222222222222222222222222";
const token = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const hash = n => "0x" + String(n).repeat(64).slice(0, 64);
const report = (subject, chainId, observations, extra = {}) => ({
  schema: "sentinel.case-report.v1", subject, subjectType: "transaction", chainId,
  provenance: { blockNumber: "0x10" }, observations, ...extra
});

test("combines transactions, proxy events and token logs in deterministic block order", () => {
  const reports = [report(hash(1), "0x1", [
    { kind: "transaction", value: { hash: hash(1), from: a, to: b, blockNumber: "0x12", transactionIndex: "0x1" } },
    { kind: "erc1967-events", events: [{ event: "Upgraded", address: a, blockNumber: "0x11", transactionHash: hash(2), logIndex: "0x0", changes: { implementation: b } }] },
    { kind: "blockTimestamp", value: "0x6553f100" }
  ])];
  const transfers = [{ chainId: "0x1", transactionHash: hash(3), blockNumber: "0x10", logIndex: "0x2", from: b, to: a, token, amountRaw: "500", caseSubject: hash(3) }];
  const result = buildEvidenceTimeline(reports, { tokenTransfers: transfers });
  assert.equal(result.schema, "sentinel.evidence-timeline.v1");
  assert.deepEqual(result.events.map(event => event.eventType), ["token-transfer", "proxy-upgraded", "transaction"]);
  assert.equal(result.events[2].timestamp, new Date(0x6553f100 * 1000).toISOString());
  assert.equal(result.events[0].timestamp, null);
});

test("filters by chain, address and inclusive block range", () => {
  const reports = [
    report(hash(1), "0x1", [{ kind: "transaction", value: { hash: hash(1), from: a, to: b, blockNumber: "0x10" } }]),
    report(hash(2), "0x38", [{ kind: "transaction", value: { hash: hash(2), from: b, to: a, blockNumber: "0x11" } }])
  ];
  const result = buildEvidenceTimeline(reports, { chainId: "0x1", address: a, fromBlock: "16", toBlock: "0x10" });
  assert.equal(result.includedEventCount, 1);
  assert.equal(result.events[0].chainId, "0x1");
  assert.equal(result.filters.fromBlock, "0x10");
});

test("deduplicates repeated report observations but preserves distinct event types", () => {
  const tx = { kind: "transaction", value: { hash: hash(1), from: a, to: b, blockNumber: "0x10" } };
  const reports = [report(hash(1), "0x1", [tx]), report(hash(1), "0x1", [tx])];
  const result = buildEvidenceTimeline(reports);
  assert.equal(result.includedEventCount, 1);
});

test("bounds output and marks truncation exactly", () => {
  const reports = [report(hash(1), "0x1", [
    { kind: "transaction", value: { hash: hash(1), from: a, to: b, blockNumber: "0x10" } },
    { kind: "transaction", value: { hash: hash(2), from: b, to: a, blockNumber: "0x11" } }
  ])];
  const capped = buildEvidenceTimeline(reports, { maxEvents: 1 });
  assert.equal(capped.includedEventCount, 1);
  assert.equal(capped.totalMatchedEventCount, 2);
  assert.equal(capped.truncated, true);
  assert.equal(buildEvidenceTimeline(reports, { maxEvents: 2 }).truncated, false);
});

test("rejects malformed filters and ignores malformed observations", () => {
  assert.throws(() => buildEvidenceTimeline({}, {}), /array/);
  assert.throws(() => buildEvidenceTimeline([], { address: "bad" }), /valid EVM address/);
  assert.throws(() => buildEvidenceTimeline([], { fromBlock: "bad" }), /block number/);
  assert.throws(() => buildEvidenceTimeline([], { maxEvents: 1001 }), /between 1 and 1000/);
  const result = buildEvidenceTimeline([report(hash(1), "0x1", [{ kind: "transaction", value: { from: "bad", to: b } }])]);
  assert.equal(result.includedEventCount, 0);
});
