import test from "node:test";
import assert from "node:assert/strict";
import { analyzeThreatIntelligence, decodeErc20TransferLog } from "../src/threat-intel.js";

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

test("builds chain-scoped address profiles from deduplicated transaction evidence", () => {
  const result = analyzeThreatIntelligence([
    report("0x1111111111111111111111111111111111111111", [tx("0xaaa", a, shared, "0x100")]),
    report("0x2222222222222222222222222222222222222222", [tx("0xbbb", shared, b, "0x101")]),
    report("0x3333333333333333333333333333333333333333", [tx("0xbbb", shared, b, "0x101")], "0x1"),
    report("0x4444444444444444444444444444444444444444", [tx("0xccc", a, b, "0x110")], "0x38")
  ]);
  const sharedProfile = result.addressProfiles.find(profile => profile.chainId === "0x1" && profile.address === shared);
  assert.equal(sharedProfile.incomingTransactionCount, 1);
  assert.equal(sharedProfile.outgoingTransactionCount, 1);
  assert.equal(sharedProfile.observedTransactionCount, 2);
  assert.equal(sharedProfile.uniqueObservedCounterpartyCount, 2);
  assert.equal(sharedProfile.distinctCaseCount, 2);
  assert.equal(sharedProfile.firstSeenBlock, "0x100");
  assert.equal(sharedProfile.lastSeenBlock, "0x101");
  assert.equal(sharedProfile.coverage, "imported-evidence-only");
  const separateChain = result.addressProfiles.find(profile => profile.chainId === "0x38" && profile.address === a);
  assert.equal(separateChain.observedTransactionCount, 1);
});

test("address profiles omit transactions without valid mined evidence", () => {
  const result = analyzeThreatIntelligence([
    report("0x1111111111111111111111111111111111111111", [tx(null, a, b, "0x100"), tx("0xabc", a, b, null)])
  ]);
  assert.equal(result.addressProfiles.length, 0);
});

const transferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const indexed = address => "0x" + address.slice(2).padStart(64, "0");
const transferLog = (overrides = {}) => ({
  address: shared,
  topics: [transferTopic, indexed(a), indexed(b)],
  data: "0x" + (2500n).toString(16).padStart(64, "0"),
  blockNumber: "0x100",
  transactionHash: "0xabc",
  logIndex: "0x2",
  ...overrides
});

test("decodes a standard ERC-20 Transfer log without guessing token decimals", () => {
  const decoded = decodeErc20TransferLog(transferLog());
  assert.deepEqual(decoded, { token: shared, from: a, to: b, amountRaw: "2500" });
});

test("rejects malformed and non-Transfer event logs", () => {
  assert.equal(decodeErc20TransferLog(null), null);
  assert.equal(decodeErc20TransferLog(transferLog({ topics: [transferTopic] })), null);
  assert.equal(decodeErc20TransferLog(transferLog({ topics: ["0x" + "0".repeat(64), indexed(a), indexed(b)] })), null);
  assert.equal(decodeErc20TransferLog(transferLog({ topics: [transferTopic, "0x" + "f".repeat(64), indexed(b)] })), null);
  assert.equal(decodeErc20TransferLog(transferLog({ data: "0x1234" })), null);
});

test("extracts and deduplicates receipt Transfer logs in imported evidence", () => {
  const receipt = { kind: "receipt", value: { transactionHash: "0xabc", blockNumber: "0x100", logs: [transferLog(), transferLog()] } };
  const result = analyzeThreatIntelligence([
    { ...report(a, [receipt]), subjectType: "transaction" }
  ]);
  assert.equal(result.tokenTransfers.length, 1);
  assert.equal(result.tokenTransfers[0].amountRaw, "2500");
  assert.equal(result.tokenTransfers[0].token, shared);
  assert.equal(result.tokenTransfers[0].from, a);
  assert.equal(result.tokenTransfers[0].to, b);
});
