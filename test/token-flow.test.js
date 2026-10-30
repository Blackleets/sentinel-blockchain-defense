import test from "node:test";
import assert from "node:assert/strict";
import { buildTokenFlowGraph } from "../src/token-flow.js";

const a = "0x1111111111111111111111111111111111111111";
const b = "0x2222222222222222222222222222222222222222";
const c = "0x3333333333333333333333333333333333333333";
const token = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const tx = hash => "0x" + hash.repeat(64).slice(0, 64);
const transfer = (from, to, block, logIndex, hash, overrides = {}) => ({
  chainId: "0x1", token, from, to, blockNumber: block, logIndex,
  transactionHash: tx(hash), amountRaw: "1000", caseSubject: "0xcase", ...overrides
});

test("builds deterministic, chain-scoped token flow nodes and evidence edges", () => {
  const result = buildTokenFlowGraph([
    transfer(a, b, "0x10", "0x0", "a"),
    transfer(b, c, "0x11", "0x0", "b")
  ]);
  assert.equal(result.schema, "sentinel.token-flow-graph.v1");
  assert.equal(result.nodeCount, 3);
  assert.equal(result.edgeCount, 2);
  assert.equal(result.edges[0].from, a);
  assert.equal(result.edges[1].to, c);
  assert.equal(result.nodes.find(node => node.address === b).incomingTransferCount, 1);
  assert.equal(result.nodes.find(node => node.address === b).outgoingTransferCount, 1);
  assert.equal(result.coverage, "imported-receipt-logs-only");
});

test("filters by chain, token contract and directly connected address", () => {
  const otherToken = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const result = buildTokenFlowGraph([
    transfer(a, b, "0x10", "0x0", "a"),
    transfer(b, c, "0x11", "0x0", "b"),
    transfer(a, c, "0x12", "0x0", "c", { chainId: "0x38" }),
    transfer(a, c, "0x13", "0x0", "d", { token: otherToken })
  ], { chainId: "0x1", token, address: a });
  assert.equal(result.edgeCount, 1);
  assert.equal(result.edges[0].to, b);
  assert.equal(result.selectedAddress, a);
});

test("deduplicates by chain, transaction and log index and sorts by block/log", () => {
  const first = transfer(a, b, "0x10", "0x2", "a");
  const duplicate = { ...first, amountRaw: "999999" };
  const second = transfer(b, c, "0x10", "0x1", "b");
  const result = buildTokenFlowGraph([first, duplicate, second]);
  assert.equal(result.edgeCount, 2);
  assert.equal(result.edges[0].logIndex, "0x1");
  assert.equal(result.edges[1].amountRaw, "1000");
});

test("bounds output and reports truncation without hiding matched count", () => {
  const result = buildTokenFlowGraph([
    transfer(a, b, "0x10", "0x0", "a"),
    transfer(b, c, "0x11", "0x0", "b")
  ], { maxTransfers: 1 });
  assert.equal(result.totalMatchedTransferCount, 2);
  assert.equal(result.includedTransferCount, 1);
  assert.equal(result.truncated, true);
});

test("rejects invalid arguments and ignores malformed evidence", () => {
  assert.throws(() => buildTokenFlowGraph({}, {}), /array/);
  assert.throws(() => buildTokenFlowGraph([], { maxTransfers: 501 }), /between 1 and 500/);
  assert.throws(() => buildTokenFlowGraph([], { address: "not-an-address" }), /valid EVM address/);
  const result = buildTokenFlowGraph([{ ...transfer(a, b, "0x10", "0x0", "a"), amountRaw: "-1" }]);
  assert.equal(result.edgeCount, 0);
});
