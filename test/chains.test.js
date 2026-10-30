import test from "node:test";
import assert from "node:assert/strict";
import { CHAINS, getChain, validateChainId } from "../src/chains.js";

test("registry exposes three EVM networks with unique chain IDs", () => {
  assert.deepEqual(Object.keys(CHAINS), ["ethereum", "bnb", "polygon"]);
  assert.equal(new Set(Object.values(CHAINS).map(chain => chain.chainId)).size, 3);
  assert.equal(CHAINS.ethereum.chainIdDecimal, 1);
  assert.equal(CHAINS.bnb.chainIdDecimal, 56);
  assert.equal(CHAINS.polygon.chainIdDecimal, 137);
});

test("getChain rejects unknown networks", () => {
  assert.equal(getChain("ethereum").name, "Ethereum Mainnet");
  assert.equal(getChain("unknown"), null);
});

test("chain ID validation is case-insensitive and detects mismatches", () => {
  assert.deepEqual(validateChainId("0x1", "0X1"), { ok: true, expected: "0x1", actual: "0x1", reason: null });
  assert.equal(validateChainId("0x1", "0x38").reason, "chain-id-mismatch");
  assert.equal(validateChainId("bad", "0x1").reason, "invalid-chain-id");
});
