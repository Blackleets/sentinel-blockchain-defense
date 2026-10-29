import test from "node:test";
import assert from "node:assert/strict";
import { inspectDelegationCode } from "../src/eip7702.js";

const target = "1234567890abcdef1234567890abcdef12345678";

test("recognizes a valid EIP-7702 designator and extracts its target", () => {
  assert.deepEqual(inspectDelegationCode("0xef0100" + target), {
    isDelegated: true,
    status: "delegated",
    implementationAddress: "0x" + target
  });
});

test("recognizes empty account code", () => {
  assert.equal(inspectDelegationCode("0x").status, "no-code");
});

test("does not classify ordinary contract bytecode as delegation", () => {
  assert.equal(inspectDelegationCode("0x6001600055").status, "ordinary-code");
});

test("rejects a truncated delegation designator", () => {
  assert.equal(inspectDelegationCode("0xef0100abcd").status, "malformed-designator");
});

test("rejects malformed hex input", () => {
  assert.equal(inspectDelegationCode("0xzz0100").status, "invalid-code");
  assert.equal(inspectDelegationCode(null).status, "invalid-code");
});
