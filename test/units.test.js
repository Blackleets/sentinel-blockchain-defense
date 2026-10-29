import test from "node:test";
import assert from "node:assert/strict";
import { formatWei } from "../src/units.js";

test("formats whole ETH values", () => {
  assert.equal(formatWei("0xde0b6b3a7640000"), "1.00000000");
});

test("formats fractional ETH without floating-point conversion", () => {
  assert.equal(formatWei("0x2386f26fc10000"), "0.01000000");
});

test("supports zero ETH", () => {
  assert.equal(formatWei("0x0"), "0.00000000");
});

test("rejects malformed quantities", () => {
  assert.throws(() => formatWei("100"), TypeError);
  assert.throws(() => formatWei("0xgg"), TypeError);
});

test("validates display precision", () => {
  assert.throws(() => formatWei("0x1", 19), RangeError);
});
