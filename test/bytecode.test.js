import test from "node:test";
import assert from "node:assert/strict";
import { analyzeBytecode, disassembleBytecode } from "../src/bytecode.js";

test("disassembles PUSH data without mistaking immediate bytes for opcodes", () => {
  const items = disassembleBytecode("0x60ff6001f4");
  assert.deepEqual(items.map(x => x.name), ["PUSH1", "PUSH1", "DELEGATECALL"]);
  assert.equal(items[0].immediate, "ff");
});

test("extracts PUSH4 selector candidates without claiming ABI certainty", () => {
  const result = analyzeBytecode("0x63a9059cbb6000");
  assert.deepEqual(result.selectorCandidates, ["0xa9059cbb"]);
});

test("counts security-relevant capabilities with explanatory evidence", () => {
  const result = analyzeBytecode("0xf4f155f1ff");
  assert.deepEqual(result.evidence.map(x => x.capability), ["DELEGATECALL", "CALL", "SELFDESTRUCT", "SSTORE"]);
  assert.equal(result.evidence[0].severity, "review");
});

test("handles empty bytecode", () => {
  assert.equal(analyzeBytecode("0x").byteLength, 0);
  assert.equal(analyzeBytecode("0x").instructionCount, 0);
});

test("reports incomplete PUSH immediate bytes without reading beyond code", () => {
  const result = analyzeBytecode("0x7f1234");
  assert.equal(result.truncatedPushCount, 1);
  assert.equal(result.instructionCount, 1);
});

test("rejects malformed bytecode", () => {
  assert.throws(() => disassembleBytecode("0x123"), TypeError);
  assert.throws(() => analyzeBytecode("not hex"), TypeError);
});
