import test from "node:test";
import assert from "node:assert/strict";
import { decodeStorageAddress, inspectErc1967Slots } from "../src/proxy.js";

const word = address => "0x" + address.replace(/^0x/, "").padStart(64, "0");
const impl = "0x1234567890abcdef1234567890abcdef12345678";

test("decodes an address from the low 20 bytes of a storage word", () => {
  assert.deepEqual(decodeStorageAddress(word(impl)), { status: "present", address: impl });
});

test("treats a zero storage word as empty", () => {
  assert.deepEqual(decodeStorageAddress("0x" + "0".repeat(64)), { status: "empty", address: null });
});

test("rejects malformed storage words", () => {
  assert.equal(decodeStorageAddress("0x1234").status, "invalid-storage-word");
});

test("prefers direct implementation slot over beacon slot", () => {
  const result = inspectErc1967Slots({
    implementationWord: word(impl),
    adminWord: word("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    beaconWord: word("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
  });
  assert.equal(result.kind, "implementation");
  assert.equal(result.implementation, impl);
  assert.equal(result.admin, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
});

test("detects beacon proxy when direct implementation slot is empty", () => {
  const result = inspectErc1967Slots({
    implementationWord: "0x" + "0".repeat(64),
    adminWord: "0x" + "0".repeat(64),
    beaconWord: word(impl)
  });
  assert.equal(result.kind, "beacon");
  assert.equal(result.beacon, impl);
});

test("does not claim a proxy when all standard slots are empty", () => {
  const zero = "0x" + "0".repeat(64);
  assert.equal(inspectErc1967Slots({ implementationWord: zero, adminWord: zero, beaconWord: zero }).kind, "not-detected");
});
