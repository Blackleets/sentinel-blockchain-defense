import test from "node:test";
import assert from "node:assert/strict";
import { ERC1967_EVENT_TOPICS, decodeErc1967Log, decodeErc1967Logs } from "../src/proxy-events.js";

const addressWord = address => "0x" + address.replace(/^0x/, "").padStart(64, "0");
const A = "0x1111111111111111111111111111111111111111";
const B = "0x2222222222222222222222222222222222222222";
const base = { address: A, blockNumber: "0x10", transactionHash: "0x" + "a".repeat(64), transactionIndex: "0x0", logIndex: "0x0" };

test("decodes indexed implementation upgrade", () => {
  const decoded = decodeErc1967Log({ ...base, topics: [ERC1967_EVENT_TOPICS.upgraded, addressWord(B)], data: "0x" });
  assert.equal(decoded.event, "Upgraded");
  assert.equal(decoded.changes.implementation, B);
});

test("decodes non-indexed admin change data", () => {
  const decoded = decodeErc1967Log({ ...base, topics: [ERC1967_EVENT_TOPICS.adminChanged], data: addressWord(A) + addressWord(B).slice(2) });
  assert.deepEqual(decoded.changes, { previousAdmin: A, newAdmin: B });
});

test("decodes indexed beacon upgrade", () => {
  const decoded = decodeErc1967Log({ ...base, topics: [ERC1967_EVENT_TOPICS.beaconUpgraded, addressWord(B)], data: "0x" });
  assert.equal(decoded.event, "BeaconUpgraded");
  assert.equal(decoded.changes.beacon, B);
});

test("ignores unknown and malformed logs", () => {
  assert.equal(decodeErc1967Log({ ...base, topics: ["0x" + "0".repeat(64)], data: "0x" }), null);
  assert.equal(decodeErc1967Log({ ...base, topics: [ERC1967_EVENT_TOPICS.upgraded], data: "0x" }), null);
});

test("sorts decoded logs by block then log index", () => {
  const later = { ...base, blockNumber: "0x11", logIndex: "0x0", topics: [ERC1967_EVENT_TOPICS.upgraded, addressWord(B)], data: "0x" };
  const earlier = { ...base, blockNumber: "0x10", logIndex: "0x2", topics: [ERC1967_EVENT_TOPICS.upgraded, addressWord(A)], data: "0x" };
  assert.equal(decodeErc1967Logs([later, earlier])[0].changes.implementation, A);
});
