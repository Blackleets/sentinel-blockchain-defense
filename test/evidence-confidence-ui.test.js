import test from "node:test";
import assert from "node:assert/strict";
import { buildSourceVerificationDossiers } from "../src/evidence-confidence-ui.js";

const hash = "0x" + "a".repeat(64);
const hash2 = "0x" + "b".repeat(64);
const address = "0x" + "1".repeat(40);

function report({ chainId = "0x1", subject = hash, subjectType = "transaction", observations = [] } = {}) {
  return {
    schema: "sentinel.case-report.v1",
    chainId,
    subject,
    subjectType,
    provenance: { blockNumber: "0x10" },
    observations
  };
}

function dossier(cases, tokenTransfers = []) {
  return {
    schema: "sentinel.investigation-dossier.v1",
    cases,
    threatIntelligence: { tokenTransfers }
  };
}

test("builds separate verification inputs per chain and deduplicates transaction references", () => {
  const cases = [
    report({ chainId: "0x1", subject: hash }),
    report({
      chainId: "0x1",
      subject: address,
      subjectType: "address",
      observations: [{ kind: "transaction", value: { hash, blockNumber: "0x10", from: address, to: address } }]
    }),
    report({ chainId: "0x38", subject: hash2 })
  ];
  const inputs = buildSourceVerificationDossiers(dossier(cases));
  assert.equal(inputs.length, 2);
  assert.deepEqual(inputs.map(item => item.subject.chainId), ["0x1", "0x38"]);
  assert.deepEqual(inputs[0].sourceReferences, [hash]);
  assert.deepEqual(inputs[1].sourceReferences, [hash2]);
});

test("preserves transfer log provenance and ignores malformed transaction hashes", () => {
  const inputs = buildSourceVerificationDossiers(dossier(
    [report({ chainId: "0x89", subject: address, subjectType: "address", observations: [
      { kind: "transaction", value: { hash: "not-a-hash" } }
    ] })],
    [{ chainId: "0x89", from: address, to: address, transactionHash: hash, token: address, amountRaw: "7", logIndex: "0x2" }]
  ));
  assert.equal(inputs.length, 1);
  assert.equal(inputs[0].timeline[0].kind, "observed-token-transfer-log");
  assert.equal(inputs[0].timeline[0].logIndex, "0x2");
  assert.equal(inputs[0].timeline[0].record.evidence.amountRaw, "7");
});

test("returns no verification input when no transaction references exist", () => {
  const inputs = buildSourceVerificationDossiers(dossier([
    report({ chainId: "0x1", subject: address, subjectType: "address" })
  ]));
  assert.deepEqual(inputs, []);
});

test("rejects a dossier with the wrong schema", () => {
  assert.throws(() => buildSourceVerificationDossiers({ schema: "wrong", cases: [] }), /multi-case investigation dossier/);
});
