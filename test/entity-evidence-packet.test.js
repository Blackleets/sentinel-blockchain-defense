import test from "node:test";
import assert from "node:assert/strict";
import { buildEntityEvidencePacket } from "../src/entity-evidence-packet.js";

const a = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const b = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const c = "0xcccccccccccccccccccccccccccccccccccccccc";
const h = "0x" + "1".repeat(64);
const neighborhood = {
  schema: "sentinel.entity-neighborhood.v1", subject: { chainId: "0x1", address: a }, maxDepth: 2,
  nodes: [{ address: a, distance: 0, origin: true }, { address: b, distance: 1, origin: false }],
  edges: [{ id: "edge-1", chainId: "0x1", from: a, to: b, type: "observed-token-transfer-log", source: "receipt-log", evidence: [{ caseSubject: h }] }],
  summary: { nodeCount: 2, edgeCount: 1, truncated: false }
};
const graph = { schema: "sentinel.correlation-graph.v1", edges: [
  { chainId: "0x1", from: a, to: b, type: "observed-transaction-flow", evidence: [{ caseSubjects: [h] }] },
  { chainId: "0x38", from: a, to: c, type: "observed-transaction-flow", evidence: [] }
] };
const threatIntelligence = {
  schema: "sentinel.threat-intelligence.v1",
  signals: [{ chainId: "0x1", entities: [a], caseSubjects: [h], evidence: [] }, { chainId: "0x38", entities: [a], caseSubjects: [], evidence: [] }],
  tokenTransfers: [{ chainId: "0x1", from: a, to: b, amountRaw: "12" }, { chainId: "0x38", from: a, to: c, amountRaw: "99" }],
  transactionLinks: [{ chainId: "0x1", from: a, via: b, to: c }],
  addressProfiles: [{ chainId: "0x1", address: a }, { chainId: "0x38", address: a }],
  tokenAddressProfiles: [{ chainId: "0x1", address: b }, { chainId: "0x38", address: b }]
};

test("builds a chain-scoped entity packet with preserved evidence and counts", () => {
  const packet = buildEntityEvidencePacket({ neighborhood, graph, threatIntelligence, generatedAt: "2026-10-30T10:00:00.000Z" });
  assert.equal(packet.schema, "sentinel.entity-evidence-packet.v1");
  assert.equal(packet.summary.entityCount, 2);
  assert.equal(packet.summary.sourceCorrelationEdgeCount, 1);
  assert.equal(packet.summary.threatSignalCount, 1);
  assert.equal(packet.summary.tokenTransferLogCount, 1);
  assert.equal(packet.summary.transactionHandoffCount, 1);
  assert.deepEqual(packet.caseSubjects, [h]);
  assert.equal(packet.assessment.verdict, "not-assessed");
  assert.ok(packet.limitations.some(item => item.includes("Transfer-shaped")));
});

test("surfaces neighborhood truncation and keeps evidence arrays scoped to selected entities", () => {
  const capped = { ...neighborhood, summary: { ...neighborhood.summary, truncated: true } };
  const packet = buildEntityEvidencePacket({ neighborhood: capped, graph, threatIntelligence });
  assert.equal(packet.summary.neighborhoodTruncated, true);
  assert.equal(packet.tokenTransfers.length, 1);
  assert.equal(packet.addressProfiles.length, 1);
});

test("rejects incompatible inputs and invalid timestamps", () => {
  assert.throws(() => buildEntityEvidencePacket({ neighborhood: {}, graph, threatIntelligence }), /entity neighborhood/);
  assert.throws(() => buildEntityEvidencePacket({ neighborhood, graph: {}, threatIntelligence }), /correlation graph/);
  assert.throws(() => buildEntityEvidencePacket({ neighborhood, graph, threatIntelligence: {} }), /threat intelligence/);
  assert.throws(() => buildEntityEvidencePacket({ neighborhood, graph, threatIntelligence, generatedAt: "nope" }), /valid date string/);
});
