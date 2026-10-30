import test from "node:test";
import assert from "node:assert/strict";
import { buildInvestigationDossier } from "../src/dossier.js";

const graph = { schema: "sentinel.correlation-graph.v1", nodeCount: 2, edgeCount: 1, nodes: [], edges: [] };
const threatIntelligence = { schema: "sentinel.threat-intelligence.v1", signalCount: 1, signals: [], transactionLinks: [], addressProfiles: [{ address: '0xabc' }], tokenTransfers: [{ token: '0xdef' }] };

test("builds a versioned dossier with cases, graph, intelligence and caveats", () => {
  const reports = [{ schema: "sentinel.case-report.v1", subject: "0xabc", observations: [] }];
  const dossier = buildInvestigationDossier({ reports, graph, threatIntelligence, sourceFiles: ["case.json"], generatedAt: "2026-10-30T09:00:00.000Z" });
  assert.equal(dossier.schema, "sentinel.investigation-dossier.v1");
  assert.equal(dossier.summary.caseCount, 1);
  assert.equal(dossier.summary.addressNodeCount, 2);
  assert.equal(dossier.summary.addressProfileCount, 1);
  assert.equal(dossier.summary.decodedTokenTransferCount, 1);
  assert.deepEqual(dossier.cases, reports);
  assert.ok(dossier.limitations.length >= 4);
  assert.equal(dossier.assessment.verdict, "not-assessed");
});

test("rejects missing or incompatible dossier components", () => {
  assert.throws(() => buildInvestigationDossier({ reports: {}, graph, threatIntelligence }), /reports must be an array/);
  assert.throws(() => buildInvestigationDossier({ reports: [], graph: {}, threatIntelligence }), /correlation graph is required/);
  assert.throws(() => buildInvestigationDossier({ reports: [], graph, threatIntelligence: {} }), /threat intelligence is required/);
  assert.throws(() => buildInvestigationDossier({ reports: [], graph, threatIntelligence, generatedAt: "yesterdayish" }), /valid date string/);
});
