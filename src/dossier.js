export function buildInvestigationDossier({ reports, graph, threatIntelligence, evidenceTimeline = null, sourceFiles = [], generatedAt = new Date().toISOString() }) {
  if (!Array.isArray(reports)) throw new TypeError("Dossier reports must be an array");
  if (!graph || graph.schema !== "sentinel.correlation-graph.v1") throw new TypeError("A SENTINEL correlation graph is required");
  if (!threatIntelligence || threatIntelligence.schema !== "sentinel.threat-intelligence.v1") throw new TypeError("SENTINEL threat intelligence is required");
  if (evidenceTimeline !== null && evidenceTimeline?.schema !== "sentinel.evidence-timeline.v1") throw new TypeError("Evidence timeline must use the SENTINEL evidence timeline schema");
  if (!Array.isArray(sourceFiles) || sourceFiles.some(name => typeof name !== "string")) throw new TypeError("Source file names must be strings");
  if (typeof generatedAt !== "string" || Number.isNaN(Date.parse(generatedAt))) throw new TypeError("generatedAt must be a valid date string");

  return {
    schema: "sentinel.investigation-dossier.v1",
    generatedAt,
    source: {
      application: "SENTINEL",
      evidenceHandling: "Imported case reports are embedded as supplied; no external upload or remote enrichment is performed by this export."
    },
    summary: {
      caseCount: reports.length,
      addressNodeCount: graph.nodeCount,
      correlationEdgeCount: graph.edgeCount,
      threatSignalCount: threatIntelligence.signalCount,
      transactionHandoffCount: threatIntelligence.transactionLinks?.length ?? 0,
      addressProfileCount: threatIntelligence.addressProfiles?.length ?? 0,
      decodedTokenTransferCount: threatIntelligence.tokenTransfers?.length ?? 0,
      tokenAddressProfileCount: threatIntelligence.tokenAddressProfiles?.length ?? 0,
      timelineEventCount: evidenceTimeline?.includedEventCount ?? 0
    },
    sourceFiles: [...sourceFiles],
    cases: reports,
    correlationGraph: graph,
    threatIntelligence,
    evidenceTimeline,
    limitations: [
      "This dossier is a point-in-time compilation of user-supplied case reports and deterministic analysis.",
      "Address matches and transaction handoff trails do not prove common ownership, control, coordination, token transfer, or malicious intent.",
      "Threat signals are review prompts, not attribution, a risk score, an audit, or a safety verdict.",
      "The completeness and accuracy of each finding depend on the supplied evidence and its original RPC/provider coverage.",
      "Verify source transactions and chain context independently before relying on this dossier."
    ],
    assessment: {
      verdict: "not-assessed",
      riskScore: null
    }
  };
}
