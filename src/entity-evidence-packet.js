const ADDRESS = /^0x[0-9a-f]{40}$/i;
const normalize = value => typeof value === "string" && ADDRESS.test(value) ? value.toLowerCase() : null;
const unique = values => [...new Set(values.filter(Boolean))].sort();

/**
 * Create a portable, entity-scoped evidence packet from an already-built neighborhood.
 * The packet preserves source records and makes its evidence coverage explicit.
 */
export function buildEntityEvidencePacket({ neighborhood, graph, threatIntelligence, generatedAt = new Date().toISOString() }) {
  if (!neighborhood || neighborhood.schema !== "sentinel.entity-neighborhood.v1") throw new TypeError("A SENTINEL entity neighborhood is required");
  if (!graph || graph.schema !== "sentinel.correlation-graph.v1") throw new TypeError("A SENTINEL correlation graph is required");
  if (!threatIntelligence || threatIntelligence.schema !== "sentinel.threat-intelligence.v1") throw new TypeError("SENTINEL threat intelligence is required");
  if (typeof generatedAt !== "string" || Number.isNaN(Date.parse(generatedAt))) throw new TypeError("generatedAt must be a valid date string");

  const chainId = neighborhood.subject.chainId;
  const addresses = new Set((neighborhood.nodes || []).map(node => normalize(node.address)).filter(Boolean));
  const edgeIds = new Set((neighborhood.edges || []).map(edge => edge.id));
  const relationshipEvidence = (graph.edges || []).filter(edge => edge.chainId === chainId &&
    (addresses.has(normalize(edge.from)) || addresses.has(normalize(edge.to)) ||
     (edge.evidence || []).some(item => addresses.has(normalize(item?.sharedAddress)))));
  const caseSubjects = unique([
    ...(neighborhood.edges || []).flatMap(edge => (edge.evidence || []).flatMap(item => [...(item.caseSubjects || []), item.caseSubject])) ,
    ...relationshipEvidence.flatMap(edge => (edge.evidence || []).flatMap(item => item.caseSubjects || [])),
    ...(threatIntelligence.signals || []).filter(signal => signal.chainId === chainId &&
      (signal.entities || []).some(address => addresses.has(normalize(address)))).flatMap(signal => signal.caseSubjects || [])
  ].filter(value => typeof value === "string"));
  const signals = (threatIntelligence.signals || []).filter(signal => signal.chainId === chainId &&
    ((signal.entities || []).some(address => addresses.has(normalize(address))) ||
     (signal.evidence || []).some(item => [item.address, item.from, item.to, item.implementation].some(address => addresses.has(normalize(address))))));
  const tokenTransfers = (threatIntelligence.tokenTransfers || []).filter(item => item.chainId === chainId &&
    (addresses.has(normalize(item.from)) || addresses.has(normalize(item.to))));
  const transactionLinks = (threatIntelligence.transactionLinks || []).filter(item => item.chainId === chainId &&
    [item.from, item.via, item.to].some(address => addresses.has(normalize(address))));
  const addressProfiles = (threatIntelligence.addressProfiles || []).filter(item => item.chainId === chainId && addresses.has(normalize(item.address)));
  const tokenAddressProfiles = (threatIntelligence.tokenAddressProfiles || []).filter(item => item.chainId === chainId && addresses.has(normalize(item.address)));
  const selectedNeighborhoodEdges = (neighborhood.edges || []).filter(edge => edgeIds.has(edge.id));

  return {
    schema: "sentinel.entity-evidence-packet.v1",
    generatedAt,
    subject: { ...neighborhood.subject },
    coverage: "bounded-entity-neighborhood-and-imported-evidence-only",
    summary: {
      entityCount: addresses.size,
      neighborhoodRelationshipCount: selectedNeighborhoodEdges.length,
      sourceCorrelationEdgeCount: relationshipEvidence.length,
      relatedCaseSubjectCount: caseSubjects.length,
      threatSignalCount: signals.length,
      tokenTransferLogCount: tokenTransfers.length,
      transactionHandoffCount: transactionLinks.length,
      addressProfileCount: addressProfiles.length,
      tokenAddressProfileCount: tokenAddressProfiles.length,
      neighborhoodTruncated: Boolean(neighborhood.summary?.truncated)
    },
    caseSubjects,
    neighborhood: {
      schema: neighborhood.schema,
      maxDepth: neighborhood.maxDepth,
      nodes: neighborhood.nodes,
      edges: selectedNeighborhoodEdges,
      summary: neighborhood.summary
    },
    sourceCorrelationEdges: relationshipEvidence,
    threatSignals: signals,
    tokenTransfers,
    transactionLinks,
    addressProfiles,
    tokenAddressProfiles,
    limitations: [
      "This packet is a point-in-time selection from evidence already imported into SENTINEL; it performs no external enrichment.",
      "A case subject is a source reference, not proof that the subject owns or controls an observed address.",
      "Graph edges, handoffs and Transfer-shaped logs do not prove common ownership, coordination, malicious intent or movement of the same assets.",
      "Token amounts remain raw base units; token decimals and contract legitimacy are not verified.",
      "A bounded or truncated neighborhood is incomplete by design. Omitted evidence is not evidence of absence.",
      "Threat signals are review prompts, not attribution, exploitability proof, a risk score or a safety verdict."
    ],
    assessment: { verdict: "not-assessed", riskScore: null }
  };
}
