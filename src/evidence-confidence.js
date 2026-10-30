const VERIFICATION_SCHEMA = "sentinel.investigation-source-verification.v1";
const CONFIDENCE_SCHEMA = "sentinel.evidence-confidence.v1";

const isObject = value => value !== null && typeof value === "object" && !Array.isArray(value);
const asCount = value => Number.isSafeInteger(value) && value >= 0 ? value : null;

function check(id, label, status, detail, references = []) {
  return { id, label, status, detail, references: [...new Set(references.filter(value => typeof value === "string" && value.length > 0))] };
}

function summarize(checks) {
  const counts = { verified: 0, conflicting: 0, unknown: 0 };
  for (const item of checks) {
    if (item.status === "verified") counts.verified++;
    else if (item.status === "conflicting") counts.conflicting++;
    else counts.unknown++;
  }
  const status = counts.conflicting > 0
    ? "conflicting"
    : counts.unknown === 0 && counts.verified === checks.length && checks.length > 0
      ? "corroborated"
      : counts.verified > 0
        ? "partially-corroborated"
        : "inconclusive";
  return { status, counts };
}

function transactionChecks(result) {
  const hash = typeof result.transactionHash === "string" ? result.transactionHash : null;
  const status = result.status;
  const transactionReceipt = status === "confirmed" || status === "canonicality-unavailable";
  const receiptConflict = status === "inconsistent";
  const canonicality = result.canonicalityStatus;
  const evidence = Array.isArray(result.evidenceChecks) ? result.evidenceChecks : [];
  const evidenceMismatch = evidence.some(item => item?.status === "mismatch");
  const evidenceMatched = evidence.length > 0 && evidence.every(item => item?.status === "matched");
  return [
    check(
      "transaction-receipt",
      "Transaction and receipt",
      receiptConflict ? "conflicting" : transactionReceipt ? "verified" : "unknown",
      receiptConflict ? "The RPC response contains a transaction/receipt consistency problem." :
        transactionReceipt ? "The transaction and receipt were returned and passed the verifier's consistency checks." :
          "The transaction/receipt pair was not fully checkable at this observation time.",
      hash ? [hash] : []
    ),
    check(
      "canonical-block",
      "Block canonicality at queried height",
      canonicality === "mismatch" ? "conflicting" : canonicality === "matched" ? "verified" : "unknown",
      canonicality === "mismatch" ? "The receipt block hash differs from the block returned by this RPC endpoint at the same height." :
        canonicality === "matched" ? "The receipt block hash matches the block returned by this RPC endpoint at the queried height." :
          "Canonical block comparison was unavailable or inconclusive.",
      hash ? [hash] : []
    ),
    check(
      "dossier-evidence",
      "Dossier observation correlation",
      evidenceMismatch ? "conflicting" : evidenceMatched ? "verified" : "unknown",
      evidenceMismatch ? "At least one dossier observation differs from the fetched transaction or receipt." :
        evidenceMatched ? "Every checkable dossier observation for this transaction matched the fetched transaction/receipt." :
          "The dossier observations were absent, incomplete or not independently checkable.",
      hash ? [hash] : []
    )
  ];
}

/**
 * Convert a read-only RPC source-verification result into an explainable,
 * non-numeric evidence-quality assessment. This is not a risk score or verdict.
 */
export function buildEvidenceConfidenceAssessment(verification) {
  if (!isObject(verification) || verification.schema !== VERIFICATION_SCHEMA) {
    throw new TypeError("A SENTINEL source-verification result is required");
  }
  if (!isObject(verification.chainCheck) || !isObject(verification.coverage) ||
      !isObject(verification.summary) || !Array.isArray(verification.results)) {
    throw new TypeError("Source-verification result is missing required chain, coverage, summary or result fields");
  }

  const results = verification.results;
  const hashes = results.map(item => item?.transactionHash).filter(value => typeof value === "string");
  const chainMatched = verification.chainCheck.matched === true;
  const chainMismatch = verification.chainCheck.matched === false;
  const transactionStatuses = results.map(item => item?.status);
  const hasReceiptConflict = transactionStatuses.includes("inconsistent");
  const allReceiptPairsChecked = results.length > 0 &&
    transactionStatuses.every(status => status === "confirmed" || status === "canonicality-unavailable");
  const canonicalityStatuses = results.map(item => item?.canonicalityStatus);
  const hasCanonicalityConflict = canonicalityStatuses.includes("mismatch");
  const allCanonicalityMatched = results.length > 0 && canonicalityStatuses.every(status => status === "matched");
  const evidenceChecks = results.flatMap(item => Array.isArray(item?.evidenceChecks) ? item.evidenceChecks : []);
  const hasEvidenceConflict = evidenceChecks.some(item => item?.status === "mismatch");
  const allEvidenceMatched = evidenceChecks.length > 0 && evidenceChecks.every(item => item?.status === "matched");
  const checked = asCount(verification.coverage.checkedTransactions);
  const unique = asCount(verification.coverage.uniqueTransactionReferences);
  const notChecked = asCount(verification.coverage.notChecked);
  const coverageComplete = verification.coverage.truncated === false &&
    checked !== null && unique !== null && unique > 0 && notChecked === 0 && checked === unique;

  const checks = [
    check(
      "provider-chain",
      "RPC network identity",
      chainMismatch ? "conflicting" : chainMatched ? "verified" : "unknown",
      chainMismatch ? "The RPC endpoint returned a chain ID different from the dossier's selected network." :
        chainMatched ? "The RPC endpoint returned the expected chain ID." :
          "The endpoint's chain identity was not confirmed."
    ),
    check(
      "transaction-receipt-consistency",
      "Transaction and receipt consistency",
      hasReceiptConflict ? "conflicting" : allReceiptPairsChecked ? "verified" : "unknown",
      hasReceiptConflict ? "At least one transaction/receipt pair was inconsistent." :
        allReceiptPairsChecked ? "Every checked reference returned a mined transaction and receipt without a reported consistency conflict." :
          "Some references were pending, missing, unavailable, errored or absent; consistency is not established for the full set.",
      hashes
    ),
    check(
      "canonical-block",
      "Block hash comparison",
      hasCanonicalityConflict ? "conflicting" : allCanonicalityMatched ? "verified" : "unknown",
      hasCanonicalityConflict ? "At least one receipt block hash differs from the block returned by the configured RPC endpoint at that height." :
        allCanonicalityMatched ? "Every checked transaction's receipt block hash matches the block returned by the configured RPC endpoint at that height." :
          "Canonical block comparison is incomplete or unavailable for one or more references.",
      hashes
    ),
    check(
      "dossier-observation-correlation",
      "Dossier observation correlation",
      hasEvidenceConflict ? "conflicting" : allEvidenceMatched ? "verified" : "unknown",
      hasEvidenceConflict ? "At least one checkable dossier observation conflicts with the fetched transaction or receipt." :
        allEvidenceMatched ? "Every checkable observation in the verification result matched its fetched transaction or receipt." :
          "At least one observation was not checkable, or no checkable observation was supplied."
    ),
    check(
      "reference-coverage",
      "Transaction-reference coverage",
      coverageComplete ? "verified" : "unknown",
      coverageComplete ? "Every transaction reference in the dossier was included in this verification run." :
        "Coverage is incomplete, truncated, or cannot be established. Unchecked references remain unknown.",
      hashes
    )
  ];

  const overall = summarize(checks);
  const perTransaction = results.map(result => {
    const items = transactionChecks(result);
    return {
      transactionHash: typeof result?.transactionHash === "string" ? result.transactionHash : null,
      status: summarize(items).status,
      checks: items
    };
  });

  return {
    schema: CONFIDENCE_SCHEMA,
    method: "deterministic-evidence-quality-rules-v1",
    assessedAt: typeof verification.observedAt === "string" ? verification.observedAt : null,
    provider: typeof verification.provider === "string" ? verification.provider : null,
    providerName: typeof verification.providerName === "string" ? verification.providerName : null,
    subject: isObject(verification.subject) ? verification.subject : null,
    assessment: overall.status,
    summary: {
      verifiedDimensions: overall.counts.verified,
      conflictingDimensions: overall.counts.conflicting,
      unknownDimensions: overall.counts.unknown,
      dimensionsAssessed: checks.length,
      transactionReferences: unique,
      checkedTransactions: checked,
      uncheckedTransactions: notChecked
    },
    checks,
    transactions: perTransaction,
    limitations: [
      "This assessment describes evidence quality and consistency, not wallet, contract or transaction risk.",
      "A matching block hash is a point-in-time observation from one configured RPC provider, not a consensus or finality proof.",
      "SHA-256 integrity, structural validity and RPC agreement do not authenticate authorship, address identity, intent, ownership or token legitimacy.",
      "Unknown means not established by the available evidence; it must not be interpreted as a clean result.",
      "A conflicting check identifies a discrepancy requiring analyst review; it does not by itself prove malicious activity."
    ]
  };
}
