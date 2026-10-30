import { verifyInvestigationDossierSources } from "./investigation-source-verification.js";
import { buildEvidenceConfidenceAssessment } from "./evidence-confidence.js";

const HASH = /^0x[0-9a-f]{64}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const STATUS_LABELS = { verified: "CORROBORATED", conflicting: "DISCREPANCY", unknown: "UNVERIFIED" };
const OVERALL_LABELS = {
  corroborated: "Corroborated",
  "partially-corroborated": "Partially corroborated",
  inconclusive: "Inconclusive",
  conflicting: "Conflicting evidence"
};
const CHAIN_NAMES = { "0x1": "Ethereum", "0x38": "BNB Chain", "0x89": "Polygon" };

function addReference(group, hash, entry = {}) {
  if (typeof hash !== "string" || !HASH.test(hash)) return;
  const normalized = hash.toLowerCase();
  const item = {
    kind: entry.kind || "case-transaction-reference",
    transactionHash: normalized,
    blockNumber: entry.blockNumber ?? null,
    logIndex: entry.logIndex ?? null,
    record: entry.record || {}
  };
  const key = [normalized, item.kind, item.logIndex ?? ""].join(":");
  if (!group.seen.has(key)) {
    group.seen.add(key);
    group.timeline.push(item);
    group.sourceReferences.push(normalized);
  }
}

/** Adapt an exported multi-case dossier into separate, chain-scoped RPC inputs. */
export function buildSourceVerificationDossiers(dossier) {
  if (!dossier || dossier.schema !== "sentinel.investigation-dossier.v1" ||
      !Array.isArray(dossier.cases)) {
    throw new TypeError("A SENTINEL multi-case investigation dossier is required");
  }
  const groups = new Map();
  const getGroup = (chainId, subject) => {
    if (typeof chainId !== "string" || !chainId.trim() ||
        typeof subject !== "string" || !ADDRESS.test(subject)) return null;
    const id = chainId.toLowerCase();
    if (!groups.has(id)) groups.set(id, {
      schema: "sentinel.investigation-intelligence.v1",
      subject: { chainId: id, address: subject.toLowerCase() },
      timeline: [], sourceReferences: [], seen: new Set()
    });
    return groups.get(id);
  };

  for (const report of dossier.cases) {
    const transactionObservation = (report?.observations || []).find(item =>
      item?.kind === "transaction" && item.value && HASH.test(item.value.hash || ""));
    const candidateAddress = ADDRESS.test(report?.subject || "")
      ? report.subject
      : [transactionObservation?.value?.from, transactionObservation?.value?.to]
          .find(value => typeof value === "string" && ADDRESS.test(value));
    const group = getGroup(report?.chainId || report?.network?.chainId, candidateAddress);
    if (!group) continue;
    if (report.subjectType === "transaction") {
      addReference(group, report.subject, {
        kind: "observed-transaction-flow",
        blockNumber: transactionObservation?.value?.blockNumber ?? report.provenance?.blockNumber,
        record: { from: transactionObservation?.value?.from, to: transactionObservation?.value?.to }
      });
    }
    for (const observation of report.observations || []) {
      if (observation?.kind === "transaction" && observation.value) {
        addReference(group, observation.value.hash, {
          kind: "observed-transaction-flow",
          blockNumber: observation.value.blockNumber,
          record: { from: observation.value.from, to: observation.value.to }
        });
      }
      if (observation?.kind === "erc1967-events") {
        for (const event of observation.events || []) {
          addReference(group, event?.transactionHash, {
            kind: "upgrade-event", blockNumber: event?.blockNumber, logIndex: event?.logIndex
          });
        }
      }
    }
  }

  for (const transfer of dossier.threatIntelligence?.tokenTransfers || []) {
    const group = getGroup(transfer?.chainId, transfer?.from || transfer?.to);
    if (!group) continue;
    addReference(group, transfer.transactionHash, {
      kind: "observed-token-transfer-log",
      blockNumber: transfer.blockNumber,
      logIndex: transfer.logIndex,
      record: { from: transfer.from, to: transfer.to,
        evidence: { token: transfer.token, amountRaw: transfer.amountRaw } }
    });
  }

  return [...groups.values()].filter(group => group.sourceReferences.length > 0)
    .map(({ seen, ...group }) => group);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function downloadAssessments(assessments) {
  const bundle = {
    schema: "sentinel.evidence-confidence-bundle.v1",
    exportedAt: new Date().toISOString(),
    assessments
  };
  const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = el("a");
  link.href = url;
  link.download = "sentinel-evidence-assessment-" +
    new Date().toISOString().replace(/[:.]/g, "-") + ".json";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderAssessment(output, chainId, assessment, verification) {
  const card = el("article", "ec-chain-card");
  const header = el("div", "ec-chain-head");
  const identity = el("div", "ec-chain-identity");
  identity.append(
    el("span", "ec-chain-kicker", "NETWORK"),
    el("h3", "", CHAIN_NAMES[chainId] || "EVM chain " + chainId),
    el("span", "ec-chain-id", "Chain ID " + chainId)
  );
  const state = el("span", "ec-overall ec-overall-" + assessment.assessment,
    OVERALL_LABELS[assessment.assessment] || assessment.assessment);
  header.append(identity, state);
  card.appendChild(header);

  const summary = assessment.summary;
  const stats = el("div", "ec-stats");
  [
    ["Verified", summary.verifiedDimensions, "verified"],
    ["Discrepancies", summary.conflictingDimensions, "conflicting"],
    ["Unverified", summary.unknownDimensions, "unknown"]
  ].forEach(([label, value, kind]) => {
    const stat = el("div", "ec-stat ec-stat-" + kind);
    stat.append(el("strong", "", value), el("span", "", label));
    stats.appendChild(stat);
  });
  card.appendChild(stats);

  const checks = el("div", "ec-checks");
  for (const item of assessment.checks) {
    const row = el("div", "ec-check ec-check-" + item.status);
    const marker = el("span", "ec-check-marker", item.status === "verified" ? "✓" :
      item.status === "conflicting" ? "!" : "—");
    const body = el("div", "ec-check-body");
    body.append(el("strong", "", item.label), el("p", "", item.detail));
    if (item.references.length) {
      body.appendChild(el("small", "ec-reference", item.references.length +
        " transaction reference(s) linked"));
    }
    row.append(marker, body, el("span", "ec-check-status",
      STATUS_LABELS[item.status] || item.status.toUpperCase()));
    checks.appendChild(row);
  }
  card.appendChild(checks);

  const meta = el("div", "ec-meta");
  meta.append(
    el("span", "", summary.checkedTransactions + " / " + summary.transactionReferences + " references checked"),
    el("span", "", "RPC · " + (verification.providerName || "Configured provider")),
    el("span", "", "Observed · " + (verification.observedAt || "timestamp unavailable"))
  );
  card.appendChild(meta);
  output.appendChild(card);
}

export function mountEvidenceConfidencePanel(container, dossier) {
  if (!(container instanceof HTMLElement)) throw new TypeError("A DOM container is required");
  const sourceDossiers = buildSourceVerificationDossiers(dossier);
  container.querySelector("#evidence-confidence-panel")?.remove();

  const panel = el("section", "ec-panel");
  panel.id = "evidence-confidence-panel";
  const top = el("div", "ec-topline");
  top.append(el("div", "ec-eyebrow", "EVIDENCE QUALITY / ENGINE 01"),
    el("span", "ec-readonly", "● READ ONLY"));
  const titleRow = el("div", "ec-title-row");
  const titleBlock = el("div");
  titleBlock.append(el("h2", "ec-title", "Evidence confidence"),
    el("p", "ec-description", "Independent source checks for transaction references found in your imported investigation cases."));
  titleRow.append(titleBlock, el("span", "ec-version", "MULTICHAIN"));
  const context = el("div", "ec-context");
  context.append(
    el("span", "", sourceDossiers.length + " network group(s)"),
    el("span", "", sourceDossiers.reduce((sum, item) => sum + item.sourceReferences.length, 0) + " transaction reference(s)"),
    el("span", "", "No score · No verdict")
  );
  const controls = el("div", "ec-controls");
  const verifyButton = el("button", "ec-run", "Run source verification");
  verifyButton.type = "button";
  verifyButton.disabled = sourceDossiers.length === 0;
  const status = el("p", "ec-status", sourceDossiers.length
    ? "Ready. RPC requests only start when you run verification."
    : "No verifiable transaction hashes found. Import case reports containing transaction references.");
  const output = el("div", "ec-results");
  const footer = el("div", "ec-limit",
    "Interpretation boundary: a single RPC provider offers a point-in-time observation, not consensus or finality proof. A discrepancy is a review signal, not proof of malicious activity. UNKNOWN is not a clean result.");
  controls.append(verifyButton);
  panel.append(top, titleRow, context, controls, status, output, footer);

  verifyButton.addEventListener("click", async () => {
    verifyButton.disabled = true;
    verifyButton.textContent = "Verifying source evidence…";
    status.textContent = "Checking each chain against its configured read-only RPC endpoint.";
    output.replaceChildren();
    const assessments = [];
    const failures = [];

    for (const sourceDossier of sourceDossiers) {
      const chainId = sourceDossier.subject.chainId;
      try {
        const verification = await verifyInvestigationDossierSources(sourceDossier);
        const assessment = buildEvidenceConfidenceAssessment(verification);
        assessments.push({ chainId, assessment, verification });
        renderAssessment(output, chainId, assessment, verification);
      } catch (error) {
        failures.push({ chainId, error: error?.message || "RPC verification failed" });
        const failed = el("article", "ec-chain-card ec-failed");
        failed.append(el("strong", "", (CHAIN_NAMES[chainId] || "EVM chain " + chainId) + " · NOT VERIFIED"),
          el("p", "", error?.message || "RPC verification failed. No positive assessment was produced."));
        output.appendChild(failed);
      }
    }

    if (assessments.length) {
      const exportRow = el("div", "ec-export-row");
      const exportButton = el("button", "ec-export", "Export assessment bundle ↓");
      exportButton.type = "button";
      exportButton.addEventListener("click", () => downloadAssessments(assessments));
      exportRow.appendChild(exportButton);
      output.appendChild(exportRow);
    }
    status.textContent = assessments.length + " network group(s) assessed · " +
      failures.length + " not verified. Failed groups are not treated as clean.";
    verifyButton.disabled = false;
    verifyButton.textContent = "Run source verification again";
  });

  container.appendChild(panel);
  return panel;
}
