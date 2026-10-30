import { verifyInvestigationDossierSources } from "./investigation-source-verification.js";
import { buildEvidenceConfidenceAssessment } from "./evidence-confidence.js";

const HASH = /^0x[0-9a-f]{64}$/i;
const STATUS_LABELS = { verified: "VERIFIED", conflicting: "CONFLICTING", unknown: "UNKNOWN" };
const OVERALL_LABELS = {
  corroborated: "CORROBORATED",
  "partially-corroborated": "PARTIALLY CORROBORATED",
  inconclusive: "INCONCLUSIVE",
  conflicting: "CONFLICTING"
};

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

/**
 * Adapt the exported multi-case dossier into the single-chain input contract
 * used by the existing read-only RPC verifier. References remain chain-scoped.
 */
export function buildSourceVerificationDossiers(dossier) {
  if (!dossier || dossier.schema !== "sentinel.investigation-dossier.v1" ||
      !Array.isArray(dossier.cases)) {
    throw new TypeError("A SENTINEL multi-case investigation dossier is required");
  }
  const groups = new Map();
  const getGroup = (chainId, subject) => {
    if (typeof chainId !== "string" || !chainId.trim() ||
        typeof subject !== "string" || !subject.trim()) return null;
    const id = chainId.toLowerCase();
    if (!groups.has(id)) groups.set(id, {
      schema: "sentinel.investigation-intelligence.v1",
      subject: { chainId: id, address: subject.toLowerCase() },
      timeline: [], sourceReferences: [], seen: new Set()
    });
    return groups.get(id);
  };

  for (const report of dossier.cases) {
    const group = getGroup(report?.chainId || report?.network?.chainId, report?.subject);
    if (!group) continue;
    if (report.subjectType === "transaction") {
      addReference(group, report.subject, {
        kind: "observed-transaction-flow",
        blockNumber: report.provenance?.blockNumber
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
            kind: "upgrade-event",
            blockNumber: event?.blockNumber,
            logIndex: event?.logIndex
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
      record: {
        from: transfer.from,
        to: transfer.to,
        evidence: { token: transfer.token, amountRaw: transfer.amountRaw }
      }
    });
  }

  return [...groups.values()]
    .filter(group => group.sourceReferences.length > 0)
    .map(({ seen, ...group }) => group);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function downloadAssessments(assessments) {
  const blob = new Blob([JSON.stringify({
    schema: "sentinel.evidence-confidence-bundle.v1",
    exportedAt: new Date().toISOString(),
    assessments
  }, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "sentinel-evidence-confidence-" +
    new Date().toISOString().replace(/[:.]/g, "-") + ".json";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Mount an explicitly user-triggered, read-only, multi-chain verification panel. */
export function mountEvidenceConfidencePanel(container, dossier) {
  if (!(container instanceof HTMLElement)) throw new TypeError("A DOM container is required");
  const sourceDossiers = buildSourceVerificationDossiers(dossier);
  container.querySelector("#evidence-confidence-panel")?.remove();

  const panel = el("section", "notice");
  panel.id = "evidence-confidence-panel";
  panel.style.marginTop = "16px";
  panel.style.background = "linear-gradient(145deg,#101f2b,#0b151f)";
  panel.style.borderColor = "#326176";
  const heading = el("strong", "", "EVIDENCE CONFIDENCE ENGINE");
  const description = el("p", "hint",
    "Verify transaction references from imported cases against their configured read-only RPC endpoints. " +
    "Each chain is assessed separately; no risk score or maliciousness verdict is generated.");
  const actionRow = el("div", "graph-controls");
  actionRow.style.marginTop = "12px";
  const verifyButton = el("button", "", "Verify source references →");
  verifyButton.type = "button";
  verifyButton.disabled = sourceDossiers.length === 0;
  const status = el("div", "hint", sourceDossiers.length
    ? sourceDossiers.length + " chain group(s) · " +
      sourceDossiers.reduce((sum, item) => sum + item.sourceReferences.length, 0) +
      " transaction reference(s) ready. No RPC request has been made."
    : "No verifiable transaction hashes were found in the imported cases.");
  status.style.marginTop = "12px";
  const output = el("div");
  output.style.marginTop = "12px";

  verifyButton.addEventListener("click", async () => {
    verifyButton.disabled = true;
    verifyButton.textContent = "Verifying against RPC…";
    status.textContent = "Querying configured providers, separately for each chain.";
    output.replaceChildren();
    const assessments = [];
    const failures = [];

    for (const sourceDossier of sourceDossiers) {
      try {
        const verification = await verifyInvestigationDossierSources(sourceDossier);
        const assessment = buildEvidenceConfidenceAssessment(verification);
        assessments.push({ chainId: sourceDossier.subject.chainId, assessment, verification });
        const section = el("section", "graph-edge");
        section.appendChild(el("b", "", "CHAIN " + sourceDossier.subject.chainId +
          " · " + (OVERALL_LABELS[assessment.assessment] || assessment.assessment.toUpperCase())));
        const summary = assessment.summary;
        section.appendChild(el("small", "",
          summary.verifiedDimensions + " verified · " + summary.conflictingDimensions +
          " conflicting · " + summary.unknownDimensions + " unknown dimensions"));
        for (const item of assessment.checks) {
          const card = el("div", "kv");
          card.appendChild(el("span", "", (STATUS_LABELS[item.status] || item.status.toUpperCase()) +
            " · " + item.label));
          card.appendChild(el("code", "", item.detail));
          section.appendChild(card);
        }
        section.appendChild(el("small", "",
          summary.checkedTransactions + " / " + summary.transactionReferences +
          " transaction references checked · provider " + (verification.providerName || "configured RPC")));
        output.appendChild(section);
      } catch (error) {
        failures.push({ chainId: sourceDossier.subject.chainId, error: error?.message || "RPC failure" });
        const failure = el("div", "graph-edge");
        failure.appendChild(el("b", "", "CHAIN " + sourceDossier.subject.chainId + " · NOT VERIFIED"));
        failure.appendChild(el("small", "", error?.message || "RPC verification failed"));
        output.appendChild(failure);
      }
    }

    if (assessments.length) {
      const exportButton = el("button", "", "Export evidence assessment JSON ↓");
      exportButton.type = "button";
      exportButton.style.marginTop = "12px";
      exportButton.addEventListener("click", () => downloadAssessments(assessments));
      output.appendChild(exportButton);
    }
    output.appendChild(el("p", "hint",
      "Limits: one RPC provider per chain; point-in-time block comparison; no consensus/finality proof, " +
      "identity attribution, ownership inference or maliciousness verdict. UNKNOWN is not a clean result."));
    status.textContent = assessments.length + " chain group(s) verified · " +
      failures.length + " failed. Failed groups are not treated as clean.";
    verifyButton.disabled = false;
    verifyButton.textContent = "Verify source references →";
  });

  actionRow.appendChild(verifyButton);
  panel.append(heading, description, actionRow, status, output);
  container.appendChild(panel);
  return panel;
}
