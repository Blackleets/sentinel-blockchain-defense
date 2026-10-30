import { verifyInvestigationDossierSources } from "./investigation-source-verification.js";
import { buildEvidenceConfidenceAssessment } from "./evidence-confidence.js";

const STATUS_LABELS = {
  verified: "VERIFIED",
  conflicting: "CONFLICTING",
  unknown: "UNKNOWN"
};
const OVERALL_LABELS = {
  corroborated: "CORROBORATED",
  "partially-corroborated": "PARTIALLY CORROBORATED",
  inconclusive: "INCONCLUSIVE",
  conflicting: "CONFLICTING"
};

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function downloadAssessment(assessment) {
  const blob = new Blob([JSON.stringify(assessment, null, 2)], { type: "application/json" });
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

/**
 * Mount an explicitly user-triggered, read-only source verification panel.
 * No RPC request is made until the analyst presses the verify button.
 */
export function mountEvidenceConfidencePanel(container, dossier) {
  if (!(container instanceof HTMLElement)) throw new TypeError("A DOM container is required");
  if (!dossier || dossier.schema !== "sentinel.investigation-intelligence.v1") {
    throw new TypeError("A valid SENTINEL investigation dossier is required");
  }

  container.querySelector("#evidence-confidence-panel")?.remove();

  const panel = element("section", "notice");
  panel.id = "evidence-confidence-panel";
  panel.style.marginTop = "16px";
  panel.style.background = "linear-gradient(145deg,#101f2b,#0b151f)";
  panel.style.borderColor = "#326176";

  const heading = element("strong", "", "EVIDENCE CONFIDENCE ENGINE");
  const description = element("p", "hint",
    "Verify dossier transaction references against the configured read-only RPC endpoint. " +
    "This is an evidence-quality assessment, not a wallet or contract risk score.");
  const actionRow = element("div", "graph-controls");
  actionRow.style.marginTop = "12px";

  const verifyButton = element("button", "", "Verify source references →");
  verifyButton.type = "button";
  const status = element("div", "hint", "Not verified yet. No RPC request has been made.");
  status.style.marginTop = "12px";
  const output = element("div");
  output.style.marginTop = "12px";

  verifyButton.addEventListener("click", async () => {
    verifyButton.disabled = true;
    verifyButton.textContent = "Verifying against RPC…";
    status.textContent = "Querying the configured provider. This may take a moment.";
    output.replaceChildren();

    try {
      const verification = await verifyInvestigationDossierSources(dossier);
      const assessment = buildEvidenceConfidenceAssessment(verification);
      const overall = element("div", "graph-summary");
      const overallPill = element("span", "", "ASSESSMENT · " +
        (OVERALL_LABELS[assessment.assessment] || assessment.assessment.toUpperCase()));
      const dimensions = assessment.summary;
      overall.append(
        overallPill,
        element("span", "", dimensions.verifiedDimensions + " verified"),
        element("span", "", dimensions.conflictingDimensions + " conflicting"),
        element("span", "", dimensions.unknownDimensions + " unknown")
      );
      output.appendChild(overall);

      const list = element("div", "graph-list");
      for (const item of assessment.checks) {
        const card = element("article", "graph-edge");
        const state = STATUS_LABELS[item.status] || item.status.toUpperCase();
        card.appendChild(element("b", "", state + " · " + item.label));
        card.appendChild(element("small", "", item.detail));
        if (item.references.length) {
          const refs = item.references.slice(0, 5).join(" · ");
          card.appendChild(element("small", "", "Transaction references: " + refs +
            (item.references.length > 5 ? " · +" + (item.references.length - 5) + " more" : "")));
        }
        list.appendChild(card);
      }
      output.appendChild(list);

      const coverage = dimensions.transactionReferences === null
        ? "Reference count unavailable"
        : dimensions.checkedTransactions + " / " + dimensions.transactionReferences +
          " transaction references checked";
      output.appendChild(element("p", "hint", coverage));
      output.appendChild(element("p", "hint",
        "Provider: " + (verification.providerName || "configured RPC") +
        " · Observed at: " + (verification.observedAt || "unknown")));
      const limitations = element("div", "hint",
        "Limits: one RPC provider; point-in-time block comparison; no consensus/finality proof, " +
        "identity attribution, ownership inference or maliciousness verdict. UNKNOWN is not a clean result.");
      output.appendChild(limitations);

      const exportButton = element("button", "", "Export evidence assessment JSON ↓");
      exportButton.type = "button";
      exportButton.style.marginTop = "12px";
      exportButton.addEventListener("click", () => downloadAssessment(assessment));
      output.appendChild(exportButton);

      status.textContent = "Verification completed. Review each dimension and its limitations.";
    } catch (error) {
      status.textContent = "Verification failed: " + (error?.message || "Unknown RPC or dossier error") +
        ". No positive assessment was produced.";
    } finally {
      verifyButton.disabled = false;
      verifyButton.textContent = "Verify source references →";
    }
  });

  actionRow.appendChild(verifyButton);
  panel.append(heading, description, actionRow, status, output);
  container.appendChild(panel);
  return panel;
}
