import { buildEvidenceTimeline } from "./timeline.js";

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, character => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[character]);
}

function downloadJson(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function mountEvidenceTimeline(container, reports, threatReport) {
  const panel = document.createElement("section");
  panel.className = "notice";
  panel.style.marginTop = "16px";
  panel.innerHTML = `
    <strong>UNIFIED EVIDENCE TIMELINE · BLOCK / LOG ORDER</strong>
    <p class="hint">Combines imported transactions, ERC-1967 changes and decoded token receipt logs. Missing timestamps stay unknown; this is not a reconstructed full-chain history.</p>
    <div class="graph-controls">
      <select data-filter="chain" aria-label="Timeline chain filter"><option value="all">All chains</option></select>
      <input data-filter="address" placeholder="Optional EVM address" aria-label="Timeline address filter">
      <input data-filter="from" placeholder="From block (decimal / 0x)" aria-label="Timeline first block">
      <input data-filter="to" placeholder="To block (decimal / 0x)" aria-label="Timeline last block">
      <button type="button" data-action="build">Build timeline</button>
    </div>
    <div class="graph-summary" data-role="summary"></div>
    <div class="graph-list" data-role="events"><div class="empty">Building evidence timeline…</div></div>
    <div class="hint">Coverage: imported case reports and receipt logs only. A timeline event is an observed record, not proof of ownership, causation, token continuity or malicious intent.</div>
  `;
  container.appendChild(panel);

  const chain = panel.querySelector('[data-filter="chain"]');
  const address = panel.querySelector('[data-filter="address"]');
  const from = panel.querySelector('[data-filter="from"]');
  const to = panel.querySelector('[data-filter="to"]');
  const summary = panel.querySelector('[data-role="summary"]');
  const events = panel.querySelector('[data-role="events"]');
  const chains = [...new Set(reports.map(report => String(report.chainId || report.network?.chainId || "unknown").toLowerCase()))].sort();
  for (const value of chains) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    chain.appendChild(option);
  }

  let currentTimeline = null;
  const render = () => {
    try {
      currentTimeline = buildEvidenceTimeline(reports, {
        tokenTransfers: threatReport.tokenTransfers,
        chainId: chain.value === "all" ? null : chain.value,
        address: address.value.trim() || null,
        fromBlock: from.value.trim() || null,
        toBlock: to.value.trim() || null,
        maxEvents: 500
      });
      summary.innerHTML = "";
      for (const label of [
        currentTimeline.totalMatchedEventCount + " matched event(s)",
        currentTimeline.includedEventCount + " shown",
        currentTimeline.filters.chainId || "All chains"
      ]) {
        const item = document.createElement("span");
        item.textContent = label;
        summary.appendChild(item);
      }
      const cards = currentTimeline.events.map(event => {
        const card = document.createElement("div");
        card.className = "graph-edge";
        const title = document.createElement("b");
        title.textContent = event.eventType.toUpperCase().replaceAll("-", " ") + " · chain " + event.chainId;
        card.appendChild(title);
        const details = document.createElement("small");
        details.textContent = "Block " + (event.blockNumber || "unknown") +
          (event.logIndex ? " · log " + event.logIndex : "") +
          (event.transactionIndex ? " · tx index " + event.transactionIndex : "");
        card.appendChild(details);
        const timestamp = document.createElement("small");
        timestamp.textContent = "Timestamp: " + (event.timestamp || "Not present in imported evidence");
        card.appendChild(timestamp);
        if (event.from || event.to) {
          const parties = document.createElement("code");
          parties.textContent = (event.from || "unknown") + " → " + (event.to || "unknown");
          card.appendChild(parties);
        }
        for (const [label, value] of [
          ["Event address", event.address],
          ["Contract / implementation", event.contract],
          ["Transaction", event.transactionHash],
          ["Case", event.caseSubject],
          ["Evidence", JSON.stringify(event.evidence)]
        ]) {
          if (!value) continue;
          const line = document.createElement("small");
          line.textContent = label + ": " + value;
          card.appendChild(line);
        }
        return card;
      });
      events.replaceChildren(...cards);
      if (!cards.length) events.innerHTML = '<div class="empty">No timeline events match these filters.</div>';
      if (currentTimeline.truncated) {
        const note = document.createElement("div");
        note.className = "hint";
        note.textContent = "Display capped at 500 events; the export contains this same bounded result.";
        events.appendChild(note);
      }
      const exportButton = document.createElement("button");
      exportButton.type = "button";
      exportButton.textContent = "Export filtered evidence timeline JSON ↓";
      exportButton.style.marginTop = "12px";
      exportButton.addEventListener("click", () => downloadJson(
        { ...currentTimeline, exportedAt: new Date().toISOString() },
        "sentinel-evidence-timeline-" + new Date().toISOString().replace(/[:.]/g, "-") + ".json"
      ));
      events.appendChild(exportButton);
    } catch (error) {
      currentTimeline = null;
      summary.replaceChildren();
      events.innerHTML = '<div class="error">' + escapeHtml(error.message) + "</div>";
    }
  };

  panel.querySelector('[data-action="build"]').addEventListener("click", render);
  render();
  return { panel, refresh: render, get result() { return currentTimeline; } };
}
