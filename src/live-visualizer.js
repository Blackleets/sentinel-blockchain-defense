import { fetchBlockscoutAddressTransfers, fetchBlockscoutAddressActivity, BLOCKSCOUT_ENDPOINTS } from "./blockscout-provider.js";
import { traceFundPaths } from "./fund-tracer.js";
import { deriveLivePatterns } from "./live-patterns.js";
export function bindNetworkRpc(rpc, network) {
  if (typeof rpc !== "function") throw new TypeError("A JSON-RPC function is required");
  if (!network || typeof network.chainId !== "string" || typeof network.rpc !== "string" || typeof network.explorer !== "string") {
    throw new TypeError("A complete selected network descriptor is required");
  }
  return (method, params = []) => rpc(method, params, network);
}

const ADDRESS = /^0x[0-9a-f]{40}$/i;
const HASH = /^0x[0-9a-f]{64}$/i;
export const ERC20_TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

function normalizeAddress(value) {
  return typeof value === "string" && ADDRESS.test(value) ? value.toLowerCase() : null;
}
function compareHex(a, b) {
  const left = BigInt(a), right = BigInt(b);
  return left < right ? -1 : left > right ? 1 : 0;
}
function addressTopic(value) {
  const address = normalizeAddress(value);
  if (!address) throw new TypeError("A valid EVM address is required");
  return "0x" + address.slice(2).padStart(64, "0");
}

/** Decode only the standard indexed ERC-20 Transfer event shape; token legitimacy is not inferred. */
export function decodeTransferLogs(logs, { chainId } = {}) {
  if (!Array.isArray(logs)) throw new TypeError("RPC logs must be an array");
  const seen = new Set(), transfers = [];
  for (const log of logs) {
    if (!log || log.removed === true || !Array.isArray(log.topics) || log.topics.length !== 3 ||
        String(log.topics[0]).toLowerCase() !== ERC20_TRANSFER_TOPIC ||
        !/^0x0{24}[0-9a-f]{40}$/i.test(log.topics[1] || "") ||
        !/^0x0{24}[0-9a-f]{40}$/i.test(log.topics[2] || "") ||
        !HASH.test(log.transactionHash || "") || !/^0x[0-9a-f]+$/i.test(log.blockNumber || "") ||
        !/^0x[0-9a-f]+$/i.test(log.logIndex || "") || !/^0x[0-9a-f]{64}$/i.test(log.data || "")) continue;
    const from = normalizeAddress("0x" + String(log.topics[1]).slice(-40));
    const to = normalizeAddress("0x" + String(log.topics[2]).slice(-40));
    const token = normalizeAddress(log.address);
    if (!from || !to || !token) continue;
    const key = log.transactionHash.toLowerCase() + "|" + log.logIndex.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    transfers.push({
      chainId: chainId == null ? null : String(chainId).toLowerCase(),
      token, from, to, amountRaw: BigInt(log.data).toString(),
      transactionHash: log.transactionHash.toLowerCase(),
      blockNumber: log.blockNumber.toLowerCase(),
      logIndex: log.logIndex.toLowerCase()
    });
  }
  return transfers.sort((a,b) => compareHex(a.blockNumber,b.blockNumber) ||
    compareHex(a.logIndex,b.logIndex) || a.transactionHash.localeCompare(b.transactionHash));
}

/** Create a bounded, address-centred graph from live RPC receipt logs. */
export function buildLiveTransferGraph(transfers, { address, chainId, scannedFrom, scannedTo, hops = 1, maxEdges = 160, maxNodes = 40 } = {}) {
  const origin = normalizeAddress(address);
  if (!origin) throw new TypeError("A valid EVM address is required");
  if (!Array.isArray(transfers)) throw new TypeError("Transfers must be an array");
  if (typeof chainId !== "string" || !/^0x[0-9a-f]+$/i.test(chainId)) throw new TypeError("A valid hexadecimal chain ID is required");
  if (!Number.isInteger(hops) || hops < 1 || hops > 2) throw new RangeError("hops must be 1 or 2");
  if (!Number.isInteger(maxEdges) || maxEdges < 1 || maxEdges > 500) throw new RangeError("maxEdges must be between 1 and 500");
  if (!Number.isInteger(maxNodes) || maxNodes < 2 || maxNodes > 100) throw new RangeError("maxNodes must be between 2 and 100");
  const all = transfers.filter(item => item && item.chainId === chainId.toLowerCase()).slice().sort((a,b) =>
    compareHex(a.blockNumber,b.blockNumber) || compareHex(a.logIndex,b.logIndex));
  const reachable = new Set([origin]);
  const hopDistance = new Map([[origin, 0]]);
  let frontier = new Set([origin]);
  const candidates = new Map();
  let nodeCapReached = false;
  for (let depth = 1; depth <= hops && frontier.size; depth++) {
    const next = new Set();
    for (const edge of all) {
      if (!frontier.has(edge.from) && !frontier.has(edge.to)) continue;
      const other = frontier.has(edge.from) ? edge.to : edge.from;
      if (!reachable.has(other)) {
        if (reachable.size + next.size >= maxNodes) { nodeCapReached = true; continue; }
        next.add(other);
      }
      candidates.set(edge.transactionHash + "|" + edge.logIndex, edge);
    }
    for (const item of next) { reachable.add(item); hopDistance.set(item, depth); }
    frontier = next;
  }
  const ordered = [...candidates.values()].sort((a,b) => compareHex(a.blockNumber,b.blockNumber) ||
    compareHex(a.logIndex,b.logIndex) || a.transactionHash.localeCompare(b.transactionHash));
  const edges = ordered.slice(-maxEdges);
  const addresses = new Set([origin]);
  for (const edge of edges) { addresses.add(edge.from); addresses.add(edge.to); }
  const nodes = [...addresses].map(addressValue => ({
    address: addressValue, origin: addressValue === origin, hop: hopDistance.get(addressValue) ?? null,
    incomingCount: edges.filter(edge => edge.to === addressValue).length,
    outgoingCount: edges.filter(edge => edge.from === addressValue).length
  })).sort((a,b) => Number(b.origin)-Number(a.origin) || a.address.localeCompare(b.address));
  return {
    schema: "sentinel.live-transfer-graph.v1",
    chainId: chainId.toLowerCase(), origin, scannedFrom, scannedTo, hops,
    totalObservedEdges: ordered.length, edgeCount: edges.length, nodeCount: nodes.length,
    truncated: ordered.length > edges.length || nodeCapReached, nodes, edges,
    coverage: "bounded-live-rpc-transfer-event-logs",
    limitations: [
      "Edges are decoded Transfer-shaped logs returned by one public RPC provider; token legitimacy is not established.",
      "Only the displayed block window is queried. This is not a complete wallet history.",
      "Native transfers, internal calls, non-standard token events and cross-chain relationships are not included.",
      "A transfer event does not establish beneficial ownership, intent, risk or illicit activity.",
      "Two-hop expansion is capped at 8 first-hop counterparties and 40 graph nodes; results can be incomplete."
    ]
  };
}

export function formatTokenAmount(rawAmount, decimals) {
  if (typeof rawAmount !== "string" || !/^\d+$/.test(rawAmount)) return "Unknown amount";
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) return rawAmount + " (raw units)";
  const value = BigInt(rawAmount), divisor = 10n ** BigInt(decimals);
  const whole = value / divisor;
  if (decimals === 0) return whole.toString();
  const fraction = (value % divisor).toString().padStart(decimals, "0").replace(/0+$/, "");
  return fraction ? whole.toString() + "." + fraction : whole.toString();
}

export function decodeAbiString(value) {
  if (typeof value !== "string" || !/^0x[0-9a-f]*$/i.test(value) || value.length < 66) return null;
  const data = value.slice(2);
  try {
    const offset = Number(BigInt("0x" + data.slice(0, 64))) * 2;
    if (Number.isSafeInteger(offset) && offset >= 0 && offset + 64 <= data.length) {
      const length = Number(BigInt("0x" + data.slice(offset, offset + 64)));
      if (Number.isSafeInteger(length) && length >= 0 && length <= 256 && offset + 64 + length * 2 <= data.length) {
        const bytes = new Uint8Array(length);
        for (let i = 0; i < length; i++) bytes[i] = parseInt(data.slice(offset + 64 + i * 2, offset + 66 + i * 2), 16);
        const decoded = new TextDecoder().decode(bytes).replace(/\u0000+$/g, "").trim();
        if (decoded) return decoded;
      }
    }
    if (data.length === 64) {
      const bytes = new Uint8Array(32);
      for (let i = 0; i < 32; i++) bytes[i] = parseInt(data.slice(i * 2, i * 2 + 2), 16);
      const decoded = new TextDecoder().decode(bytes).replace(/\u0000+$/g, "").trim();
      return decoded || null;
    }
  } catch {}
  return null;
}

export function decodeTokenMetadata({ symbolResult, nameResult, decimalsResult } = {}) {
  let decimals = null;
  if (typeof decimalsResult === "string" && /^0x[0-9a-f]{64}$/i.test(decimalsResult)) {
    const parsed = Number(BigInt(decimalsResult));
    if (Number.isInteger(parsed) && parsed >= 0 && parsed <= 36) decimals = parsed;
  }
  return { symbol: decodeAbiString(symbolResult), name: decodeAbiString(nameResult), decimals };
}

async function fetchTokenMetadata(address, rpc) {
  const call = selector => rpc("eth_call", [{ to: address, data: selector }, "latest"]);
  const [symbolResult, nameResult, decimalsResult] = await Promise.all([
    call("0x95d89b41").catch(() => null),
    call("0x06fdde03").catch(() => null),
    call("0x313ce567").catch(() => null)
  ]);
  return decodeTokenMetadata({ symbolResult, nameResult, decimalsResult });
}

async function fetchMetadataBatch(addresses, rpc) {
  const metadata = new Map(), unique = [...new Set(addresses)].slice(0, 24);
  for (let i = 0; i < unique.length; i += 6) {
    const batch = await Promise.all(unique.slice(i, i + 6).map(async address => {
      try { return [address, await fetchTokenMetadata(address, rpc)]; }
      catch { return [address, { symbol: null, name: null, decimals: null }]; }
    }));
    for (const [address, value] of batch) metadata.set(address, value);
  }
  return metadata;
}
const short = value => value.slice(0, 8) + "…" + value.slice(-6);
const esc = value => String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
function point(index, total, width, height, hop = 1) {
  if (hop === 0) return { x: width/2, y: height/2 };
  const angle = index * (Math.PI*2/Math.max(1,total)) - Math.PI/2;
  const radius = Math.min(width,height) * (hop === 1 ? .27 : .41);
  return { x: width/2 + Math.cos(angle)*radius, y: height/2 + Math.sin(angle)*radius };
}

export function mountLiveVisualizer(container, { rpc, getNetwork }) {
  if (!container || typeof rpc !== "function" || typeof getNetwork !== "function") throw new TypeError("Visualizer requires a container, RPC function and network accessor");
  const panel = document.createElement("section");
  panel.className = "sentinel-live";
  panel.innerHTML = `
    <div class="sl-head"><div><div class="sl-kicker">SENTINEL / LIVE VISUALIZER</div><h2>Address relationship map</h2><p>Explore on-chain Transfer events around an address. Every edge links to its source transaction.</p></div><span class="sl-readonly">● READ ONLY</span></div>
    <form class="sl-controls"><input name="address" spellcheck="false" autocomplete="off" placeholder="Paste an EVM wallet or contract address" aria-label="Address to trace" required><label>History source <select name="source"><option value="rpc" selected>Live RPC · recent blocks</option><option value="indexed">Indexed ERC-20 history · Ethereum</option><option value="activity">Indexed activity · ETH + internal · Ethereum</option></select></label><label>Block window <select name="window"><option value="500">500</option><option value="2000" selected>2,000</option><option value="5000">5,000</option><option value="10000">10,000</option></select></label><label>Graph depth <select name="hops"><option value="1" selected>1 hop</option><option value="2">2 hops</option></select></label><button type="submit">Trace address ↗</button></form>
    <div class="sl-meta" data-role="status">Choose an address to build a live relationship map from recent ERC-20 Transfer logs.</div>
    <div class="sl-stats" data-role="stats"></div>
    <section class="sl-patterns" data-role="patterns"><div class="sl-patterns-head"><div class="sl-kicker">SENTINEL / TOPOLOGY INTELLIGENCE</div><strong>Patterns to review</strong></div><div data-role="pattern-results" class="sl-pattern-results">Patterns will be derived from the loaded evidence.</div><div data-role="pattern-note" class="sl-pattern-note"></div></section>
    <div class="sl-investigation-tools" data-role="investigation-tools" hidden><label>Flow <select data-role="flow-filter"><option value="all">All directions</option><option value="incoming">Incoming</option><option value="outgoing">Outgoing</option></select></label><label>Asset <select data-role="asset-filter"><option value="all">All assets</option></select></label><label>Find address <input data-role="node-search" type="search" placeholder="0x… or address fragment" autocomplete="off"></label><button type="button" data-role="locate-node">Locate node</button><button type="button" data-role="export-evidence">Export evidence JSON ↓</button></div>
    <div class="sl-layout"><div class="sl-canvas" data-role="canvas"><div class="sl-empty">Your graph will appear here</div></div><aside class="sl-inspector" data-role="inspector"><span class="sl-kicker">NODE INSPECTOR</span><strong>Select a node</strong><p>Address details and observed transfer evidence will appear here.</p></aside></div>
    <div class="sl-ledger" data-role="ledger"></div>
    <section class="sl-timeline" data-role="timeline" hidden><div class="sl-timeline-head"><div><div class="sl-kicker">INVESTIGATION TIMELINE</div><strong>Observed event sequence</strong></div><span data-role="timeline-count"></span></div><div class="sl-timeline-list" data-role="timeline-list"></div></section>
    <section class="sl-fund" aria-label="Fund Tracer"><div class="sl-kicker">SENTINEL / FUND TRACER</div><h3>Candidate fund routes</h3><p>Search the currently loaded evidence for amount-compatible paths. This does not prove the same funds moved between addresses.</p><div class="sl-fund-controls"><input data-role="fund-target" spellcheck="false" autocomplete="off" placeholder="Destination EVM address" aria-label="Destination address"><label>Maximum hops <select data-role="fund-depth"><option value="1">1</option><option value="2" selected>2</option><option value="3">3</option></select></label><button type="button" data-role="fund-run">Trace candidate routes ↗</button></div><div data-role="fund-results" class="sl-fund-results">Run an address trace first, then enter a destination to inspect candidate routes.</div></section>
    <div class="sl-foot">Coverage: bounded RPC window · ERC-20 Transfer-shaped logs only · single-provider observation · no attribution or risk verdict</div>
  `;
  const style = document.createElement("style");
  style.textContent = `
    .sentinel-live{margin:20px 0;padding:22px;border:1px solid #29495d;border-radius:18px;background:radial-gradient(ellipse at 82% 0%,rgba(39,133,155,.15),transparent 36%),linear-gradient(145deg,#101e2b,#08121d);color:#e8f3fa;box-shadow:0 18px 48px rgba(0,0,0,.2)}
    .sentinel-live *{box-sizing:border-box}.sl-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}.sl-kicker{font-size:9px;letter-spacing:.2em;font-weight:800;color:#6dd7e6}.sl-head h2{font-size:22px;margin:7px 0 4px;letter-spacing:-.035em}.sl-head p,.sl-inspector p{font-size:11px;line-height:1.6;color:#91a8ba;margin:0}.sl-readonly{white-space:nowrap;font-size:9px;letter-spacing:.12em;color:#8de0b9;border:1px solid #285e4b;border-radius:30px;padding:7px 10px;background:#10271f}
    .sl-controls{display:flex;gap:9px;margin:18px 0 10px;flex-wrap:wrap}.sl-controls input{flex:1;min-width:220px;background:#07111b;border:1px solid #294458;border-radius:9px;padding:12px;color:#e8f3fa}.sl-controls label{display:flex;align-items:center;gap:8px;color:#91a8ba;font-size:10px}.sl-controls select{background:#07111b;border:1px solid #294458;border-radius:9px;padding:10px;color:#e8f3fa}.sl-controls button{min-height:42px;padding:0 16px}.sl-meta{font-size:10px;color:#91a8ba;min-height:20px}.sl-stats{display:flex;gap:8px;flex-wrap:wrap;margin:13px 0}.sl-stat{border:1px solid #223c50;background:#091722;padding:8px 11px;border-radius:8px;color:#a9bdcb;font-size:10px}.sl-stat b{color:#e7f7ff;margin-right:4px}.sl-patterns{margin:12px 0;padding:13px;border:1px solid #29495d;border-radius:11px;background:#091722}.sl-patterns-head{display:flex;justify-content:space-between;gap:12px;align-items:center}.sl-patterns-head strong{font-size:11px;color:#dff6ff}.sl-pattern-results{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:8px;margin-top:10px}.sl-pattern-card{padding:10px;border:1px solid #31536a;border-radius:8px;background:#07131e}.sl-pattern-card strong{display:block;font-size:10px;color:#dff6ff}.sl-pattern-card small{display:block;font-size:9px;line-height:1.5;color:#91a8ba;margin-top:5px}.sl-pattern-note{font-size:9px;color:#91a8ba;line-height:1.5;margin-top:9px}
    .sl-layout{display:grid;grid-template-columns:minmax(0,1fr) 245px;gap:12px}.sl-canvas{position:relative;min-width:0;min-height:420px;border:1px solid #20394c;border-radius:12px;background:radial-gradient(circle at center,rgba(27,73,92,.18),transparent 54%),#07111b;overflow:hidden}.sl-canvas svg{width:100%;height:420px;display:block;touch-action:none;cursor:grab}.sl-canvas svg:active{cursor:grabbing}.sl-graph-tools{position:absolute;z-index:2;top:10px;right:10px;display:flex;gap:5px}.sl-graph-tools button{border:1px solid #31536a;background:#0b1c29;color:#cfe8f2;border-radius:7px;min-width:30px;height:29px;padding:0 8px;font-size:11px;cursor:pointer}.sl-graph-tools button:hover{border-color:#6dd7e6;background:#102b3a}.sl-edge{stroke:#367c91;stroke-opacity:.7;stroke-width:1.8;cursor:pointer;pointer-events:stroke}.sl-edge:hover,.sl-edge.is-selected{stroke:#f4c66b;stroke-opacity:1;stroke-width:3.5}.sl-edge-dot{fill:#73dce9}.sl-node{cursor:pointer;outline:none}.sl-node circle{fill:#123448;stroke:#58b9cc;stroke-width:1.5}.sl-node[data-origin="true"] circle{fill:#155c67;stroke:#8ce6ec;stroke-width:2.5}.sl-node text{fill:#c8dbe6;font:10px ui-monospace,monospace;text-anchor:middle}.sl-node:focus circle,.sl-node.is-selected circle{stroke:#f4c66b;stroke-width:3}.sl-empty{display:grid;place-items:center;min-height:420px;color:#71889a;font-size:11px}.sl-inspector{padding:15px;border:1px solid #20394c;border-radius:12px;background:#091722;min-width:0}.sl-inspector strong{display:block;font:11px ui-monospace,monospace;overflow-wrap:anywhere;margin:14px 0 8px;color:#e4f6ff}.sl-inspector a{color:#72d8e7;font-size:10px;overflow-wrap:anywhere}.sl-inspector .sl-kv{border-top:1px solid #1c3345;padding:8px 0;font-size:10px;color:#91a8ba}.sl-inspector .sl-kv b{display:block;color:#d9eaf3;margin-top:3px;overflow-wrap:anywhere}.sl-investigation-tools{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:12px 0;padding:10px;border:1px solid #20394c;border-radius:10px;background:#091722}.sl-investigation-tools[hidden],.sl-timeline[hidden]{display:none}.sl-investigation-tools label{display:flex;align-items:center;gap:7px;color:#91a8ba;font-size:10px}.sl-investigation-tools select,.sl-investigation-tools input,.sl-investigation-tools button{background:#102536;border:1px solid #31536a;border-radius:7px;padding:8px 10px;color:#d9edf6;font-size:10px}.sl-investigation-tools input{min-width:190px;outline:none}.sl-investigation-tools input:focus{border-color:#6dd7e6;box-shadow:0 0 0 2px #6dd7e622}.sl-investigation-tools button{cursor:pointer}.sl-investigation-tools button:hover{border-color:#6dd7e6}.sl-ledger{display:grid;gap:7px;margin-top:12px}.sl-timeline{margin-top:14px;padding:14px;border:1px solid #20394c;border-radius:12px;background:#091722}.sl-timeline-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:10px}.sl-timeline-head strong{display:block;color:#dff6ff;font-size:12px;margin-top:5px}.sl-timeline-head>span{font-size:9px;color:#91a8ba}.sl-timeline-list{display:grid;gap:7px;max-height:390px;overflow:auto}.sl-timeline-event{display:grid;grid-template-columns:90px minmax(0,1fr) auto;gap:10px;align-items:center;padding:9px;border:1px solid #20394c;border-radius:8px;background:#07131e}.sl-timeline-event time{font:9px ui-monospace,monospace;color:#91a8ba}.sl-timeline-event code{font-size:9px;color:#cce0eb;overflow-wrap:anywhere}.sl-timeline-event small{display:block;color:#8299ab;font-size:9px;margin-top:4px}.sl-timeline-event button{border:1px solid #31536a;background:#102536;color:#6dd7e6;border-radius:6px;padding:6px 8px;font-size:9px;cursor:pointer}.sl-transfer{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:center;padding:10px 12px;border:1px solid #20394c;border-radius:9px;background:#091722}.sl-ledger-title{font-size:9px;letter-spacing:.16em;color:#6dd7e6;margin:7px 0 2px}.sl-transfer-button{width:100%;text-align:left;color:inherit;cursor:pointer;font:inherit}.sl-transfer-button:hover{border-color:#6dd7e6;background:#102536}.sl-transfer-button>span:first-child{min-width:0}.sl-transfer-action{font-size:9px;color:#6dd7e6;white-space:nowrap}.sl-transfer code{display:block;color:#cce0eb;font-size:10px;overflow-wrap:anywhere}.sl-transfer small{display:block;color:#8299ab;font-size:9px;margin-top:4px}.sl-transfer a{font-size:10px;color:#6dd7e6;white-space:nowrap}.sl-foot{margin-top:13px;color:#71899b;font-size:9px;line-height:1.6}.sl-error{color:#ff9b9f}.sl-empty-state{padding:16px;color:#91a8ba;font-size:10px}.sl-fund{margin-top:16px;padding:15px;border:1px solid #29495d;border-radius:12px;background:#091722}.sl-fund h3{font-size:16px;margin:7px 0 5px}.sl-fund>p{font-size:10px;line-height:1.6;color:#91a8ba;margin:0}.sl-fund-controls{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}.sl-fund-controls input{flex:1;min-width:220px;background:#07111b;border:1px solid #294458;border-radius:8px;padding:10px;color:#e8f3fa}.sl-fund-controls label{display:flex;align-items:center;gap:7px;color:#91a8ba;font-size:10px}.sl-fund-controls select,.sl-fund-controls button{background:#102536;border:1px solid #31536a;border-radius:8px;padding:10px;color:#d9edf6}.sl-fund-controls button{cursor:pointer}.sl-fund-results{display:grid;gap:8px}.sl-fund-path{border:1px solid #20394c;border-radius:9px;padding:10px;background:#07131e}.sl-fund-path strong{font-size:10px;color:#dff6ff}.sl-fund-path p{font-size:9px;color:#91a8ba;margin:5px 0}.sl-fund-hop{display:flex;justify-content:space-between;gap:8px;padding:7px 0;border-top:1px solid #1c3345;font:9px ui-monospace,monospace;color:#c9e0ec;overflow-wrap:anywhere}.sl-fund-hop a{color:#6dd7e6;white-space:nowrap}.sl-fund-note{font-size:9px;color:#91a8ba;line-height:1.6;padding:9px;border-left:2px solid #c49b52;background:#171b20}
    .sentinel-live{display:block;width:100%;max-width:100%;min-width:0;flex:0 0 100%}.sl-controls>*{min-width:0;max-width:100%}.sl-controls input,.sl-controls select{max-width:100%}
@media(max-width:780px){.sentinel-live{padding:15px;min-width:0;max-width:100%;overflow:hidden}.sl-controls{display:grid;grid-template-columns:minmax(0,1fr);width:100%;min-width:0}.sl-controls>*{width:100%;min-width:0;max-width:100%}.sl-controls input{min-width:0;width:100%}.sl-controls label{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.2fr);width:100%;min-width:0;gap:8px}.sl-controls select{width:100%;min-width:0}.sl-layout{grid-template-columns:minmax(0,1fr);min-width:0}.sl-canvas,.sl-empty{min-height:320px}.sl-canvas svg{height:320px}.sl-inspector{min-height:130px}.sl-head h2{font-size:19px}}
@media(max-width:520px){.sentinel-live{width:100%;padding:14px;margin:14px 0;overflow:hidden}.sl-head{gap:8px}.sl-head p{max-width:100%}.sl-controls{display:grid;grid-template-columns:minmax(0,1fr);width:100%;gap:10px}.sl-controls>*{width:100%;min-width:0;max-width:100%}.sl-controls input{min-width:0;width:100%;font-size:16px}.sl-controls label{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.2fr);align-items:center;gap:8px;width:100%;min-width:0}.sl-controls select{width:100%;min-width:0;font-size:16px}.sl-controls button{width:100%;min-height:48px}.sl-layout{width:100%;min-width:0}.sl-canvas{min-width:0;width:100%;min-height:260px}.sl-empty{min-height:260px;text-align:center;padding:18px}.sl-canvas svg{height:260px;max-width:100%}.sl-inspector{width:100%;min-width:0}.sl-transfer{grid-template-columns:minmax(0,1fr)}.sl-transfer a{white-space:normal}.sl-investigation-tools{display:grid;grid-template-columns:minmax(0,1fr);width:100%}.sl-investigation-tools>*{width:100%;min-width:0}.sl-investigation-tools label{display:grid;grid-template-columns:1fr 1fr}.sl-investigation-tools select,.sl-investigation-tools button{width:100%;min-width:0}.sl-timeline-event{grid-template-columns:1fr auto;gap:6px}.sl-timeline-event time{grid-column:1/-1}.sl-timeline-event code{overflow-wrap:anywhere}.sl-fund{min-width:0;padding:12px}.sl-fund-controls{display:grid;grid-template-columns:minmax(0,1fr);width:100%}.sl-fund-controls>*{width:100%;min-width:0;max-width:100%}.sl-fund-controls input{min-width:0;width:100%}.sl-fund-controls label{display:flex;justify-content:space-between}.sl-fund-hop{flex-wrap:wrap}}
@media(max-width:360px){.sl-head{display:block}.sl-readonly{display:inline-flex;margin-top:10px}.sl-controls label{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}}
  `;
  panel.appendChild(style); container.appendChild(panel);
  const form = panel.querySelector("form"), status = panel.querySelector('[data-role="status"]');
  const stats = panel.querySelector('[data-role="stats"]'), canvas = panel.querySelector('[data-role="canvas"]');
  const inspector = panel.querySelector('[data-role="inspector"]'), ledger = panel.querySelector('[data-role="ledger"]');
  const investigationTools=panel.querySelector('[data-role="investigation-tools"]');
  const flowFilter=panel.querySelector('[data-role="flow-filter"]'),assetFilter=panel.querySelector('[data-role="asset-filter"]');
  const nodeSearch=panel.querySelector('[data-role="node-search"]'),locateNode=panel.querySelector('[data-role="locate-node"]');
  const timeline=panel.querySelector('[data-role="timeline"]'),timelineList=panel.querySelector('[data-role="timeline-list"]'),timelineCount=panel.querySelector('[data-role="timeline-count"]');
  let current = null, selected = null, activeNode = null;
  let tokenMetadata = new Map();
  const renderNodeLedger = address => {
    if (!current) return;
    activeNode=address;
    const direction=flowFilter.value,asset=assetFilter.value;
    const visible = current.edges.filter(edge => (edge.from === address || edge.to === address) && (direction==="all"||(direction==="incoming"&&edge.to===address)||(direction==="outgoing"&&edge.from===address)) && (asset==="all"||edge.token===asset));
    ledger.innerHTML = visible.length ? '<div class="sl-ledger-title">OBSERVED TRANSFERS · '+visible.length+'</div>'+visible.slice().reverse().slice(0, 30).map(edge => {
      const meta = tokenMetadata.get(edge.token) || {};
      const amount = meta.decimals == null ? edge.amountRaw + " raw units" : formatTokenAmount(edge.amountRaw, meta.decimals);
      const index=current.edges.indexOf(edge);
      return '<button type="button" class="sl-transfer sl-transfer-button" data-edge-index="'+index+'"><span><code>' + esc(short(edge.from)) + ' → ' + esc(short(edge.to)) + '</code><small>Block ' + parseInt(edge.blockNumber,16).toLocaleString() + ' · ' + esc(edge.transferType || 'ERC-20') + ' · ' + esc(meta.symbol || short(edge.token)) + ' · ' + esc(amount) + '</small></span><span class="sl-transfer-action">Inspect ↗</span></button>';
    }).join("") : '<div class="sl-empty-state">No matching value-flow records for this node in the selected coverage window.</div>';
    ledger.querySelectorAll("[data-edge-index]").forEach(button=>button.addEventListener("click",()=>showEdge(Number(button.dataset.edgeIndex))));
  };
  const showEdge = index => {
    if (!current || !current.edges[index]) return;
    const edge=current.edges[index],meta=tokenMetadata.get(edge.token)||{};
    const amount=meta.decimals==null?edge.amountRaw+" raw units":formatTokenAmount(edge.amountRaw,meta.decimals);
    selected=null;
    inspector.innerHTML='<span class="sl-kicker">TRANSFER INSPECTOR</span><strong>'+esc(meta.symbol||edge.transferType||"Observed transfer")+'</strong><div class="sl-kv">From<b>'+esc(edge.from)+'</b></div><div class="sl-kv">To<b>'+esc(edge.to)+'</b></div><div class="sl-kv">Observed amount<b>'+esc(amount)+'</b></div><div class="sl-kv">Token contract<b>'+esc(edge.token)+'</b></div><div class="sl-kv">Block / log index<b>'+esc(parseInt(edge.blockNumber,16).toLocaleString())+' / '+esc(parseInt(edge.logIndex,16).toString())+'</b></div><div class="sl-kv">Transaction hash<b>'+esc(edge.transactionHash)+'</b></div><a href="'+esc(current.explorer)+'/tx/'+esc(edge.transactionHash)+'" target="_blank" rel="noopener noreferrer">Open transaction in explorer ↗</a>';
    canvas.querySelectorAll(".sl-node").forEach(el=>el.classList.remove("is-selected"));
    canvas.querySelectorAll(".sl-edge").forEach((el,i)=>el.classList.toggle("is-selected",i===index));
  };
  const showNode = address => {
    if (!current) return;
    selected = address;
    const node = current.nodes.find(item => item.address === address);
    const incoming = current.edges.filter(edge => edge.to === address), outgoing = current.edges.filter(edge => edge.from === address);
    inspector.innerHTML = '<span class="sl-kicker">NODE INSPECTOR</span><strong>'+esc(address)+'</strong><div class="sl-kv">Role<b>'+(node.origin?'Trace origin':'Observed counterparty')+'</b></div><div class="sl-kv">Hop distance<b>'+(node.hop??'unknown')+'</b></div><div class="sl-kv">Incoming value-flow edges<b>'+incoming.length+'</b></div><div class="sl-kv">Outgoing value-flow edges<b>'+outgoing.length+'</b></div><div class="sl-kv">Assets / transfer types<b>'+new Set([...incoming,...outgoing].map(edge=>edge.token)).size+'</b></div><a href="'+esc(getNetwork().explorer)+'/address/'+esc(address)+'" target="_blank" rel="noopener noreferrer">Open address in explorer ↗</a>';
    panel.querySelectorAll(".sl-node").forEach(el => el.classList.toggle("is-selected",el.dataset.address===address));
    renderNodeLedger(address);
  };
  const render = graph => {
    current = graph; selected = graph.origin;
    const coverageNote=panel.querySelector(".sl-foot");
    if(coverageNote)coverageNote.textContent=graph.coverage==="indexed-mixed-value-flow-history"?"Coverage: Blockscout indexed ERC-20 + native + successful internal value-flow records · internal traces are separate from parent transactions · provider index may be incomplete":graph.coverage==="indexed-erc20-address-history"?"Coverage: Blockscout indexed Ethereum ERC-20 transfer records · pagination status shown above · one-hop graph · provider index may be incomplete":"Coverage: bounded RPC window · ERC-20 Transfer-shaped logs only · single-provider observation · no attribution or risk verdict";
    stats.innerHTML = [
      ['NODES',graph.nodeCount],[graph.coverage==='indexed-mixed-value-flow-history'?'VALUE-FLOW EDGES':'OBSERVED TRANSFER LOGS',graph.totalObservedEdges],
      ['ASSET / EVENT TYPES',new Set(graph.edges.map(edge=>edge.token)).size],['HOPS',graph.hops],
      ['BLOCK WINDOW',graph.scannedFrom+' → '+graph.scannedTo]
    ].map(([label,value])=>'<span class="sl-stat"><b>'+esc(value)+'</b>'+esc(label)+'</span>').join('');
    const patternReport=deriveLivePatterns(graph.edges,{origin:graph.origin});
    const patternResults=panel.querySelector('[data-role="pattern-results"]');
    patternResults.innerHTML=patternReport.signals.map(signal=>'<article class="sl-pattern-card"><strong>'+esc(signal.label)+' · '+signal.counterpartyCount+' counterparties</strong><small>'+esc(short(signal.subject))+' · '+esc(short(signal.token))+' · '+signal.edgeCount+' observed edge(s)</small><small>'+signal.transactionHashes.length+' transaction reference(s) · '+esc(signal.pattern)+'</small></article>').join('')||'<div class="sl-empty-state">No configured fan-in or fan-out pattern found in this evidence snapshot.</div>';
    panel.querySelector('[data-role="pattern-note"]').textContent='Topology prompts only — not risk scores, ownership attribution or proof of intent. '+patternReport.limitations[0];
    graph.topologyIntelligence=patternReport;
    investigationTools.hidden=false;
    const assets=[...new Set(graph.edges.map(edge=>edge.token))];
    assetFilter.innerHTML='<option value="all">All assets ('+assets.length+')</option>'+assets.map(token=>{const meta=tokenMetadata.get(token)||{};return '<option value="'+esc(token)+'">'+esc(meta.symbol||short(token))+'</option>';}).join('');
    assetFilter.value="all";flowFilter.value="all";
    const ordered=graph.edges.slice().sort((a,b)=>{const x=BigInt(a.blockNumber),y=BigInt(b.blockNumber);if(x!==y)return x<y?-1:1;const li=BigInt(a.logIndex),ri=BigInt(b.logIndex);return li<ri?-1:li>ri?1:0;});
    timeline.hidden=false;timelineCount.textContent=ordered.length+' events · block order';
    timelineList.innerHTML=ordered.slice(-50).reverse().map(edge=>{const meta=tokenMetadata.get(edge.token)||{};const amount=meta.decimals==null?edge.amountRaw+' raw':formatTokenAmount(edge.amountRaw,meta.decimals);return '<article class="sl-timeline-event"><time>BLOCK '+parseInt(edge.blockNumber,16).toLocaleString()+'</time><div><code>'+esc(short(edge.from))+' → '+esc(short(edge.to))+'</code><small>'+esc(meta.symbol||short(edge.token))+' · '+esc(amount)+' · '+esc(edge.transferType||'ERC-20')+'</small></div><button type="button" data-timeline-edge="'+graph.edges.indexOf(edge)+'">Inspect</button></article>';}).join('')||'<div class="sl-empty-state">No timeline events in this evidence set.</div>';
    timelineList.querySelectorAll('[data-timeline-edge]').forEach(button=>button.addEventListener('click',()=>showEdge(Number(button.dataset.timelineEdge))));
    const width=760,height=420,positions=new Map();const rings=new Map();for(const node of graph.nodes){const hop=node.hop??1;if(!rings.has(hop))rings.set(hop,[]);rings.get(hop).push(node);}for(const [hop,nodesInRing] of rings){nodesInRing.forEach((node,index)=>positions.set(node.address,point(index,nodesInRing.length,width,height,hop)));}
    const lines=graph.edges.map((edge,index)=>{const a=positions.get(edge.from),b=positions.get(edge.to);return '<line class="sl-edge" data-edge-index="'+index+'" tabindex="0" role="button" aria-label="Inspect transfer '+(index+1)+'" marker-end="url(#sl-arrow)" x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+'"><title>'+esc(edge.token)+' · '+esc(edge.transactionHash)+'</title></line>';}).join('');
    const nodes=graph.nodes.map((node,index)=>{const p=positions.get(node.address),radius=node.origin?13:Math.min(10,6+Math.log2(1+node.incomingCount+node.outgoingCount));return '<g class="sl-node'+(node.origin?' is-selected':'')+'" data-address="'+esc(node.address)+'" data-origin="'+node.origin+'" tabindex="0" role="button" aria-label="Inspect '+esc(node.address)+'"><circle cx="'+p.x+'" cy="'+p.y+'" r="'+radius+'"></circle><text x="'+p.x+'" y="'+(p.y+radius+14)+'">'+esc(short(node.address))+'</text></g>';}).join('');
    canvas.innerHTML='<div class="sl-graph-tools"><button type="button" data-zoom="in" aria-label="Zoom in">+</button><button type="button" data-zoom="out" aria-label="Zoom out">−</button><button type="button" data-zoom="reset" aria-label="Reset graph view">Reset</button></div><svg viewBox="0 0 '+width+' '+height+'" role="img" aria-label="Address transfer relationship graph"><defs><marker id="sl-arrow" markerWidth="7" markerHeight="7" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 z" fill="#73dce9"></path></marker></defs>'+lines+nodes+'</svg>';
    canvas.querySelectorAll(".sl-node").forEach(el=>{const activate=()=>showNode(el.dataset.address);el.addEventListener("click",activate);el.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" "){event.preventDefault();activate();}});});
    canvas.querySelectorAll(".sl-edge").forEach(el=>{const activate=()=>showEdge(Number(el.dataset.edgeIndex));el.addEventListener("click",activate);el.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" "){event.preventDefault();activate();}});});
    const svg=canvas.querySelector("svg");
    const view={x:0,y:0,w:width,h:height};
    const applyView=()=>svg.setAttribute("viewBox",[view.x,view.y,view.w,view.h].join(" "));
    const zoom=factor=>{const nextW=Math.max(190,Math.min(width*2,view.w*factor));const nextH=nextW*height/width;view.x+=(view.w-nextW)/2;view.y+=(view.h-nextH)/2;view.w=nextW;view.h=nextH;applyView();};
    canvas.querySelectorAll("[data-zoom]").forEach(button=>button.addEventListener("click",()=>{const action=button.dataset.zoom;if(action==="reset"){view.x=0;view.y=0;view.w=width;view.h=height;applyView();}else zoom(action==="in" ? 0.82 : 1.22);}));
    svg.addEventListener("wheel",event=>{event.preventDefault();zoom(event.deltaY<0 ? 0.9 : 1.1);},{passive:false});
    let drag=null;
    svg.addEventListener("pointerdown",event=>{if(event.target.closest(".sl-node"))return;drag={x:event.clientX,y:event.clientY};try{svg.setPointerCapture(event.pointerId);}catch{}});
    svg.addEventListener("pointermove",event=>{if(!drag)return;const rect=svg.getBoundingClientRect();const dx=(event.clientX-drag.x)*view.w/rect.width;const dy=(event.clientY-drag.y)*view.h/rect.height;view.x-=dx;view.y-=dy;drag={x:event.clientX,y:event.clientY};applyView();});
    const stopDrag=()=>{drag=null;};
    svg.addEventListener("pointerup",stopDrag);svg.addEventListener("pointercancel",stopDrag);
    ledger.innerHTML=graph.edges.length?graph.edges.slice().reverse().slice(0,30).map(edge=>'<div class="sl-transfer"><div><code>'+esc(short(edge.from))+' → '+esc(short(edge.to))+'</code><small>Block '+parseInt(edge.blockNumber,16).toLocaleString()+' · '+esc(edge.token)+' · raw amount '+esc(edge.amountRaw)+'</small></div><a href="'+esc(getNetwork().explorer)+'/tx/'+esc(edge.transactionHash)+'" target="_blank" rel="noopener noreferrer">View transaction ↗</a></div>').join(''):'<div class="sl-empty-state">No Transfer-shaped logs were returned for this address in the scanned block window. This does not mean the address has no activity.</div>';
    if(graph.truncated)status.textContent+=' · Display capped at '+graph.edgeCount+' edges; '+graph.totalObservedEdges+' matched.';
    showNode(graph.origin);
  };
  const fundTarget=panel.querySelector('[data-role="fund-target"]');
  const fundDepth=panel.querySelector('[data-role="fund-depth"]');
  const fundResults=panel.querySelector('[data-role="fund-results"]');
  locateNode.addEventListener("click",()=>{if(!current)return;const query=nodeSearch.value.trim().toLowerCase();if(!query){nodeSearch.focus();return;}const matches=current.nodes.filter(node=>node.address.toLowerCase().includes(query));if(matches.length===1){showNode(matches[0].address);const element=[...canvas.querySelectorAll(".sl-node")].find(item=>item.dataset.address===matches[0].address);element?.scrollIntoView({block:"nearest",inline:"nearest"});nodeSearch.setCustomValidity("");}else if(matches.length>1){nodeSearch.setCustomValidity("Multiple matches. Enter more address characters.");nodeSearch.reportValidity();}else{nodeSearch.setCustomValidity("No matching address in this graph.");nodeSearch.reportValidity();}});
  nodeSearch.addEventListener("input",()=>nodeSearch.setCustomValidity(""));
  nodeSearch.addEventListener("keydown",event=>{if(event.key==="Enter"){event.preventDefault();locateNode.click();}});
  flowFilter.addEventListener("change",()=>{if(activeNode)renderNodeLedger(activeNode);});
  assetFilter.addEventListener("change",()=>{if(activeNode)renderNodeLedger(activeNode);});
  panel.querySelector('[data-role="export-evidence"]').addEventListener("click",()=>{
    if(!current)return;
    const bundle={schema:"sentinel.evidence-export.v1",exportedAt:new Date().toISOString(),chainId:current.chainId,origin:current.origin,coverage:current.coverage,provider:current.provider||null,scannedFrom:current.scannedFrom,scannedTo:current.scannedTo,hops:current.hops,nodeCount:current.nodeCount,edgeCount:current.edgeCount,totalObservedEdges:current.totalObservedEdges,truncated:Boolean(current.truncated),limitations:current.limitations||[],topologyIntelligence:current.topologyIntelligence||null,nodes:current.nodes,edges:current.edges.map(edge=>({...edge,tokenMetadata:tokenMetadata.get(edge.token)||null}))};
    const blob=new Blob([JSON.stringify(bundle,null,2)],{type:"application/json"});
    const url=URL.createObjectURL(blob),link=document.createElement("a");link.href=url;link.download="sentinel-evidence-"+current.chainId+"-"+current.origin.slice(2,10)+".json";document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  });
  panel.querySelector('[data-role="fund-run"]').addEventListener("click",()=>{
    if(!current){fundResults.textContent="Run an address trace before reconstructing candidate routes.";return;}
    const target=normalizeAddress(fundTarget.value.trim());
    if(!target){fundResults.innerHTML='<div class="sl-error">Enter a valid destination EVM address.</div>';return;}
    if(target===current.origin){fundResults.innerHTML='<div class="sl-error">Destination must differ from the trace origin.</div>';return;}
    try{
      const result=traceFundPaths(current.edges,{source:current.origin,target,chainId:current.chainId,maxDepth:Number(fundDepth.value),maxPaths:20});
      if(!result.pathCount){fundResults.innerHTML='<div class="sl-empty-state">No candidate route found in the currently loaded evidence. This is not evidence of inactivity or proof that no route exists.</div>';return;}
      const paths=result.paths.map(path=>{const hops=path.edges.map((edge,index)=>{const meta=tokenMetadata.get(edge.token)||{};const amount=meta.decimals==null?edge.amountRaw+" raw":formatTokenAmount(edge.amountRaw,meta.decimals);return '<div class="sl-fund-hop"><span>'+esc(short(edge.from))+' → '+esc(short(edge.to))+' · '+esc(meta.symbol||short(edge.token))+' · '+esc(amount)+'</span><a href="'+esc(getNetwork().explorer)+'/tx/'+esc(edge.transactionHash)+'" target="_blank" rel="noopener noreferrer">TX '+(index+1)+' ↗</a></div>';}).join("");return '<article class="sl-fund-path"><strong>'+esc(path.pathId)+' · '+path.hopCount+' hop(s) · '+esc(path.amountCompatibility)+'</strong><p>'+esc(path.assetKey)+' · first observed '+esc(path.firstObservedAmountRaw)+' raw units → final '+esc(path.finalObservedAmountRaw)+' raw units</p>'+hops+'</article>';}).join("");
      fundResults.innerHTML=paths+'<div class="sl-fund-note">Candidate sequence only. Matching asset, chronology and non-increasing amounts do not establish that the same units moved between hops; balances can be pooled or replenished. Internal traces are excluded to avoid double-counting parent execution.</div>'+(result.truncated?'<div class="sl-empty-state">Path output reached its configured cap.</div>':"");
    }catch(error){fundResults.innerHTML='<div class="sl-error">'+esc(error.message)+'</div>';}
  });
  form.elements.source.addEventListener("change",()=>{
    const indexed=form.elements.source.value==="indexed";
    form.elements.window.disabled=indexed||form.elements.source.value==="activity";
    form.elements.hops.disabled=indexed||form.elements.source.value==="activity";
    if(indexed)form.elements.hops.value="1";
  });
  form.addEventListener("submit",async event=>{
    event.preventDefault();const address=normalizeAddress(form.elements.address.value.trim());
    if(!address){status.textContent="Enter a valid 20-byte EVM address.";status.classList.add("sl-error");return;}
    const network=getNetwork(),source=form.elements.source.value,pinnedRpc=bindNetworkRpc(rpc,network);
    status.classList.remove("sl-error");form.querySelector("button").disabled=true;form.querySelector("button").textContent="Tracing…";
    canvas.innerHTML='<div class="sl-empty">Querying '+(source==="indexed"?"indexed address history":"live RPC Transfer logs")+'…</div>';ledger.replaceChildren();stats.replaceChildren();
    try{
      let graph;
      if(source==="activity"){
        if(!BLOCKSCOUT_ENDPOINTS[String(network.chainId).toLowerCase()])throw new Error("Indexed activity is not configured for "+network.name+". Select Ethereum Mainnet or switch to Live RPC.");
        const [history,activity]=await Promise.all([
          fetchBlockscoutAddressTransfers({address,chainId:network.chainId,maxPages:8}),
          fetchBlockscoutAddressActivity({address,chainId:network.chainId,maxPages:4})
        ]);
        const combined=[...history.transfers,...activity.records];
        const blockValues=combined.map(item=>BigInt(item.blockNumber));
        const fromBlock=blockValues.length?blockValues.reduce((a,b)=>a<b?a:b).toString():"n/a";
        const toBlock=blockValues.length?blockValues.reduce((a,b)=>a>b?a:b).toString():"n/a";
        graph=buildLiveTransferGraph(combined,{address,chainId:network.chainId,scannedFrom:fromBlock,scannedTo:toBlock,hops:1,maxEdges:160,maxNodes:40});
        graph.coverage="indexed-mixed-value-flow-history";
        graph.provider=history.provider;
        graph.activity={erc20:history.itemCount,native:activity.counts.nativeTransfers,internal:activity.counts.internalTransfers,pages:history.pagesFetched+activity.pagesFetched,complete:history.complete&&activity.complete,truncated:history.truncated||activity.truncated,malformed:history.malformedItems+activity.counts.malformedTransactions+activity.counts.malformedInternal,coverage:activity.coverage};
        graph.truncated=graph.truncated||graph.activity.truncated;
        graph.limitations=[...history.limitations,...activity.limitations];
        graph.explorer=network.explorer;graph.networkName=network.name;
        tokenMetadata=new Map([...Object.entries(history.tokenMetadata),...activity.records.map(item=>[item.token,item.tokenMetadata])]);
        render(graph);
        status.textContent="Ethereum Mainnet · Blockscout · "+history.itemCount+" ERC-20 + "+activity.counts.nativeTransfers+" native + "+activity.counts.internalTransfers+" internal value-flow records · "+graph.activity.pages+" pages · "+(graph.activity.complete?"provider pagination complete":"partial history; page cap reached")+" · internal calls are not additive balance changes · "+new Date().toISOString();
      }else if(source==="indexed"){
        if(!BLOCKSCOUT_ENDPOINTS[String(network.chainId).toLowerCase()])throw new Error("Indexed history is not configured for "+network.name+". Select Ethereum Mainnet or switch to Live RPC.");
        const history=await fetchBlockscoutAddressTransfers({address,chainId:network.chainId,maxPages:8});
        graph=buildLiveTransferGraph(history.transfers,{address,chainId:network.chainId,scannedFrom:history.blockRange?.from??"n/a",scannedTo:history.blockRange?.to??"n/a",hops:1,maxEdges:160,maxNodes:40});
        graph.coverage="indexed-erc20-address-history";
        graph.provider=history.provider;
        graph.history={pagesFetched:history.pagesFetched,itemCount:history.itemCount,complete:history.complete,truncated:history.truncated,malformedItems:history.malformedItems,directionCoverage:history.directionCoverage,limitations:history.limitations};
        graph.truncated=graph.truncated||history.truncated;
        graph.limitations=history.limitations;
        graph.explorer=network.explorer;graph.networkName=network.name;
        tokenMetadata=new Map(Object.entries(history.tokenMetadata));
        render(graph);
        status.textContent="Ethereum Mainnet · Blockscout indexed history · "+history.itemCount.toLocaleString()+" ERC-20 records · "+history.pagesFetched+" pages · "+(history.complete?"provider pagination complete":"partial history; page cap reached")+(history.malformedItems?" · "+history.malformedItems+" malformed records skipped":"")+" · "+new Date().toISOString();
      }else{
        const chainId=await pinnedRpc("eth_chainId",[]);
        if(chainId.toLowerCase()!==network.chainId.toLowerCase())throw new Error("RPC chain ID mismatch; no graph data accepted.");
        const latestHex=await pinnedRpc("eth_blockNumber",[]),latest=BigInt(latestHex),requested=Number(form.elements.window.value);
        let windowBlocks=requested,logs=[],lastError=null;
        for(let attempt=0;attempt<4;attempt++){
          const from=latest>BigInt(windowBlocks)?latest-BigInt(windowBlocks):0n,fromHex="0x"+from.toString(16);
          try{
            const [sent,received]=await Promise.all([
              pinnedRpc("eth_getLogs",[{fromBlock:fromHex,toBlock:latestHex,topics:[ERC20_TRANSFER_TOPIC,addressTopic(address)]}]),
              pinnedRpc("eth_getLogs",[{fromBlock:fromHex,toBlock:latestHex,topics:[ERC20_TRANSFER_TOPIC,null,addressTopic(address)]}])
            ]);
            logs=[...(sent||[]),...(received||[])];lastError=null;break;
          }catch(error){lastError=error;if(attempt===3||windowBlocks<=64)break;windowBlocks=Math.max(64,Math.floor(windowBlocks/2));}
        }
        if(lastError)throw new Error("RPC could not scan the requested window: "+lastError.message);
        const requestedHops = Number(form.elements.hops.value);
        const from=latest>BigInt(windowBlocks)?latest-BigInt(windowBlocks):0n;
        let allLogs = logs.slice(), expansionFailures = 0, expandedAddresses = 0, expansionCandidates = 0;
        const rootTransfers = decodeTransferLogs(logs,{chainId:network.chainId});
        if (requestedHops === 2) {
          const allPeers = [...new Set(rootTransfers.map(edge => edge.from === address ? edge.to : edge.from).filter(peer => peer !== address))];
          expansionCandidates = allPeers.length;
          const peers = allPeers.slice(0,8);
          const expanded = await Promise.allSettled(peers.map(async peer => {
            const [sent,received] = await Promise.all([
              pinnedRpc("eth_getLogs",[{fromBlock:"0x"+from.toString(16),toBlock:latestHex,topics:[ERC20_TRANSFER_TOPIC,addressTopic(peer)]}]),
              pinnedRpc("eth_getLogs",[{fromBlock:"0x"+from.toString(16),toBlock:latestHex,topics:[ERC20_TRANSFER_TOPIC,null,addressTopic(peer)]}])
            ]);
            return [...(sent||[]),...(received||[])];
          }));
          for (const result of expanded) {
            if (result.status === "fulfilled") { allLogs.push(...result.value); expandedAddresses++; }
            else expansionFailures++;
          }
        }
        const transfers=decodeTransferLogs(allLogs,{chainId:network.chainId});
        graph=buildLiveTransferGraph(transfers,{address,chainId:network.chainId,scannedFrom:from.toString(),scannedTo:latest.toString(),hops:requestedHops,maxEdges:160,maxNodes:40});
        graph.provider="Selected public RPC endpoint";
        graph.explorer=network.explorer;
        graph.networkName=network.name;
        tokenMetadata = await fetchMetadataBatch(graph.edges.map(edge => edge.token), pinnedRpc);
        render(graph);
        status.textContent=network.name+" · "+requestedHops+" hop(s) · scanned "+windowBlocks.toLocaleString()+" blocks"+(requestedHops===2?" · expanded "+expandedAddresses+"/"+Math.min(expansionCandidates,8)+" counterparties"+(expansionCandidates>8?" (8-counterparty cap)":""):"")+(expansionFailures?" · "+expansionFailures+" expansion queries failed":"")+(graph.truncated?" · graph reached its node/edge cap":"")+" · "+new Date().toISOString();
      }
    }catch(error){canvas.innerHTML='<div class="sl-empty sl-error">'+esc(error.message)+'</div>';status.textContent="Live trace failed. Check provider availability, chain support and pagination limits.";status.classList.add("sl-error");}
    finally{form.querySelector("button").disabled=false;form.querySelector("button").textContent="Trace address ↗";}
  });
  return {panel,trace:()=>form.requestSubmit(),get result(){return current;}};
}
