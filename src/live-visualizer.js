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
  for (let depth = 1; depth <= hops && frontier.size; depth++) {
    const next = new Set();
    for (const edge of all) {
      if (!frontier.has(edge.from) && !frontier.has(edge.to)) continue;
      const other = frontier.has(edge.from) ? edge.to : edge.from;
      if (!reachable.has(other)) {
        if (reachable.size + next.size >= maxNodes) continue;
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
    truncated: ordered.length > edges.length || reachable.size >= maxNodes, nodes, edges,
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
    <form class="sl-controls"><input name="address" spellcheck="false" autocomplete="off" placeholder="Paste an EVM wallet or contract address" aria-label="Address to trace" required><label>Block window <select name="window"><option value="500">500</option><option value="2000" selected>2,000</option><option value="5000">5,000</option><option value="10000">10,000</option></select></label><label>Graph depth <select name="hops"><option value="1" selected>1 hop</option><option value="2">2 hops</option></select></label><button type="submit">Trace address ↗</button></form>
    <div class="sl-meta" data-role="status">Choose an address to build a live relationship map from recent ERC-20 Transfer logs.</div>
    <div class="sl-stats" data-role="stats"></div>
    <div class="sl-layout"><div class="sl-canvas" data-role="canvas"><div class="sl-empty">Your graph will appear here</div></div><aside class="sl-inspector" data-role="inspector"><span class="sl-kicker">NODE INSPECTOR</span><strong>Select a node</strong><p>Address details and observed transfer evidence will appear here.</p></aside></div>
    <div class="sl-ledger" data-role="ledger"></div>
    <div class="sl-foot">Coverage: bounded RPC window · ERC-20 Transfer-shaped logs only · single-provider observation · no attribution or risk verdict</div>
  `;
  const style = document.createElement("style");
  style.textContent = `
    .sentinel-live{margin:20px 0;padding:22px;border:1px solid #29495d;border-radius:18px;background:radial-gradient(ellipse at 82% 0%,rgba(39,133,155,.15),transparent 36%),linear-gradient(145deg,#101e2b,#08121d);color:#e8f3fa;box-shadow:0 18px 48px rgba(0,0,0,.2)}
    .sentinel-live *{box-sizing:border-box}.sl-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}.sl-kicker{font-size:9px;letter-spacing:.2em;font-weight:800;color:#6dd7e6}.sl-head h2{font-size:22px;margin:7px 0 4px;letter-spacing:-.035em}.sl-head p,.sl-inspector p{font-size:11px;line-height:1.6;color:#91a8ba;margin:0}.sl-readonly{white-space:nowrap;font-size:9px;letter-spacing:.12em;color:#8de0b9;border:1px solid #285e4b;border-radius:30px;padding:7px 10px;background:#10271f}
    .sl-controls{display:flex;gap:9px;margin:18px 0 10px;flex-wrap:wrap}.sl-controls input{flex:1;min-width:220px;background:#07111b;border:1px solid #294458;border-radius:9px;padding:12px;color:#e8f3fa}.sl-controls label{display:flex;align-items:center;gap:8px;color:#91a8ba;font-size:10px}.sl-controls select{background:#07111b;border:1px solid #294458;border-radius:9px;padding:10px;color:#e8f3fa}.sl-controls button{min-height:42px;padding:0 16px}.sl-meta{font-size:10px;color:#91a8ba;min-height:20px}.sl-stats{display:flex;gap:8px;flex-wrap:wrap;margin:13px 0}.sl-stat{border:1px solid #223c50;background:#091722;padding:8px 11px;border-radius:8px;color:#a9bdcb;font-size:10px}.sl-stat b{color:#e7f7ff;margin-right:4px}
    .sl-layout{display:grid;grid-template-columns:minmax(0,1fr) 245px;gap:12px}.sl-canvas{position:relative;min-width:0;min-height:420px;border:1px solid #20394c;border-radius:12px;background:radial-gradient(circle at center,rgba(27,73,92,.18),transparent 54%),#07111b;overflow:hidden}.sl-canvas svg{width:100%;height:420px;display:block}.sl-graph-tools{position:absolute;z-index:2;top:10px;right:10px;display:flex;gap:5px}.sl-graph-tools button{border:1px solid #31536a;background:#0b1c29;color:#cfe8f2;border-radius:7px;min-width:30px;height:29px;padding:0 8px;font-size:11px;cursor:pointer}.sl-graph-tools button:hover{border-color:#6dd7e6;background:#102b3a}.sl-edge{stroke:#367c91;stroke-opacity:.7;stroke-width:1.5}.sl-edge-dot{fill:#73dce9}.sl-node{cursor:pointer;outline:none}.sl-node circle{fill:#123448;stroke:#58b9cc;stroke-width:1.5}.sl-node[data-origin="true"] circle{fill:#155c67;stroke:#8ce6ec;stroke-width:2.5}.sl-node text{fill:#c8dbe6;font:10px ui-monospace,monospace;text-anchor:middle}.sl-node:focus circle,.sl-node.is-selected circle{stroke:#f4c66b;stroke-width:3}.sl-empty{display:grid;place-items:center;min-height:420px;color:#71889a;font-size:11px}.sl-inspector{padding:15px;border:1px solid #20394c;border-radius:12px;background:#091722;min-width:0}.sl-inspector strong{display:block;font:11px ui-monospace,monospace;overflow-wrap:anywhere;margin:14px 0 8px;color:#e4f6ff}.sl-inspector a{color:#72d8e7;font-size:10px;overflow-wrap:anywhere}.sl-inspector .sl-kv{border-top:1px solid #1c3345;padding:8px 0;font-size:10px;color:#91a8ba}.sl-inspector .sl-kv b{display:block;color:#d9eaf3;margin-top:3px;overflow-wrap:anywhere}.sl-ledger{display:grid;gap:7px;margin-top:12px}.sl-transfer{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:center;padding:10px 12px;border:1px solid #20394c;border-radius:9px;background:#091722}.sl-transfer code{display:block;color:#cce0eb;font-size:10px;overflow-wrap:anywhere}.sl-transfer small{display:block;color:#8299ab;font-size:9px;margin-top:4px}.sl-transfer a{font-size:10px;color:#6dd7e6;white-space:nowrap}.sl-foot{margin-top:13px;color:#71899b;font-size:9px;line-height:1.6}.sl-error{color:#ff9b9f}.sl-empty-state{padding:16px;color:#91a8ba;font-size:10px}
    @media(max-width:780px){.sentinel-live{padding:15px}.sl-layout{grid-template-columns:1fr}.sl-canvas,.sl-empty{min-height:320px}.sl-canvas svg{height:320px}.sl-inspector{min-height:130px}.sl-head h2{font-size:19px}}@media(max-width:520px){.sl-controls{display:grid;grid-template-columns:1fr}.sl-controls input{min-width:0}.sl-controls label{justify-content:space-between}.sl-controls button{width:100%}.sl-transfer{grid-template-columns:1fr}.sl-transfer a{white-space:normal}}
  `;
  panel.appendChild(style); container.appendChild(panel);
  const form = panel.querySelector("form"), status = panel.querySelector('[data-role="status"]');
  const stats = panel.querySelector('[data-role="stats"]'), canvas = panel.querySelector('[data-role="canvas"]');
  const inspector = panel.querySelector('[data-role="inspector"]'), ledger = panel.querySelector('[data-role="ledger"]');
  let current = null, selected = null;
  let tokenMetadata = new Map();
  const renderNodeLedger = address => {
    if (!current) return;
    const visible = current.edges.filter(edge => edge.from === address || edge.to === address);
    ledger.innerHTML = visible.length ? visible.slice().reverse().slice(0, 30).map(edge => {
      const meta = tokenMetadata.get(edge.token) || {};
      const amount = meta.decimals == null ? edge.amountRaw + " raw units" : formatTokenAmount(edge.amountRaw, meta.decimals);
      return '<div class="sl-transfer"><div><code>' + esc(short(edge.from)) + ' → ' + esc(short(edge.to)) + '</code><small>Block ' + parseInt(edge.blockNumber,16).toLocaleString() + ' · ' + esc(meta.symbol || short(edge.token)) + ' · ' + esc(amount) + '</small></div><a href="' + esc(getNetwork().explorer) + '/tx/' + esc(edge.transactionHash) + '" target="_blank" rel="noopener noreferrer">View transaction ↗</a></div>';
    }).join("") : '<div class="sl-empty-state">No matching Transfer events for this node in the scanned window.</div>';
  };
  const showNode = address => {
    if (!current) return;
    selected = address;
    const node = current.nodes.find(item => item.address === address);
    const incoming = current.edges.filter(edge => edge.to === address), outgoing = current.edges.filter(edge => edge.from === address);
    inspector.innerHTML = '<span class="sl-kicker">NODE INSPECTOR</span><strong>'+esc(address)+'</strong><div class="sl-kv">Role<b>'+(node.origin?'Trace origin':'Observed counterparty')+'</b></div><div class="sl-kv">Hop distance<b>'+(node.hop??'unknown')+'</b></div><div class="sl-kv">Incoming Transfer logs<b>'+incoming.length+'</b></div><div class="sl-kv">Outgoing Transfer logs<b>'+outgoing.length+'</b></div><div class="sl-kv">Token contracts observed<b>'+new Set([...incoming,...outgoing].map(edge=>edge.token)).size+'</b></div><a href="'+esc(getNetwork().explorer)+'/address/'+esc(address)+'" target="_blank" rel="noopener noreferrer">Open address in explorer ↗</a>';
    panel.querySelectorAll(".sl-node").forEach(el => el.classList.toggle("is-selected",el.dataset.address===address));
    renderNodeLedger(address);
  };
  const render = graph => {
    current = graph; selected = graph.origin;
    stats.innerHTML = [
      ['NODES',graph.nodeCount],['OBSERVED TRANSFER LOGS',graph.totalObservedEdges],
      ['TOKENS',new Set(graph.edges.map(edge=>edge.token)).size],['HOPS',graph.hops],
      ['BLOCK WINDOW',graph.scannedFrom+' → '+graph.scannedTo]
    ].map(([label,value])=>'<span class="sl-stat"><b>'+esc(value)+'</b>'+esc(label)+'</span>').join('');
    const width=760,height=420,positions=new Map();const rings=new Map();for(const node of graph.nodes){const hop=node.hop??1;if(!rings.has(hop))rings.set(hop,[]);rings.get(hop).push(node);}for(const [hop,nodesInRing] of rings){nodesInRing.forEach((node,index)=>positions.set(node.address,point(index,nodesInRing.length,width,height,hop)));}
    const lines=graph.edges.map(edge=>{const a=positions.get(edge.from),b=positions.get(edge.to);return '<line class="sl-edge" marker-end="url(#sl-arrow)" x1="'+a.x+'" y1="'+a.y+'" x2="'+b.x+'" y2="'+b.y+'"><title>'+esc(edge.token)+' · '+esc(edge.transactionHash)+'</title></line>';}).join('');
    const nodes=graph.nodes.map((node,index)=>{const p=positions.get(node.address),radius=node.origin?13:Math.min(10,6+Math.log2(1+node.incomingCount+node.outgoingCount));return '<g class="sl-node'+(node.origin?' is-selected':'')+'" data-address="'+esc(node.address)+'" data-origin="'+node.origin+'" tabindex="0" role="button" aria-label="Inspect '+esc(node.address)+'"><circle cx="'+p.x+'" cy="'+p.y+'" r="'+radius+'"></circle><text x="'+p.x+'" y="'+(p.y+radius+14)+'">'+esc(short(node.address))+'</text></g>';}).join('');
    canvas.innerHTML='<div class="sl-graph-tools"><button type="button" data-zoom="in" aria-label="Zoom in">+</button><button type="button" data-zoom="out" aria-label="Zoom out">−</button><button type="button" data-zoom="reset" aria-label="Reset graph view">Reset</button></div><svg viewBox="0 0 '+width+' '+height+'" role="img" aria-label="Address transfer relationship graph"><defs><marker id="sl-arrow" markerWidth="7" markerHeight="7" refX="5" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 z" fill="#73dce9"></path></marker></defs>'+lines+nodes+'</svg>';
    canvas.querySelectorAll(".sl-node").forEach(el=>{const activate=()=>showNode(el.dataset.address);el.addEventListener("click",activate);el.addEventListener("keydown",event=>{if(event.key==="Enter"||event.key===" "){event.preventDefault();activate();}});});
    const svg=canvas.querySelector("svg");
    const view={x:0,y:0,w:width,h:height};
    const applyView=()=>svg.setAttribute("viewBox",[view.x,view.y,view.w,view.h].join(" "));
    const zoom=factor=>{const nextW=Math.max(190,Math.min(width*2,view.w*factor));const nextH=nextW*height/width;view.x+=(view.w-nextW)/2;view.y+=(view.h-nextH)/2;view.w=nextW;view.h=nextH;applyView();};
    canvas.querySelectorAll("[data-zoom]").forEach(button=>button.addEventListener("click",()=>{const action=button.dataset.zoom;if(action==="reset"){view.x=0;view.y=0;view.w=width;view.h=height;applyView();}else zoom(action==="in" ? 0.82 : 1.22);}));
    svg.addEventListener("wheel",event=>{event.preventDefault();zoom(event.deltaY<0 ? 0.9 : 1.1);},{passive:false});
    let drag=null;
    svg.addEventListener("pointerdown",event=>{if(event.target.closest(".sl-node"))return;drag={x:event.clientX,y:event.clientY};svg.setPointerCapture(event.pointerId);});
    svg.addEventListener("pointermove",event=>{if(!drag)return;const rect=svg.getBoundingClientRect();const dx=(event.clientX-drag.x)*view.w/rect.width;const dy=(event.clientY-drag.y)*view.h/rect.height;view.x-=dx;view.y-=dy;drag={x:event.clientX,y:event.clientY};applyView();});
    const stopDrag=()=>{drag=null;};
    svg.addEventListener("pointerup",stopDrag);svg.addEventListener("pointercancel",stopDrag);
    ledger.innerHTML=graph.edges.length?graph.edges.slice().reverse().slice(0,30).map(edge=>'<div class="sl-transfer"><div><code>'+esc(short(edge.from))+' → '+esc(short(edge.to))+'</code><small>Block '+parseInt(edge.blockNumber,16).toLocaleString()+' · '+esc(edge.token)+' · raw amount '+esc(edge.amountRaw)+'</small></div><a href="'+esc(getNetwork().explorer)+'/tx/'+esc(edge.transactionHash)+'" target="_blank" rel="noopener noreferrer">View transaction ↗</a></div>').join(''):'<div class="sl-empty-state">No Transfer-shaped logs were returned for this address in the scanned block window. This does not mean the address has no activity.</div>';
    if(graph.truncated)status.textContent+=' · Display capped at '+graph.edgeCount+' edges; '+graph.totalObservedEdges+' matched.';
    showNode(graph.origin);
  };
  form.addEventListener("submit",async event=>{
    event.preventDefault();const address=normalizeAddress(form.elements.address.value.trim());
    if(!address){status.textContent="Enter a valid 20-byte EVM address.";status.classList.add("sl-error");return;}
    const network=getNetwork();status.classList.remove("sl-error");form.querySelector("button").disabled=true;form.querySelector("button").textContent="Tracing…";
    canvas.innerHTML='<div class="sl-empty">Querying live RPC Transfer logs…</div>';ledger.replaceChildren();stats.replaceChildren();
    try{
      const chainId=await rpc("eth_chainId",[]);
      if(chainId.toLowerCase()!==network.chainId.toLowerCase())throw new Error("RPC chain ID mismatch; no graph data accepted.");
      const latestHex=await rpc("eth_blockNumber",[]),latest=BigInt(latestHex),requested=Number(form.elements.window.value);
      let windowBlocks=requested,logs=[],lastError=null;
      for(let attempt=0;attempt<4;attempt++){
        const from=latest>BigInt(windowBlocks)?latest-BigInt(windowBlocks):0n,fromHex="0x"+from.toString(16);
        try{
          const [sent,received]=await Promise.all([
            rpc("eth_getLogs",[{fromBlock:fromHex,toBlock:latestHex,topics:[ERC20_TRANSFER_TOPIC,addressTopic(address)]}]),
            rpc("eth_getLogs",[{fromBlock:fromHex,toBlock:latestHex,topics:[ERC20_TRANSFER_TOPIC,null,addressTopic(address)]}])
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
            rpc("eth_getLogs",[{fromBlock:"0x"+from.toString(16),toBlock:latestHex,topics:[ERC20_TRANSFER_TOPIC,addressTopic(peer)]}]),
            rpc("eth_getLogs",[{fromBlock:"0x"+from.toString(16),toBlock:latestHex,topics:[ERC20_TRANSFER_TOPIC,null,addressTopic(peer)]}])
          ]);
          return [...(sent||[]),...(received||[])];
        }));
        for (const result of expanded) {
          if (result.status === "fulfilled") { allLogs.push(...result.value); expandedAddresses++; }
          else expansionFailures++;
        }
      }
      const transfers=decodeTransferLogs(allLogs,{chainId:network.chainId});
      const graph=buildLiveTransferGraph(transfers,{address,chainId:network.chainId,scannedFrom:from.toString(),scannedTo:latest.toString(),hops:requestedHops,maxEdges:160,maxNodes:40});
      tokenMetadata = await fetchMetadataBatch(graph.edges.map(edge => edge.token), rpc);
      render(graph);
      status.textContent=network.name+" · "+requestedHops+" hop(s) · scanned "+windowBlocks.toLocaleString()+" blocks"+(requestedHops===2?" · expanded "+expandedAddresses+"/"+Math.min(expansionCandidates,8)+" counterparties"+(expansionCandidates>8?" (8-counterparty cap)":""):"")+(expansionFailures?" · "+expansionFailures+" expansion queries failed":"")+(graph.truncated?" · graph reached its node/edge cap":"")+" · "+new Date().toISOString();
    }catch(error){canvas.innerHTML='<div class="sl-empty sl-error">'+esc(error.message)+'</div>';status.textContent="Live trace failed. The provider may limit eth_getLogs range or availability.";status.classList.add("sl-error");}
    finally{form.querySelector("button").disabled=false;form.querySelector("button").textContent="Trace address ↗";}
  });
  return {panel,trace:()=>form.requestSubmit(),get result(){return current;}};
}
