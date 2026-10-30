# SENTINEL — Blockchain Defense Intelligence

SENTINEL is an evidence-led, read-only multichain EVM security research workspace. The browser inspector supports Ethereum Mainnet, BNB Smart Chain and Polygon PoS with chain-ID verification before accepting inspection data.

**Live repository:** https://github.com/Blackleets/sentinel-blockchain-defense

## Current release

- Select Ethereum Mainnet (chain ID 1), BNB Smart Chain (56) or Polygon PoS (137); each selected RPC endpoint is checked with `eth_chainId` before any inspection result is accepted.
- Inspect EVM account addresses on the selected network using `eth_getCode`, `eth_getBalance`, `eth_getTransactionCount` and `eth_blockNumber`.
- Inspect transaction hashes using `eth_getTransactionByHash`, `eth_getTransactionReceipt` and block metadata.
- Detect the EIP-7702 delegated-code designator prefix `0xef0100`, extract the 20-byte delegation target, and inspect whether that target currently has deployed code.
- Static EVM bytecode disassembly that correctly skips PUSH immediate data.
- ERC-1967 implementation, admin and beacon slot inspection, including a read-only beacon implementation() lookup when applicable.
- Contract bytecode analysis follows a resolved ERC-1967 implementation when available.
- Explainable contract capability evidence for CALL-family operations, CREATE/CREATE2, SELFDESTRUCT, SSTORE and TSTORE.
- PUSH4 selector candidates, explicitly not treated as verified ABI functions.
- Bounded recent ERC-1967 event history (`Upgraded`, `AdminChanged`, `BeaconUpgraded`) via read-only `eth_getLogs`, with explicit scanned block range and partial-history caveats.
- Heuristic UUPS / ERC-1822 selector indicators (`proxiableUUID`, `upgradeTo`, `upgradeToAndCall`) clearly labelled as selector candidates, never proof of a working upgrade path.
- Export a provenance-labelled JSON evidence snapshot for address and transaction inspections, including provider, chain ID, block context and explicit non-verdict caveats.
- Import multiple exported case reports locally and build a cross-case evidence graph for shared proxy/delegation infrastructure and observed transaction flows; export the graph as JSON.
- Rule-based evidence findings and chronological ERC-1967 change timeline for each inspection. Findings expose supporting observations and never produce an automatic maliciousness verdict or numeric risk score.
- Evidence correlation engine for comparing multiple user-supplied case reports: shared EIP-7702 delegation targets, ERC-1967 implementations/admins/beacons, resolved implementations and observed transaction participants. Relationships remain evidence-only, never a maliciousness verdict.
- Explainable threat-intelligence rules for repeated transaction senders and recipients, reused ERC-1967 slot infrastructure, and bounded upgrade-event clusters. Thresholds are configurable; every signal includes evidence and non-attribution caveats.
- Observed transaction handoff trails connect a transaction recipient to a later sender on the same chain using imported transaction hashes and block ordering. These links are not proof of token transfers or fund movement.
- Address Intelligence profiles summarize imported mined transactions per chain and address: incoming/outgoing appearances, distinct observed counterparties, case count, observed block range and sample transaction hashes. Coverage is explicitly limited to supplied evidence.
- Decode standard ERC-20 `Transfer` event logs from imported transaction receipts, deduplicate by chain/transaction/log index, and preserve exact raw base-unit amounts. No token decimals, fiat values, internal transfers or complete history are inferred. A contract can emit a Transfer-shaped event without being a legitimate ERC-20 token; verify the contract independently.
- Build token-specific address profiles per chain and contract with incoming/outgoing event counts, exact raw-unit totals, counterparties, case count and observed block range. Tokens are never merged and totals are not presented as human units without verified decimals.
- Generate a deterministic token-flow graph from imported receipt logs, with chain/token/address filters, bounded rendering, node activity counts and per-edge transaction/block/log evidence. The graph never infers unobserved hops or ownership.
- Build a unified evidence timeline across imported transaction observations, ERC-1967 proxy events and decoded token receipt logs, with chain/address/block filters, deterministic block/log ordering, explicit missing timestamps, bounded export and source-level caveats.
- Open an address-centric investigation workspace from imported graph entities or a manually supplied EVM address. It consolidates chain-scoped transaction observations, decoded token logs, proxy/delegation roles, correlation edges, handoff trails, review signals, related cases and bounded JSON export.
- Explore a bounded entity neighborhood (1–3 hops) across same-chain correlation edges, imported Transfer-shaped receipt logs, shared-infrastructure evidence and transaction handoff trails. Node and edge counts are independently capped; truncation is explicit. The explorer does not infer ownership, common control, coordination or movement of the same assets.
- Interactive entity relationship graph with deterministic radial layout, selectable and pivotable address nodes, chain and hop-depth controls, evidence-type filtering, live search across addresses and provenance, clickable relationship lines, zoom, pan, an evidence inspector, a provenance ledger and portable JSON export. The visualization is not an attribution model.
- Compare two entities on the same chain using exact shared counterparties, direct observed edges, transaction hashes, case references and infrastructure metadata; export the comparison with explicit non-attribution limits.
- Seal entity comparison and entity evidence packet exports with deterministic SHA-256 integrity metadata; verification detects content changes but does not authenticate authorship or prove evidence truth.
- Evidence Gap Analysis converts explicit coverage gaps and observed evidence shapes into prioritized, explainable next verification steps: truncation recovery, proxy/delegation metadata checks, receipt and token-contract validation, handoff-leg verification, signal source revalidation and missing transaction provenance. Recommendations are deterministic review prompts, not risk scores or verdicts.
- Compare two addresses with chain-scoped evidence intersections: direct observed links, shared counterparties, transaction hashes, case references and shared infrastructure, with a portable comparison export and explicit non-attribution limits.
- Export a chain-scoped entity evidence packet (`sentinel.entity-evidence-packet.v1`) containing the bounded neighborhood, source correlation edges, related review signals, token receipt logs, handoff trails and address profiles, with case references and explicit truncation/coverage caveats.
- Portable investigation dossier export (`sentinel.investigation-dossier.v1`) bundles accepted source case reports, the correlation graph, threat-intelligence output, source filenames, generation time and explicit analytical limitations. Export is generated locally in the browser.
- Unit tests for case-report schema validation, proxy-event decoding, chronological ordering and evidence correlation.
- Unit tests for EIP-7702 parsing, bytecode decoding, capability evidence and exact ETH formatting.
- GitHub Actions CI runs the Node.js test suite on pushes and pull requests.
- Show raw observations, network context and query timestamp.
- Responsive dark security-console interface; no build step or installation required.

## Run locally

Because the application uses native JavaScript modules, serve the repository over HTTP rather than opening the file directly. With Node.js 20+, run `npx serve .` from the repository folder and open the local URL it prints. The inspector uses public RPC endpoints configured in `src/chains.js`: Cloudflare Ethereum, BNB public dataseed and Polygon public RPC. These community/public endpoints may rate-limit, change policy or be unavailable; browser access also depends on CORS. The app fails closed when the returned chain ID does not match the selected network.

## Security model

- Read-only public RPC calls only.
- No wallet connection, private-key collection, transaction signing, transaction broadcasting or funds movement.
- No claim that an account or contract is safe based solely on the absence of a delegation marker.
- A detected EIP-7702 designator is an observation, **not** proof of malicious intent.
- Current account code is not a substitute for historical authorization analysis.
- Public RPC responses are not independently attested by SENTINEL. Verify critical findings against an independent provider or trusted node.

## Scope and limitations

This is an early functional foundation, not a complete smart-contract audit platform. It currently supports three EVM networks through public RPC endpoints and does not yet provide persistent case storage or full historical tracing (the current proxy-event view scans only a bounded recent block window), contract source verification, bytecode decompilation, automated exploit simulation, monitoring, alert delivery or a calibrated risk score. The interface must not be used as the sole basis for financial or security decisions.

## Roadmap

1. Add configurable RPC providers, provider health checks and network-specific explorer links.
2. Add EIP-7702 history and authorization analysis with clearly sourced evidence.
3. Expand proxy intelligence beyond ERC-1967 and add verified-contract metadata and historical context.
4. Add indexed historical transaction tracing, persistence controls and alert delivery.
5. Add richer case timelines and safe local threat simulations.
6. Add browser-level verification, deployment hardening and independent RPC cross-checks.

## Development principles

Evidence before verdict. Explicit source and freshness. Simulations labelled as simulations. Fail closed on unavailable data. Never request secrets or execute transactions.

## License

No license has been granted yet. All rights reserved by default until a license is added.
