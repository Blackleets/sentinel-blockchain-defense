# SENTINEL — Blockchain Defense Intelligence

SENTINEL is an evidence-led, read-only Ethereum security research workspace. The first release provides a browser-based Ethereum account and transaction inspector with EIP-7702 delegation-marker detection.

**Live repository:** https://github.com/Blackleets/sentinel-blockchain-defense

## Current release

- Inspect Ethereum Mainnet account addresses using `eth_getCode`, `eth_getBalance`, `eth_getTransactionCount` and `eth_blockNumber`.
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
- Evidence correlation engine for comparing multiple user-supplied case reports: shared EIP-7702 delegation targets, ERC-1967 implementations/admins/beacons, resolved implementations and observed transaction participants. Relationships remain evidence-only, never a maliciousness verdict.\n- Unit tests for case-report schema validation, proxy-event decoding, chronological ordering and evidence correlation.
- Unit tests for EIP-7702 parsing, bytecode decoding, capability evidence and exact ETH formatting.
- GitHub Actions CI runs the Node.js test suite on pushes and pull requests.
- Show raw observations, network context and query timestamp.
- Responsive dark security-console interface; no build step or installation required.

## Run locally

Because the application uses native JavaScript modules, serve the repository over HTTP rather than opening the file directly. With Node.js 20+, run `npx serve .` from the repository folder and open the local URL it prints. The inspector calls the public Cloudflare Ethereum JSON-RPC endpoint at `https://cloudflare-eth.com`. Browser access depends on endpoint availability and CORS policy.

## Security model

- Read-only public RPC calls only.
- No wallet connection, private-key collection, transaction signing, transaction broadcasting or funds movement.
- No claim that an account or contract is safe based solely on the absence of a delegation marker.
- A detected EIP-7702 designator is an observation, **not** proof of malicious intent.
- Current account code is not a substitute for historical authorization analysis.
- Public RPC responses are not independently attested by SENTINEL. Verify critical findings against an independent provider or trusted node.

## Scope and limitations

This is an early functional foundation, not a complete smart-contract audit platform. It currently targets Ethereum Mainnet and does not yet provide persistent case storage or full historical tracing (the current proxy-event view scans only a bounded recent block window), contract source verification, bytecode decompilation, automated exploit simulation, monitoring, alert delivery or a calibrated risk score. The interface must not be used as the sole basis for financial or security decisions.

## Roadmap

1. Add configurable RPC providers, chain selection and provider health checks.
2. Add EIP-7702 history and authorization analysis with clearly sourced evidence.
3. Expand proxy intelligence beyond ERC-1967 and add verified-contract metadata and historical context.
4. Add explainable risk indicators with evidence links and confidence boundaries.
5. Add forensic timelines, exportable case reports and safe local threat simulations.
6. Add automated tests, CI and deployment hardening.

## Development principles

Evidence before verdict. Explicit source and freshness. Simulations labelled as simulations. Fail closed on unavailable data. Never request secrets or execute transactions.

## License

No license has been granted yet. All rights reserved by default until a license is added.
