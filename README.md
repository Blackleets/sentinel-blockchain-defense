# SENTINEL — Blockchain Defense Intelligence

SENTINEL is an evidence-led, read-only Ethereum security research workspace. The first release provides a browser-based Ethereum account and transaction inspector with EIP-7702 delegation-marker detection.

**Live repository:** https://github.com/Blackleets/sentinel-blockchain-defense

## Current release

- Inspect Ethereum Mainnet account addresses using `eth_getCode`, `eth_getBalance`, `eth_getTransactionCount` and `eth_blockNumber`.
- Inspect transaction hashes using `eth_getTransactionByHash`, `eth_getTransactionReceipt` and block metadata.
- Detect the EIP-7702 delegated-code designator prefix `0xef0100`, extract the 20-byte delegation target, and inspect whether that target currently has deployed code.
- Unit tests for valid, empty, ordinary, malformed and invalid account-code inputs.
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

This is an early functional foundation, not a complete smart-contract audit platform. It currently targets Ethereum Mainnet and does not yet provide historical tracing, contract source verification, bytecode decompilation, automated exploit simulation, monitoring, alert delivery or a calibrated risk score. The interface must not be used as the sole basis for financial or security decisions.

## Roadmap

1. Add configurable RPC providers, chain selection and provider health checks.
2. Add EIP-7702 history and authorization analysis with clearly sourced evidence.
3. Add verified-contract metadata and bytecode-level inspection.
4. Add explainable risk indicators with evidence links and confidence boundaries.
5. Add forensic timelines, exportable case reports and safe local threat simulations.
6. Add automated tests, CI and deployment hardening.

## Development principles

Evidence before verdict. Explicit source and freshness. Simulations labelled as simulations. Fail closed on unavailable data. Never request secrets or execute transactions.

## License

No license has been granted yet. All rights reserved by default until a license is added.
