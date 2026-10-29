# SENTINEL Architecture

## Release 0 — browser-only inspector

The first release is deliberately small and auditable:

- `index.html`: semantic interface, responsive styling and browser-side inspection logic.
- Public RPC: Cloudflare Ethereum JSON-RPC endpoint.
- No backend, database, wallet SDK, authentication, secrets or transaction-writing methods.

### Read paths

| User input | JSON-RPC methods | Output |
|---|---|---|
| 20-byte address | `eth_getCode`, `eth_getBalance`, `eth_getTransactionCount`, `eth_blockNumber` | Current code, balance, nonce, block and EIP-7702 designator observation |
| 32-byte transaction hash | `eth_getTransactionByHash`, `eth_getTransactionReceipt`, `eth_getBlockByNumber` | Transaction participants, value, receipt status, gas and block timestamp |

## EIP-7702 detection

The inspector checks whether current account code begins with the 3-byte designator `0xef0100`. For a matching 23-byte code value, the remaining 20 bytes are displayed as the delegation target.

This is a current-state observation only. It does not reconstruct the authorization tuple, prove who authorized it, establish intent, inspect the delegated implementation, or identify historical changes. Those require additional evidence and historical data sources.

## Contract bytecode intelligence (release 1)

The browser can disassemble current runtime bytecode and report conservative capability evidence. The disassembler advances over PUSH1–PUSH32 immediate data, so byte values inside PUSH payloads are not misclassified as opcodes.

Current observations include byte length, decoded instruction count, unknown opcode count, selected capability counts (CALL, DELEGATECALL, CALLCODE, STATICCALL, CREATE, CREATE2, SELFDESTRUCT, SSTORE and TSTORE), and PUSH4 selector candidates. Selector candidates are not verified ABI functions.

These are capability indicators, not vulnerability findings. In particular, CALL and SSTORE are common in ordinary contracts; DELEGATECALL and SELFDESTRUCT require contextual review and are not verdicts. The current analysis is limited to runtime bytecode at the latest block, does not decompile code, resolve proxies generally, verify source, or reconstruct historical behavior.

## ERC-1967 proxy inspection (release 2)

For every inspected address, the client reads the standardized implementation, admin and beacon storage slots defined by ERC-1967. It extracts the low 20 bytes as an address and distinguishes empty slots from malformed values. If the implementation slot is empty and a beacon address is present, it makes a read-only `eth_call` to the beacon's `implementation()` selector (`0x5c60da1b`).

The engine reports the implementation/admin/beacon observations and analyzes the effective implementation bytecode when it can resolve one. A populated admin slot identifies the address stored in that slot; it does not by itself prove what permissions that address has in the implementation or whether every upgrade path is controlled by it. Beacon resolution may fail, and non-ERC-1967 proxy patterns are outside this detector.

Reference: [ERC-1967 specification](https://eips.ethereum.org/EIPS/eip-1967).

## Planned modular architecture

Future expansion should keep these domains separated:

- **Data adapters:** chain RPC providers, provider health, chain metadata and source timestamps.
- **Account intelligence:** account code, delegation state, nonce and balance observations.
- **Contract intelligence:** verified source metadata, bytecode fingerprints and static-analysis findings.
- **Forensics:** block-ordered event evidence and reproducible case snapshots.
- **Risk engine:** transparent rules, evidence references, confidence and explicit unknown states.
- **Presentation:** dashboard, explorer, case view and exportable reports.

## Engineering constraints

1. Keep every chain read attributable to a provider, chain ID and block context.
2. Distinguish unavailable data from negative findings.
3. Never infer malicious intent from a single technical marker.
4. Treat RPC responses and contract metadata as untrusted external input.
5. Keep simulations isolated and clearly labelled; never broadcast them.
6. Do not add wallet signing or private-key handling.
7. Add automated tests before introducing scoring or automated alerts.
