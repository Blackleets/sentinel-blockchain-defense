# Security Policy

## Safe-use boundary

SENTINEL is a defensive, read-only research tool. It must not:
- request or store seed phrases, private keys, passwords or wallet secrets;
- connect to a wallet for signing;
- sign, simulate-and-broadcast, or broadcast transactions;
- move assets or change account permissions;
- present an automated indicator as a definitive security audit.

## Reporting a vulnerability

Please do not publish exploit details, credentials, private keys, or sensitive personal data in a public issue. For a suspected vulnerability in SENTINEL, contact the repository maintainer privately through GitHub's available security reporting channel. Include the affected version or commit, reproducible steps, expected behaviour, actual behaviour, and impact. Allow time for investigation and remediation before public disclosure.

## Data handling

The current static application sends read-only JSON-RPC requests to the configured public Ethereum RPC endpoint. Search inputs and returned chain data are processed in the browser. The current release does not include an application backend, account system, or persistent storage layer. The RPC provider may independently process request metadata under its own policies.

## Research caveat

On-chain observations can be incomplete, delayed, or provider-dependent. A detected EIP-7702 delegation designator is not by itself evidence of compromise. Absence of a detected marker is not proof of safety.
