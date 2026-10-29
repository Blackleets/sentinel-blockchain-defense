/**
 * Parse the current account code for the EIP-7702 delegation designator.
 * Expected bytecode: 0xef0100 followed by exactly one 20-byte address.
 * This is a state observation, not a maliciousness verdict.
 */
export function inspectDelegationCode(code) {
  if (typeof code !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(code)) {
    return { isDelegated: false, status: "invalid-code", implementationAddress: null };
  }

  if (code === "0x") {
    return { isDelegated: false, status: "no-code", implementationAddress: null };
  }

  const normalized = code.toLowerCase();
  if (!normalized.startsWith("0xef0100")) {
    return { isDelegated: false, status: "ordinary-code", implementationAddress: null };
  }

  if (normalized.length !== 48) {
    return { isDelegated: false, status: "malformed-designator", implementationAddress: null };
  }

  return {
    isDelegated: true,
    status: "delegated",
    implementationAddress: "0x" + normalized.slice(8)
  };
}
