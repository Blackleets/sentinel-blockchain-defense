export const ERC1967_SLOTS = Object.freeze({
  implementation: "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
  admin: "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
  beacon: "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
});

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export function decodeStorageAddress(word) {
  if (typeof word !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(word)) {
    return { status: "invalid-storage-word", address: null };
  }
  const address = "0x" + word.slice(-40).toLowerCase();
  return address === ZERO_ADDRESS
    ? { status: "empty", address: null }
    : { status: "present", address };
}

export function inspectErc1967Slots({ implementationWord, adminWord, beaconWord }) {
  const implementation = decodeStorageAddress(implementationWord);
  const admin = decodeStorageAddress(adminWord);
  const beacon = decodeStorageAddress(beaconWord);
  const kind = implementation.address ? "implementation" : beacon.address ? "beacon" : "not-detected";
  return {
    kind,
    implementation: implementation.address,
    admin: admin.address,
    beacon: beacon.address,
    statuses: { implementation: implementation.status, admin: admin.status, beacon: beacon.status }
  };
}
