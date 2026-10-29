export const ERC1967_EVENT_TOPICS = Object.freeze({
  upgraded: "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b",
  adminChanged: "0x7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f",
  beaconUpgraded: "0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e"
});

function topicAddress(topic) {
  if (typeof topic !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(topic)) return null;
  const address = "0x" + topic.slice(-40).toLowerCase();
  return address === "0x0000000000000000000000000000000000000000" ? null : address;
}

function dataAddress(data, wordIndex) {
  if (typeof data !== "string" || !/^0x(?:[0-9a-fA-F]{64})+$/.test(data)) return null;
  const start = 2 + wordIndex * 64;
  if (start + 64 > data.length) return null;
  return topicAddress("0x" + data.slice(start, start + 64));
}

export function decodeErc1967Log(log) {
  if (!log || !Array.isArray(log.topics) || typeof log.topics[0] !== "string") return null;
  const topic = log.topics[0].toLowerCase();
  let event, changes = {};
  if (topic === ERC1967_EVENT_TOPICS.upgraded) {
    event = "Upgraded";
    changes.implementation = topicAddress(log.topics[1]);
    if (!changes.implementation) return null;
  } else if (topic === ERC1967_EVENT_TOPICS.adminChanged) {
    event = "AdminChanged";
    changes.previousAdmin = dataAddress(log.data, 0);
    changes.newAdmin = dataAddress(log.data, 1);
    if (typeof log.data !== "string" || log.data.length !== 130) return null;
  } else if (topic === ERC1967_EVENT_TOPICS.beaconUpgraded) {
    event = "BeaconUpgraded";
    changes.beacon = topicAddress(log.topics[1]);
    if (!changes.beacon) return null;
  } else return null;

  return {
    event,
    address: typeof log.address === "string" ? log.address.toLowerCase() : null,
    blockNumber: log.blockNumber || null,
    transactionHash: log.transactionHash || null,
    transactionIndex: log.transactionIndex || null,
    logIndex: log.logIndex || null,
    changes
  };
}

export function decodeErc1967Logs(logs) {
  if (!Array.isArray(logs)) return [];
  return logs.map(decodeErc1967Log).filter(Boolean).sort((a, b) => {
    const block = BigInt(a.blockNumber || "0x0") - BigInt(b.blockNumber || "0x0");
    if (block !== 0n) return block < 0n ? -1 : 1;
    const index = BigInt(a.logIndex || "0x0") - BigInt(b.logIndex || "0x0");
    return index < 0n ? -1 : index > 0n ? 1 : 0;
  });
}
