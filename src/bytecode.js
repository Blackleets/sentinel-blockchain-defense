const OPCODES = new Map([
  [0x00,"STOP"],[0x01,"ADD"],[0x02,"MUL"],[0x03,"SUB"],[0x04,"DIV"],[0x05,"SDIV"],[0x06,"MOD"],[0x07,"SMOD"],[0x08,"ADDMOD"],[0x09,"MULMOD"],[0x0a,"EXP"],[0x0b,"SIGNEXTEND"],
  [0x10,"LT"],[0x11,"GT"],[0x12,"SLT"],[0x13,"SGT"],[0x14,"EQ"],[0x15,"ISZERO"],[0x16,"AND"],[0x17,"OR"],[0x18,"XOR"],[0x19,"NOT"],[0x1a,"BYTE"],[0x1b,"SHL"],[0x1c,"SHR"],[0x1d,"SAR"],
  [0x20,"KECCAK256"],[0x30,"ADDRESS"],[0x31,"BALANCE"],[0x32,"ORIGIN"],[0x33,"CALLER"],[0x34,"CALLVALUE"],[0x35,"CALLDATALOAD"],[0x36,"CALLDATASIZE"],[0x37,"CALLDATACOPY"],[0x38,"CODESIZE"],[0x39,"CODECOPY"],[0x3a,"GASPRICE"],[0x3b,"EXTCODESIZE"],[0x3c,"EXTCODECOPY"],[0x3d,"RETURNDATASIZE"],[0x3e,"RETURNDATACOPY"],[0x3f,"EXTCODEHASH"],
  [0x40,"BLOCKHASH"],[0x41,"COINBASE"],[0x42,"TIMESTAMP"],[0x43,"NUMBER"],[0x44,"PREVRANDAO"],[0x45,"GASLIMIT"],[0x46,"CHAINID"],[0x47,"SELFBALANCE"],[0x48,"BASEFEE"],[0x49,"BLOBHASH"],[0x4a,"BLOBBASEFEE"],
  [0x50,"POP"],[0x51,"MLOAD"],[0x52,"MSTORE"],[0x53,"MSTORE8"],[0x54,"SLOAD"],[0x55,"SSTORE"],[0x56,"JUMP"],[0x57,"JUMPI"],[0x58,"PC"],[0x59,"MSIZE"],[0x5a,"GAS"],[0x5b,"JUMPDEST"],[0x5c,"TLOAD"],[0x5d,"TSTORE"],[0x5e,"MCOPY"],[0x5f,"PUSH0"],
  [0xf0,"CREATE"],[0xf1,"CALL"],[0xf2,"CALLCODE"],[0xf3,"RETURN"],[0xf4,"DELEGATECALL"],[0xf5,"CREATE2"],[0xfa,"STATICCALL"],[0xfd,"REVERT"],[0xfe,"INVALID"],[0xff,"SELFDESTRUCT"]
]);

const RULES = [
  ["DELEGATECALL","External code executes in this contract's storage context; review target control and storage assumptions."],
  ["CALLCODE","Legacy external execution in this contract's storage context; review carefully."],
  ["CALL","External message call capability; inspect destination and value/data constraints."],
  ["STATICCALL","External read-only call capability; inspect dependencies and return-data handling."],
  ["CREATE","Contract creation capability; inspect creation bytecode and authorization."],
  ["CREATE2","Deterministic contract creation capability; inspect salt and init-code controls."],
  ["SELFDESTRUCT","Sensitive termination/balance-transfer opcode present; semantics depend on fork and account history."],
  ["SSTORE","Persistent storage writes are present; this is normal for stateful contracts."],
  ["TSTORE","Transient storage writes are present; inspect transaction-scoped state assumptions."]
];

const UPGRADE_SELECTORS = Object.freeze({
  "0x52d1902d": "proxiableUUID() — ERC-1822 compatibility signal",
  "0x3659cfe6": "upgradeTo(address) — legacy UUPS upgrade entry-point candidate",
  "0x4f1ef286": "upgradeToAndCall(address,bytes) — UUPS upgrade entry-point candidate"
});

function parseCode(code) {
  if (typeof code !== "string" || !/^0x(?:[0-9a-fA-F]{2})*$/.test(code)) {
    throw new TypeError("Expected 0x-prefixed, even-length hexadecimal bytecode");
  }
  return code.slice(2).toLowerCase();
}

export function disassembleBytecode(code) {
  const hex = parseCode(code);
  const instructions = [];
  for (let pc = 0; pc < hex.length / 2;) {
    const opcode = parseInt(hex.slice(pc * 2, pc * 2 + 2), 16);
    const name = opcode >= 0x60 && opcode <= 0x7f ? `PUSH${opcode - 0x5f}` : OPCODES.get(opcode) || (opcode >= 0x80 && opcode <= 0x8f ? `DUP${opcode - 0x7f}` : opcode >= 0x90 && opcode <= 0x9f ? `SWAP${opcode - 0x8f}` : opcode >= 0xa0 && opcode <= 0xa4 ? `LOG${opcode - 0xa0}` : "UNKNOWN");
    const width = opcode >= 0x60 && opcode <= 0x7f ? opcode - 0x5f : 0;
    const available = Math.min(width, Math.max(0, hex.length / 2 - pc - 1));
    const immediate = width ? hex.slice((pc + 1) * 2, (pc + 1 + available) * 2) : null;
    instructions.push({ pc, opcode: "0x" + opcode.toString(16).padStart(2,"0"), name, immediate, truncated: available < width });
    pc += 1 + width;
  }
  return instructions;
}

export function analyzeBytecode(code) {
  const hex = parseCode(code);
  const instructions = disassembleBytecode(code);
  const counts = {};
  const selectors = [];
  for (const instruction of instructions) {
    counts[instruction.name] = (counts[instruction.name] || 0) + 1;
    if (instruction.name === "PUSH4" && instruction.immediate?.length === 8 && !instruction.truncated) {
      const selector = "0x" + instruction.immediate;
      if (!selectors.includes(selector)) selectors.push(selector);
    }
  }
  const evidence = RULES.filter(([name]) => counts[name]).map(([capability, explanation]) => ({
    capability, count: counts[capability], explanation,
    severity: capability === "DELEGATECALL" || capability === "CALLCODE" || capability === "SELFDESTRUCT" ? "review" : "info"
  }));
  return {
    byteLength: hex.length / 2,
    instructionCount: instructions.length,
    opcodeCounts: counts,
    evidence,
    selectorCandidates: selectors,
    upgradeSurfaceIndicators: selectors.filter(selector => UPGRADE_SELECTORS[selector]).map(selector => ({ selector, label: UPGRADE_SELECTORS[selector] })),
    unknownOpcodeCount: counts.UNKNOWN || 0,
    truncatedPushCount: instructions.filter(item => item.truncated).length
  };
}
