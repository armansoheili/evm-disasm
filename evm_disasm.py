#!/usr/bin/env python3
"""evm_disasm.py - a tiny, dependency-free EVM bytecode disassembler.

Parses raw EVM bytecode (as hex or bytes) into a readable listing of
program-counter, opcode, mnemonic, pushed operand, and base gas cost.
Dynamic-cost opcodes (SSTORE, CALL, LOGn, EXP, ...) are marked with '-'.
"""

from __future__ import annotations

import argparse
import doctest
import sys
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Opcode table: opcode -> (mnemonic, base_gas)
# base_gas is the STATIC portion only (post-Berlin / current values).
# None means the cost is dynamic (memory expansion, storage access, etc.).
# ---------------------------------------------------------------------------

OPCODES: dict[int, tuple[str, int | None]] = {
    0x00: ("STOP", 0),
    0x01: ("ADD", 3),
    0x02: ("MUL", 5),
    0x03: ("SUB", 3),
    0x04: ("DIV", 5),
    0x05: ("SDIV", 5),
    0x06: ("MOD", 5),
    0x07: ("SMOD", 5),
    0x08: ("ADDMOD", 8),
    0x09: ("MULMOD", 8),
    0x0A: ("EXP", None),
    0x0B: ("SIGNEXTEND", 5),
    0x10: ("LT", 3),
    0x11: ("GT", 3),
    0x12: ("SLT", 3),
    0x13: ("SGT", 3),
    0x14: ("EQ", 3),
    0x15: ("ISZERO", 3),
    0x16: ("AND", 3),
    0x17: ("OR", 3),
    0x18: ("XOR", 3),
    0x19: ("NOT", 3),
    0x1A: ("BYTE", 3),
    0x1B: ("SHL", 3),
    0x1C: ("SHR", 3),
    0x1D: ("SAR", 3),
    0x20: ("SHA3", None),  # aka KECCAK256
    0x27: ("MCOPY", None),
    0x30: ("ADDRESS", 2),
    0x31: ("BALANCE", 100),
    0x32: ("ORIGIN", 2),
    0x33: ("CALLER", 2),
    0x34: ("CALLVALUE", 2),
    0x35: ("CALLDATALOAD", 3),
    0x36: ("CALLDATASIZE", 2),
    0x37: ("CALLDATACOPY", None),
    0x38: ("CODESIZE", 2),
    0x39: ("CODECOPY", None),
    0x3A: ("GASPRICE", 2),
    0x3B: ("EXTCODESIZE", 100),
    0x3C: ("EXTCODECOPY", None),
    0x3D: ("RETURNDATASIZE", 2),
    0x3E: ("RETURNDATACOPY", None),
    0x3F: ("EXTCODEHASH", 100),
    0x40: ("BLOCKHASH", 20),
    0x41: ("COINBASE", 2),
    0x42: ("TIMESTAMP", 2),
    0x43: ("NUMBER", 2),
    0x44: ("PREVRANDAO", 2),  # formerly DIFFICULTY
    0x45: ("GASLIMIT", 2),
    0x46: ("CHAINID", 2),
    0x47: ("SELFBALANCE", 5),
    0x48: ("BASEFEE", 2),
    0x50: ("POP", 2),
    0x51: ("MLOAD", None),
    0x52: ("MSTORE", None),
    0x53: ("MSTORE8", None),
    0x54: ("SLOAD", 100),
    0x55: ("SSTORE", None),
    0x56: ("JUMP", 8),
    0x57: ("JUMPI", 10),
    0x58: ("PC", 2),
    0x59: ("MSIZE", 2),
    0x5A: ("GAS", 2),
    0x5B: ("JUMPDEST", 1),
    0x5C: ("TLOAD", 100),
    0x5D: ("TSTORE", 100),
    0xF0: ("CREATE", None),
    0xF1: ("CALL", None),
    0xF2: ("CALLCODE", None),
    0xF3: ("RETURN", 0),
    0xF4: ("DELEGATECALL", None),
    0xF5: ("CREATE2", None),
    0xFA: ("STATICCALL", None),
    0xFD: ("REVERT", 0),
    0xFE: ("INVALID", 0),
    0xFF: ("SELFDESTRUCT", None),
}

# PUSH1..PUSH32, DUP1..DUP16, SWAP1..SWAP16, LOG0..LOG4
for _i in range(32):
    OPCODES[0x60 + _i] = (f"PUSH{_i + 1}", 3)
for _i in range(16):
    OPCODES[0x80 + _i] = (f"DUP{_i + 1}", 3)
for _i in range(16):
    OPCODES[0x90 + _i] = (f"SWAP{_i + 1}", 3)
for _i in range(5):
    OPCODES[0xA0 + _i] = (f"LOG{_i}", None)

del _i


def is_push(opcode: int) -> bool:
    """True for PUSH1..PUSH32 opcodes.

    >>> is_push(0x60) and is_push(0x7F) and not is_push(0x58)
    True
    """
    return 0x60 <= opcode <= 0x7F


def push_size(opcode: int) -> int:
    """Number of immediate bytes a PUSH opcode consumes.

    >>> push_size(0x60), push_size(0x7F)
    (1, 32)
    """
    return opcode - 0x5F


@dataclass
class Instruction:
    pc: int
    opcode: int
    mnemonic: str
    operand: bytes
    gas: int | None

    def line(self) -> str:
        op = f" 0x{self.operand.hex()}" if self.operand else ""
        gas = str(self.gas) if self.gas is not None else "-"
        return f"{self.pc:04x}  {self.mnemonic:<10}{op:<36} gas={gas}"


def disassemble(code: bytes) -> list[Instruction]:
    """Disassemble raw EVM bytecode into Instructions.

    >>> ins = disassemble(bytes.fromhex("6080604052"))
    >>> [(i.pc, i.mnemonic, i.operand.hex()) for i in ins]
    [(0, 'PUSH1', '80'), (2, 'PUSH1', '40'), (4, 'MSTORE', '')]

    Unknown opcodes are kept as UNKNOWN so offsets stay exact:

    >>> ins = disassemble(bytes.fromhex("0c"))
    >>> [(i.pc, i.mnemonic) for i in ins]
    [(0, 'UNKNOWN')]

    A truncated PUSH (bytecode ends mid-operand) yields what is left:

    >>> ins = disassemble(bytes.fromhex("60"))
    >>> [(i.pc, i.mnemonic, i.operand.hex()) for i in ins]
    [(0, 'PUSH1', '')]
    """
    out: list[Instruction] = []
    pc = 0
    while pc < len(code):
        opcode = code[pc]
        start = pc
        mnemonic, gas = OPCODES.get(opcode, ("UNKNOWN", None))
        operand = b""
        if is_push(opcode):
            want = push_size(opcode)
            operand = code[pc + 1 : pc + 1 + want]
            pc += 1 + len(operand)
        else:
            pc += 1
        out.append(Instruction(start, opcode, mnemonic, operand, gas))
    return out


def disassemble_hex(hexcode: str) -> list[Instruction]:
    """Disassemble a hex string (with or without a 0x prefix).

    >>> [i.mnemonic for i in disassemble_hex("0x600101")]
    ['PUSH1', 'ADD']
    """
    s = hexcode.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    return disassemble(bytes.fromhex(s))


def format_listing(ins: list[Instruction]) -> str:
    """Render instructions as a text listing.

    >>> print(format_listing(disassemble_hex("600035")))
    0000  PUSH1      0x00                                gas=3
    0002  CALLDATALOAD                                     gas=3
    """
    return "\n".join(i.line() for i in ins)


DEMO_HEX = (
    "6080604052"      # PUSH1 0x80, PUSH1 0x40, MSTORE  (free-memory pointer)
    "348015600f57"    # CALLVALUE, DUP1, ISZERO, PUSH1 0x0f, JUMPI
    "600080fd"        # PUSH1 0x00, DUP1, REVERT  (non-payable guard)
    "5b50"            # JUMPDEST, POP
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Disassemble EVM bytecode.")
    ap.add_argument("hexcode", nargs="?", help="bytecode as hex string (0x optional)")
    ap.add_argument("--demo", action="store_true", help="disassemble the built-in demo snippet")
    ap.add_argument("--test", action="store_true", help="run doctests")
    args = ap.parse_args(argv)

    if args.test:
        results = doctest.testmod(verbose=False)
        print(f"doctests: {results.attempted} run, {results.failed} failed")
        return 1 if results.failed else 0

    if args.demo or not args.hexcode:
        print(f"# demo: {DEMO_HEX}")
        ins = disassemble_hex(DEMO_HEX)
    else:
        ins = disassemble_hex(args.hexcode)
    print(format_listing(ins))
    print(f"# {len(ins)} instructions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
