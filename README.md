# evm-disasm

A tiny, dependency-free EVM bytecode disassembler in pure Python.

Feed it raw contract bytecode (hex string) and get a readable listing of
program counters, mnemonics, pushed operands, and base gas costs.
Dynamic-cost opcodes (SSTORE, CALL, LOGn, ...) are marked `gas=-`.

```bash
$ python evm_disasm.py 6080604052
0000  PUSH1      0x80                                gas=3
0002  PUSH1      0x40                                gas=3
0004  MSTORE                                         gas=-
# 3 instructions
```

## Features

- Full EVM opcode table: PUSH1–PUSH32, DUP1–DUP16, SWAP1–SWAP16, LOG0–LOG4,
  plus arithmetic, comparison, memory/storage, jumps, calls, and system ops
- Base gas costs (post-Berlin static values); `gas=-` where cost is dynamic
- Graceful handling of unknown opcodes and truncated PUSH operands, so
  program counters stay exact
- `disassemble()` / `disassemble_hex()` API plus a CLI with `--demo` and `--test`

## Usage

```bash
python evm_disasm.py <hex>     # disassemble bytecode (0x prefix optional)
python evm_disasm.py --demo    # disassemble the built-in solc-preamble sample
python evm_disasm.py --test    # run the doctests
```

```python
from evm_disasm import disassemble_hex

for ins in disassemble_hex("0x600101"):
    print(ins.line())
```

## Tests

10 doctests, run with `python evm_disasm.py --test`.
