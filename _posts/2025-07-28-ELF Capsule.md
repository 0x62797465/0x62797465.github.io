---
title: ELF Capsule
category: UIUCTF-2025
chall_description: 
points: 0
solves: 0
tags: rev
date: 2025-07-28
comments: false
---

This was a riscv64 kernel with a VM from UIUCTF. I almost solved it, but the CTF ended before I had the chance to finish. 

---

# Kernel Analysis
This is a riscv64 kernel that executes a child process which contains the actual challenge. The entry point is as follows:
```c
li              t0, -1
csrw            medeleg, t0
csrw            mideleg, t0
csrw            pmpaddr0, t0
csrsi           pmpcfg0, 0Fh
la              t0, exit_halt_wtv
csrw            mtvec, t0
csrw            stvec, t0
lui             t0, 40h # '@'
csrs            mstatus, t0
csrc            mstatus, t0
csrs            sstatus, t0
csrc            sstatus, t0
li              t0, 1080h
li              t1, 800h
csrc            mstatus, t0
csrs            mstatus, t1
la              t0, j_set_up_program
csrw            mepc, t0
mret
```
What this does is it passes all interrupts/exceptions to supervisor mode, meaning it gets handed off to the kernel. It also does some other set up which is not really relevant before jumping (really returning) to `j_set_up_program`. `j_set_up_program` jumps to `set_up_program` which is as follows:
```c
void __noreturn set_up_program()
{
  __int64 v0; // [sp+8h] [-18h] BYREF

  uart_initialization();                        // uart stuff
  load_program(og_elf, &v0);                    // loads program into specific memory
  setup(0x800FFFFFLL, v0, (__int64)&idk);   // specifies where execution should go and
}
```
The `uart_initialization` and `load_program` functions are not too important. `load_program` *seems* to load the elf into `v0`. This is the code for `setup`:
```c
la              ra, exit_halt_wtv
csrw            sscratch, a2
mv              sp, a0
li              t0, 100h
csrc            sstatus, t0
li              t0, 20h # ' '
csrs            sstatus, t0
csrw            sepc, a1
la              t1, trap_handler
csrw            stvec, t1
sret
```
This makes `a0` the stack pointer, and `a1` the address the code returns to. In the context of `set_up_program`, `0x800FFFFFLL` is the stack pointer and `v0` (which contains the loaded ELF) is where execution starts. It also sets up `trap_handler` to handle traps/exceptions. `trap_handler` is essentially a wrapper for the `VM`. So, from a high level, this is how the program operates:
```
┌──────┐              
│Kernel│              
└──┬───┘              
   │                  
   │                  
┌──▼───┐Fault┌───────┐
│Child ┼─────►Handler│
└──▲───┘     └───┬───┘
   │             │    
   │             │    
   │           ┌─▼─┐  
   └───────────┤VM │  
               └───┘  
```
## VM Analysis
The setup is as follows:
```c
  __asm { csrr            a0, scause }          // cause of fault, 5 or 7
                                                // a faulting load 
                                                // instruction causes 
                                                // it to be 7.
                                                // eg sd a4, 0(a5) will
                                                // cause it to be 7.
                                                // but ld a4, 0(a5) would
                                                // cause it to be 5.
  if ( result < 0 )
    exit_halt_wtv();
  v43 = *a42;
  if ( result != 5 )
  {
    if ( result == 7 )
    {
      __asm { csrr            a3, stval }       // contains data stored in faulting instruction, in this case the opcode
      v45 = a42 + 1;
      result = *(&a9 + ((v43 >> 20) & 0x1FLL));
      v46 = (105 * (_A3 ^ 0x420)) & 0xFFF;
	...
	}
	...
  }
  __asm { csrr            a3, stval }           // data held in faulting instruction's register, opcode in this case
  v50 = (105 * (_A3 ^ 0x420)) & 0xFFF;
  v51 = (v43 >> 7) & 0x1FLL; // a9, seen in the previous setup, is
                             // adding on later	
  ... 
```
All this does is load the cause of the fault into `a0` aka `result` and executes different instructions based on it. A load fault leads to it being 5, a store fault causes it to be 7. It also loads the faulting address into `a3`. Then a decoding step is done: `(105 * (_A3 ^ 0x420)) & 0xFFF`. The argument is also loaded via `result = *(&a9 + ((v43 >> 20) & 0x1FLL))`. Here is an example:
```
[-0x22d].q = 1
```
This is a write to `-0x22d` or `0xfffffffffffffdd3`. `(105 * (0xfffffffffffffdd3 ^ 0x420)) & 0xFFF` is `0x4ab`. In the switch statement:
```c
        if ( v46 == 0x4AB )
        {
          v72 = (char *)off_80005000;
          *(_QWORD *)off_80005000 = result;     // push
          off_80005000 = v72 + 8;
          return result;
        }
```
So `[-0x22d].q = 1` is `push 1`. The VM itself executes certain instructions under mode 7 which only operate on one piece of the stack. So:
```c
          if ( v46 == 1401 )
          {
            *((_QWORD *)off_80005000 - 1) |= result;// or
            return result;
          }
```
Does an `or` operation on the top of the stack. Other instructions in this mode include `puts`, `push`, `xor`, `loop` (initialization), `cryptographic stuff`, `add`, `mul`, and `rol`. The `loop` instruction is used as followed:
```
loop 5
...
loop
```
So the code in between the instructions gets executed 6 times (not 5). The second loop instruction is in mode 5. For mode 5, instructions operate on the top two values and store the result in a register. So this:
```c
      if ( v50 == 1401 )
      {
        v61 = *((_QWORD *)off_80005000 - 2);
        v62 = *((_QWORD *)off_80005000 - 1);
        off_80005000 = (_UNKNOWN *)((char *)off_80005000 - 16);
        *(&a9 + v51) = v61 | v62;               // or using two stack values
        return result;
      }
```
`pop`'s both 8 byte values off the stack, `or`'s the values and stores the result in a register (usually `a4`). Other instructions include `xor`, `add`, `mul`, `rol`, `pop`, `getchar`, and `loop`.
# Child Analysis - Disassembly and Hurdles
The child looks as follows:
```
   0 @ 80100004  int64_t var_8 = s0
   1 @ 80100018  [0x421].q = "What is the flag?"
   2 @ 80100028  [-0x22c].q = 1
   3 @ 80100038  [-0x22c].q = 2
   4 @ 80100044  int64_t a4 = [-0x22c].q
   5 @ 8010004c  if (a4 != 2) then 6 else 7
```
Clearly, we need a disassembler to work on top of this one. Analyzing the disassembly itself would be hard, because the format changes when computing the address to write to/read from. Thankfully, as shown above, Binary Ninja's MLIL (medium level intermediate language) works perfectly. The script I used extracts the addresses read from/written to, computes the obfuscation thing (`(105 * (x ^ 0x420)) & 0xFFF`), uses a lookup table, and comments the mnemonic along with the argument. So our old code becomes:
```
   0 @ 80100004  int64_t var_8 = s0
   1 @ 80100018  [0x421].q = "What is the flag?"  // puts 0x80101000
   2 @ 80100028  [0xfffffffffffffdd4].q = 1  // push 1
   3 @ 80100038  [-0x22c].q = 2  // push 2
   4 @ 80100044  int64_t a4 = [-0x22c].q  // pop a4 
   5 @ 8010004c  if (a4 != 2) then 6 else 7
```
There is one more hurdle we have to get through. Things like this happens:
```
  16 @ 8010007c  int64_t var_18_1 = 0
  17 @ 80100088  [0x657].q = 0xf  // ctrl b3 15
  18 @ 80100094  int64_t a4_2 = arg9
  19 @ 80100098  [-0x22c].q = a4_2  // push a4_2
```
`arg9` is a mystery value, how is it assigned? Well `var_18` is `sp-0x18` and `arg9` is `sp+0xffe8`. You may notice that `0x10000-0x18=0xffe8`, somehow `arg9` and `var_18` are the same. 
# Child Analysis - Manual Analysis
The code starts with:
```
   0 @ 80100004  int64_t var_8 = s0
   1 @ 80100018  [0x421].q = "What is the flag?"  // puts 0x80101000
   2 @ 80100028  [0xfffffffffffffdd4].q = 1  // push 1
   3 @ 80100038  [-0x22c].q = 2  // push 2
   4 @ 80100044  int64_t a4 = [-0x22c].q  // pop a4 
   5 @ 8010004c  if (a4 != 2) then 6 else 7
   7 @ 8010004c  goto 10 @ 0x80100058
   10 @ 80100058  int64_t a4_1 = [-0x22c].q  // pop a4 
   11 @ 80100060  if (a4_1 == 1) then 14 else 15

```
This can be simplified to:
```python
puts("What is the flag?")
push 1
push 2
pop a4
if (a4 != 2):
	wrong()
pop a4
if (a4 != 1):
	wrong()
```
This is just a kind of sanity check, nothing too bad. The next section of code seems to be just initialization of memory, static analysis can be avoided because these values can be dumped at runtime (which we will do later). The input loop is as follows:
```
  76 @ 80100338  [0x657].q = a4_13  // ctrl b3 a4_13
  77 @ 80100340  a5_9 = zx.q([0x421].b)  // getchar
  78 @ 80100344  var_41_1 = a5_9
  79 @ 80100348  a5_10 = arg7
  80 @ 8010034c  a4_14 = zx.q(a5_10)
  81 @ 80100354  if (a4_14 == 0xa) then 82 else 83

  82 @ 80100354  jump(&data_801003c4 => 84 @ &data_801003c4)

  83 @ 80100354  goto 85 @ 0x80100360

  84 @ 801003c4  goto 97 @ 0x801003cc

  85 @ 80100360  a4_15 = zx.q(arg7)
  86 @ 80100364  [-0x22c].q = a4_15  // push a4_15
  87 @ 80100374  [-0x22c].q = -1  // push -1
  88 @ 80100384  a4_16 = [0x74b].q  // xor stack values 
  89 @ 80100388  [-0x22c].q = a4_16  // push a4_16
  90 @ 80100398  [-0x532].q = 1  // add 1
  91 @ 801003a4  a4_17 = ([-0x22c].q).b  // pop
  92 @ 801003ac  a4_18 = zx.q(a4_17)
  93 @ 801003b0  [0x3e1].b = a4_18  // crypto a4_18
  94 @ 801003b8  a5_11 = [0x657].q  // ctrl b3 
```
This can be simplified to:
```python
loop b3 80 # found at runtime # b3 specifies the loop name, allowing for multiple loops within each other
char = getchar # a5_9, var_41_1, a5_10, and arg7 are all the same
char &= 0xff # char mask
if (arg7 == '\n'): # end taking input on newline
	break
push char
push 0xffffffffffffffff
xor stack # pops both off and stores in a4
push a4
add 1 # add 1 to the top of the stack
pop a4
crypto a4
loop b3
```
Which can be further simplified to:
```python
a = input()
for i in a:
	temp = i & 0xff
	temp ^= 0xffffffffffffffff
	temp += 1
	temp &= 0xff
	crypto(temp)
```
What `crypto` does exactly will be revealed later. Next up is this huge function:
```
  97 @ 801003cc  int64_t var_58_1 = 1
  98 @ 801003d8  [0x657].q = 6  // ctrl b3 6
  99 @ 801003e4  int64_t a4_19 = arg6
 100 @ 801003e8  [-0x22c].q = a4_19  // push a4_19
 101 @ 801003f4  int64_t a4_20 = arg6
 102 @ 801003f8  [-0x379].q = a4_20  // mul a4_20
 103 @ 8010040c  int64_t a4_21 = [-0x17c].q  // rol stack values 
 104 @ 80100410  [-0x22c].q = a4_21  // push a4_21
 105 @ 8010041c  int64_t a4_22 = arg6
 106 @ 80100420  [-0x22c].q = a4_22  // push a4_22
 107 @ 80100430  [-0x532].q = 1  // add 1
 108 @ 8010043c  int64_t a5_12 = [-0x22c].q  // pop a4 
 109 @ 80100440  int64_t var_58_2 = a5_12
 110 @ 80100454  [0x74b].q = 0x9e3779b97f4a7c15  // xor -7046029254386353131
 111 @ 80100460  int64_t a5_13 = [-0x22c].q  // pop a4 
 112 @ 80100464  int64_t var_60_1 = a5_13
 113 @ 80100470  int64_t a5_14 = [-0x22c].q  // pop a4 
 114 @ 80100474  int64_t var_68_1 = a5_14
 115 @ 80100484  [-0x22c].q = 3  // push 3
 116 @ 80100490  int64_t a4_23 = arg5
 ...
```
This is really complex, and manual analysis took a while. So here is the python version:
```python
def rotate_left(val,valer):
    val &= 0xFFFFFFFFFFFFFFFF  # Ensure 64-bit
    while valer:
        val = ((val << 1) | (val >> 63)) & 0xFFFFFFFFFFFFFFFF
        valer-=1
    return val

input_1 = 0xfcfcfcdcdcdccccc
input_2 = 0xccbcbcbcacacac9c
counter = 1
temp = counter ** 2
temp_1 = rotate_left(input_1, temp)
counter += 1
temp_1 ^= 0x9e3779b97f4a7c15
rolled_xorred_input_1 = temp_1
temp_3 = 3 + (rolled_xorred_input_1 ^ input_2)
temp_4 = (rolled_xorred_input_1 ^ 0xFFFFFFFFFFFFFFFF) | (input_2 ^ 0xFFFFFFFFFFFFFFFF)
temp_4 *= 3
temp_4 &= 0xFFFFFFFFFFFFFFFF
temp_5 = (temp_4 + temp_3) & 0xFFFFFFFFFFFFFFFF
temp_6 = (rolled_xorred_input_1 ^ 0xFFFFFFFFFFFFFFFF) | (input_2 ^ 0xFFFFFFFFFFFFFFFF)
temp_6 ^= 0xFFFFFFFFFFFFFFFF
temp_6 *= 5
temp_6 = temp_6 & 0xFFFFFFFFFFFFFFFF
temp_5 += temp_6
temp_5 &= 0xFFFFFFFFFFFFFFFF
input_1 = temp_5

print(hex(input_1)
```
This is just one round, and we do not know how `0xfcfcfcdcdcdccccc` and `0xccbcbcbcacacac9c` are derived. To improve understanding, debugging of the VM can be used. For this I manually set up a gdb script to break on VM instructions and logged the arguments. This led me to derive an initial state that gets overwritten, and also that the bytes used to overwrite the initial state are derived from the cryptographic function. Finally, we have a working reproduction of the original code:
```python
def transform_byte(input_byte):
    input_byte &= 0xFF

    stored_18 = input_byte ^ 0x29
    stored_20 = (input_byte - 0x52) & 0xFF
    v71 = ((input_byte << 4) | (input_byte >> 4)) & 0xFF
    diff = (stored_20 - stored_18) & 0xFF
    final_result = input_byte ^ diff

    return v71, final_result

def overwrite_input(input_array, payload):
    # Flatten the 64-bit input array into a bytearray (little-endian)
    bytes_flat = bytearray()
    for val in input_array:
        bytes_flat.extend(val.to_bytes(8, 'big'))

    # Overwrite v71s from start, final_results from end
    for i, c in enumerate(payload):
        input_byte = (-ord(c)) & 0xFF
        v71, final_result = transform_byte(input_byte)

        # Overwrite byte i from start with v71
        bytes_flat[i] = v71

        # Overwrite byte i from end with final_result
        bytes_flat[-(i + 1)] = final_result

    # Reconstruct 64-bit integers from the modified bytearray
    new_input = [
        int.from_bytes(bytes_flat[i:i+8], 'big')
        for i in range(0, len(bytes_flat), 8)
    ]
    return new_input

# === EXAMPLE ===

input = [
    0xdf0361e63202eb70,
    0x1d39b79c7b7fbbef,
    0xe16cdee1c70d4646,
    0x0271c23352ed8d6a,
    0x9d297101cd1b5ec3,
    0x89e4dc9e64bce67f,
    0x5c10b631c4c9b0b4,
    0x5ee1bf4b7ad77c30
]
payload = "uiuctf{placeholder}"
input = overwrite_input(input, payload)
def rotate_left(val,valer):
    val &= 0xFFFFFFFFFFFFFFFF  # Ensure 64-bit
    while valer:
        val = ((val << 1) | (val >> 63)) & 0xFFFFFFFFFFFFFFFF
        valer-=1
    return val

counter = 1
while True:
    temp = counter ** 2
    temp_1 = rotate_left(input[0], temp)
    counter += 1
    temp_1 ^= 0x9e3779b97f4a7c15
    rolled_xorred_input_1 = temp_1
    temp_3 = 3 + (rolled_xorred_input_1 ^ input[counter-1])
    temp_4 = (rolled_xorred_input_1 ^ 0xFFFFFFFFFFFFFFFF) | (input[counter-1] ^ 0xFFFFFFFFFFFFFFFF)

    
    temp_4 *= 3
    temp_4 &= 0xFFFFFFFFFFFFFFFF
    
    temp_5 = (temp_4 + temp_3) & 0xFFFFFFFFFFFFFFFF
    
    temp_6 = (rolled_xorred_input_1 ^ 0xFFFFFFFFFFFFFFFF) | (input[counter-1] ^ 0xFFFFFFFFFFFFFFFF)
    
    temp_6 ^= 0xFFFFFFFFFFFFFFFF
    temp_6 *= 5
    temp_6 = temp_6 & 0xFFFFFFFFFFFFFFFF
    
    temp_5 += temp_6
    temp_5 &= 0xFFFFFFFFFFFFFFFF
    input[0] = temp_5
    print(hex(input[0]))
    if counter == 8:
        break
print(hex(input[0]))
```
At this point, the CTF ended. All that was left to do was to reverse engineer the next function (which was smaller and had similar functionality) and transcribe them into z3 constraints, the first function needed `input[0]` to equal `0x37fbe21eae04066a` at the end. 
# Conclusion
While disappointed that I was not able to finish this challenge, I was very close. The analysis files involved are [here](https://mega.nz/file/CQ0CwQia#r0rVZODBylDJYG9oZIJ0IDk8z17cPWiaLzfpFPDiRYY). 
