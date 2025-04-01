---
title: 
category: UMD-CTF-2024
chall_description: 
points: 500
solves: 28
tags: rev
date: 2025-04-01
comments: false
---
This VM should keep my program safe... right?
---

# Initial Overview 
VM exe coded in C, takes an arg which is a 32 bit integer which is the password, prints the flag if correct, prints nothing if not. 
# Analysis
## Initial Analysis
First thing we have to do is find the VM function, bytecode, and target (what prints the flag). For the target, we see:
```c
00401000    void __fastcall sub_401000(int32_t arg1, int32_t arg2)

00401000    {
00401000        int32_t Buffer = arg1;
00401000        
0040100f        if (arg2 == 1)
0040100f        {
00401018            int32_t var_114_1 = 0;
0040101d            int32_t eax_1;
0040101d            int32_t edx;
0040101d            eax_1 = RtlCrc64(&Buffer, 4, 0);
00401031            void var_108;
00401031            wsprintfA(&var_108, "FLAG{0x%x%x}", eax_1, edx);
00401037            TEB* fsbase;
00401037            struct _TEB* Self = fsbase->NtTib.Self;
0040104a            int32_t nNumberOfCharsToWrite = lstrlenA(&var_108);
00401061            WriteConsoleA(Self->ProcessEnvironmentBlock->ProcessParameters->StandardOutput, 
00401061                &var_108, nNumberOfCharsToWrite, nullptr, nullptr);
0040100f        }
00401000    }

```
So arg2 has to be one, I would go farther to find out what needs to be set, but when we disassemble the bytecode it will be pretty obvious. 

The VM function is pretty easy to find, just look for a function that has a bunch of branches based of a single byte (0x004012b5). 

Finally, the argument passed into the VM function contains the bytecode:
```c
00401145                __builtin_memcpy(i, 0x403000, 0x82);
00401156                struct _PEB* ProcessEnvironmentBlock =
00401156                    fsbase->NtTib.Self->ProcessEnvironmentBlock;
0040115c                **(eax_5 + 0xc) = *(eax_5 + 8);
0040115e                int32_t* ecx_7 = *(eax_5 + 0xc);
00401163                ecx_7[1] = *ecx_7;
0040116b                *(*(eax_5 + 0xc) + 0x1c) = ProcessEnvironmentBlock;
0040116e                *(eax_5 + 4) = i;
00401171                vm(eax_5);
```
So what is in "i"?
```
3e020000003f01370104400101013d003e16c31f483f003901003f003b03034101033b03034301363ec9a505ae3f033700033ef09bacb43f033b00033e70d4eaf23f013edf310e813f033b01030000000000000000000000000000000000000000000000000000000000000000000000003b03034100014301363e010000003f03360000
```
Looks like good old bytecode!
## VM analysis
The first byte comparison we see is:
```c
004012dd            if (bytecode == 0x36)
004012dd            {
004014b2                ebx[0x14] = 0;
004014b2                break;
004012dd            }
```
This terminates the loop, so we can assume that 0x36 is the opcode for halt/exit/ret (has no functions so it might as well be). 

The second comparison we see is:
```c
004012e9            if (bytecode >= 0x37 && bytecode <= 0x3c)
004012e9            {
004012ed                sub_401236(ebx);
004012f2                esi = *(ebx + 4);
004012e9            }
```

In that we see an argument parser (for bytes following) and then:
```c
0040126b            if (eax_2 == 0x37)
0040126b            {
004012a5                result = ecx + edx_1;
004012a8                *(esi_1 + (edi_1 << 2) + 0xc) = result;
0040126b            }
```
Similar comparisons take place, with similar operations, so tl;dr:
```
0x37 = add
0x38 = sub
0x39 = mul (used like sub/add)
0x3a = div (used like sub/add)
0x3b = xor
0x3c = mov
```
Going back to the VM, we see:
```c
00401348                if (eax_7 == 0x3d)
00401348                {
0040146a                    char temp1_1 = esi[1];
00401471                    uint32_t bytecode_4 = bytecode_2;
00401474                    bytecode_2 = esi[1];
00401474                    
00401477                    if (temp1_1 >= 0x14)
00401477                        bytecode_2 = bytecode_4;
00401477                    
0040147a                    bytecode_3 = bytecode_2;
0040147a                    
0040147d                    if (temp1_1 >= 0x14)
00401499                        esi = &esi[1];
0040147d                    else
0040147d                    {
0040147f                        int32_t* eax_33 = *(ebx + 0xc);
00401482                        *eax_33 -= 4;
00401485                        bytecode_2 = *(ebx + 0xc);
00401494                        **bytecode_2 =
00401494                            *(bytecode_2 + (bytecode_3 << 2) + 0xc);
00401499                        esi = &(*(ebx + 4))[1];
0040147d                    }
00401348                }

```
This was... confusing. Using dynamic analysis it was found that it pushed the password onto the "stack", which we are about to explore.

The next comparison is:
```c
00401348                else if (eax_7 == 0x3e)
00401351                {
00401449                    int32_t* eax_29 = *(ebx + 0xc);
0040144e                    *eax_29 -= 4;
0040145c                    ***(ebx + 0xc) = *(*(ebx + 4) + 1);
00401462                    esi = *(ebx + 4) + 4;
00401351                }
```
This is just a push instruction, it pushes a 32 bit integer onto the the stack, this is evident by the subtracting of eax_29, similar to the substitution of rsp during a push. 

The following comparison is:
```c
00401351                else if (eax_7 == 0x3f)
0040135a                {
0040141a                    arg1 = esi[1];
00401420                    bytecode_2 = arg1;
00401420                    
00401426                    if (arg1 >= 0x14)
00401426                        bytecode_2 = *arg1[1];
00401426                    
00401429                    bytecode_1 = bytecode_2;
00401429                    
0040142c                    if (arg1 >= 0x14)
00401499                        esi = &esi[1];
0040142c                    else
0040142c                    {
0040142e                        bytecode_2 = *(ebx + 0xc);
0040143d                        *(bytecode_2 + (bytecode_1 << 2) + 0xc) =
0040143d                            **bytecode_2;
00401441                        int32_t* eax_28 = *(ebx + 0xc);
00401445                        *eax_28 += 4;
00401499                        esi = &(*(ebx + 4))[1];
0040142c                    }
0040135a                }
```
The usage of eax+=4 looks like increasing rsp after a pop, we can confirm that this works similar to pop via testing, we can also see in the bytecode that the following argument is always 4 or less (indicating a register ID).

The following bytecode was:
```c
0040135a                else if (eax_7 == 0x40)
00401363                {
004013c1                    char var_7;
004013c1                    
004013c8                    if (sub_40120d(ebx, &var_8, &var_7))
004013c8                    {
004013ce                        bytecode_2 = *(ebx + 0xc);
004013d1                        char ecx_4 = esi[3];
004013d9                        int32_t esi_2 =
004013d9                            *(bytecode_2 + (var_7 << 2) + 0xc);
004013dd                        char eax_21 = ecx_4;
004013e0                        int32_t i_1 = 4;
004013e0                        
004013e1                        if (ecx_4 > 4)
004013e1                            eax_21 = 4;
004013e1                        
004013e9                        if (eax_21)
004013e9                        {
004013eb                            uint32_t edi_1 = var_8;
004013f2                            void* eax_23 = &bytecode_2[(edi_1 + 3) << 2];
004013fc                            int32_t i;
004013fc                            
004013fc                            do
004013fc                            {
004013f5                                *eax_23 = 0;
004013f8                                eax_23 += 1;
004013f9                                i = i_1;
004013f9                                i_1 -= 1;
004013fc                            } while (i != 1);
0040140d                            __builtin_memcpy(
0040140d                                *(ebx + 0xc) + ((edi_1 + 3) << 2), esi_2, 
0040140d                                eax_21);
0040140f                            edi = *(ebx + 4);
004013e9                        }
004013c8                    }
004013c8                    
00401412                    esi = &edi[3];
00401363                }
```
This was unreadable, through testing I found that this was used as an anti-debug check, it moved whether or not the process was being debugged into the register id "01".

The following code was:
```c
00401363                else if (eax_7 == 0x41)
00401368                {
00401377                    char var_6;
0040137e                    char var_5;
0040137e                    
0040137e                    if (sub_40120d(ebx, &var_5, &var_6))
0040137e                    {
00401380                        void* ecx_2 = *(ebx + 0xc);
00401387                        bytecode_2 = *(ecx_2 + (var_5 << 2) + 0xc);
0040138f                        int32_t eax_16 = *(ecx_2 + (var_6 << 2) + 0xc);
00401393                        *(ecx_2 + 8) = 0;
00401393                        
00401399                        if (bytecode_2 < eax_16)
0040139e                            *(*(ebx + 0xc) + 8) = 0xff;
00401399                        else if (bytecode_2 > eax_16)
004013a9                            *(*(ebx + 0xc) + 8) = 1;
0040137e                    }
0040137e                    
004013b0                    esi = *(ebx + 4) + 2;
00401368                }
```
This looked like a comparison function, as you can see this section:
```c
00401393                        *(ecx_2 + 8) = 0;
00401393                        
00401399                        if (bytecode_2 < eax_16)
0040139e                            *(*(ebx + 0xc) + 8) = 0xff;
00401399                        else if (bytecode_2 > eax_16)
004013a9                            *(*(ebx + 0xc) + 8) = 1;
```
It sets a flag to zero if equal, -1 if bytecode_2 is less, and 1 if more. 

Finally, we make it to the end:
```c
00401300            {
00401302                uint32_t eax = bytecode;
00401305                arg1 = 0;
00401305                
0040130a                if (eax == 0x42)
0040132d                    arg1 = 1;
0040130a                else if (eax == 0x43)
00401328                    arg1 = !*(*(ebx + 0xc) + 8);
0040130f                else if (eax == 0x44)
0040131c                    arg1 = *(*(ebx + 0xc) + 8);
0040131c                
00401331                if (arg1)
0040133b                    esi = &esi[esi[1]];
0040133b                
00401499                esi = &esi[1];
00401300            }
```
This uses the flag set by cmp in order to jump ahead a few bytes. 0x42 looks like a jmp (always set), 0x43 looks like jz, and 0x44 looks like jnz.

# Disassembling
So far we have:
```
0x36 = hlt
0x37 = add
0x38 = sub
0x39 = mul (used like sub/add)
0x3a = div (used like sub/add)
0x3b = xor
0x3c = mov
0x3d = push password
0x3e = push
0x3f = pop
0x40 = mov ecx, isbeingdebugged
0x41 = cmp
0x42 = jmp
0x43 = jz
0x44 = jnz
```

Now we can disassemble:
```
; 00 = eax
; 01 = ecx
; 02 = edx
; 03 = esi
; 04 = edi
push 2 ; 3e02000000
pop ecx ; 3f01
add ecx, edi ; 370104
mov ecx, isBeingDebugged ; 40010101
push password ; 3d00
push 0x481fc316 ; 3e16c31f48
pop eax ; 3f00
mul ecx, eax ; 390100
pop eax ; 3f00
xor esi, esi ; 3b0303
cmp ecx, esi ; 410103
xor esi, esi ; 3b0303
jz +1 ; 4301
hlt ; 36

push 0xae05a5c9 ; 3ec9a505ae
pop esi ; 3f03
add eax, esi ; 370003
push 0xb4ac9bf0 ; 3ef09bacb4
pop esi ; 3f03
xor eax, esi ; 3b0003
push 0xf2ead470 ; 3e70d4eaf2
pop ecx ; 3f01
push 0x810e31df ; 3edf310e81
pop esi ; 3f03
xor ecx, esi ; 3b0103
nop ; 000000000000000000000000000000000000000000000000000000000000000000000000
xor esi, esi ; 3b0303
cmp eax, ecx ; 410001
jz +1 ; 4301
hlt ; 36

push 0x1 ; 3e01000000 ; win?
pop esi ; 3f03
hlt ; 36
```
# Assembly Analysis
The first section:
```
push 2 ; 3e02000000
pop ecx ; 3f01
add ecx, edi ; 370104
mov ecx, isBeingDebugged ; 40010101
push password ; 3d00
push 0x481fc316 ; 3e16c31f48
pop eax ; 3f00
mul ecx, eax ; 390100
pop eax ; 3f00
xor esi, esi ; 3b0303
cmp ecx, esi ; 410103
xor esi, esi ; 3b0303
jz +1 ; 4301
hlt ; 36
```
Just moves the password integer into eax and terminates if debugged. 

The second section:
```
push 0xae05a5c9 ; 3ec9a505ae
pop esi ; 3f03
add eax, esi ; 370003
push 0xb4ac9bf0 ; 3ef09bacb4
pop esi ; 3f03
xor eax, esi ; 3b0003
push 0xf2ead470 ; 3e70d4eaf2
pop ecx ; 3f01
push 0x810e31df ; 3edf310e81
pop esi ; 3f03
xor ecx, esi ; 3b0103
nop ; 000000000000000000000000000000000000000000000000000000000000000000000000
xor esi, esi ; 3b0303
cmp eax, ecx ; 410001
jz +1 ; 4301
hlt ; 36
```
We can solve with starting from the end. First, eax and ecx must be the same. Since ecx is not dependent on the input, we can analyze it first. Let's simulate it in python and see the end result:
```python
# push 0xf2ead470 ; 3e70d4eaf2
# pop ecx ; 3f01
ecx = 0xf2ead470
# push 0x810e31df ; 3edf310e81
# pop esi ; 3f03
esi = 0x810e31df
# xor ecx, esi ; 3b0103
ecx = ecx ^ esi

print(ecx)
```
We get `1944380847`, now that we know that value, we can find out input. The equation can be represented as `1944380847 = (eax + 0xae05a5c9) ^ 0xb4ac9bf0` let's simplify by xoring each side: `3343416927 = (eax + 0xae05a5c9)` next lets subtract each side: 423811222 = eax.

With that, we have our input.
# Flag
FLAG{0x4a516025f931857b}
