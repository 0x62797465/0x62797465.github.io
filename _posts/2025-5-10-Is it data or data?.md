---
title: Is it data or data?
category: DamCTF-2025
chall_description: 
points: 0
solves: 0
tags: rev
date: 2025-5-10
comments: false
---

# Initial Analysis
This is an ELF binary coded in C++, the main function contains a loop that, once exits, prints the flag.
```c
  {
      char i;
      
      do
      {
          if (!set_7th_char_to_g())
          {
              char j;
              
              do
                  j = input_and_mutation();
               while (!j);
          }
          
          cur_char_for_g += 1;
          i = check_string();
      } while (!i);
      print_flag();
      /* no return */
  }
```
In order to understand our goal, we need to understand what the check_string function does:
```c
  int64_t check_string()

  {
      uint64_t rdx = data_4062c8;
      int64_t rax = 0;
      
      if (rdx == data_4062a8)
      {
          rax = 1;
          
          if (rdx)
          {
              int64_t rsi = data_4062a0;
              int64_t rax_1;
              rax_1 = !memcmp(data_4062c0, rsi, rdx);
              return rax_1;
          }
      }
      
      return rax;
  }
```
Most of this is just noise, what you really need to know is that `data_4062a0` must equal `data_4062c0`. If we cross reference both of them we can see `data_4062c0` being set in the `INIT` function to "inagalaxyfarfaraway". The other string is set by many functions, most of which are in the mutate function.
# Analysis
Before we analyze the input function let's take a brief look at the set of the 7th char to g:
```c
  {
      if (cur_char_for_g != 7)
          return 0;
      
      int64_t charptr_1 = charptr;
      int64_t rax_1;
      
      if (string_for_comp == &data_4062b0)
          rax_1 = 0xf;
      else
          rax_1 = data_4062b0;
      
      if (rax_1 < charptr_1 + 1)
          std::string::_M_mutate(&string_for_comp, charptr_1, 0, 
              nullptr, 1);
      
      string_for_comp[charptr_1] = 'g';
      charptr = charptr_1 + 1;
      string_for_comp[charptr_1 + 1] = 0;
      return 1;
  }
```
It sets the current character to `g`. In the context of the main function, it appears to set the 7th char after the input function runs 7th time and returns 1 each time. Based off this the conclusion can be made that this will set the 7th char to `g` (which we will find to be incorrect later on). Now, let's analyze the input function:
```c
      while (true)
      {
          class std::istream* rax_15 =
              std::getline<char>(&__in, &__str_1, 0x20);
          
          if (*(rax_15 + rax_15->_vptr.basic_istream[-3] + 0x20)
                  & 5)
              break;
          
          if (!rbx_2)
              std::string::_M_assign(&var_228, &__str_1);
          else if (rbx_2 == 1)
              std::string::_M_assign(&var_208, &__str_1);
          
          rbx_2 += 1;
      }
```
The first section is just a simple string input, it looks that both `var_208` and `var_228` can hold a copy of our input, but looking at cross references it looks like `var_228` is our input (it will be renamed from now on). 
```c
      if (sub_403b1f(__isoc23_strtol, "stoi", input, nullptr, 0xa)
          != 1)
      {
          if (sub_403b1f(__isoc23_strtol, "stoi", input, nullptr, 
              0xa) == 0xb)
          {
              sub_402bb1();
              rbp = 1;
          }
          else if (sub_403b1f(__isoc23_strtol, "stoi", input, 
              nullptr, 0xa) == 0xd)
          {
              sub_402c4f();
              rbp = 1;
          }
          else if (sub_403b1f(__isoc23_strtol, "stoi", input, 
              nullptr, 0xa) == 4)
          {
              sub_402bd1();
              rbp = 1;
          }
          else if (sub_403b1f(__isoc23_strtol, "stoi", input, 
              nullptr, 0xa) == 5)
          {
              sub_402cad();
              rbp = 1;
          }
          else if (sub_403b1f(__isoc23_strtol, "stoi", input, 
              nullptr, 0xa) == 6)
          {
              sub_402900();
              rbp = 1;
          }
          else if (sub_403b1f(__isoc23_strtol, "stoi", input, 
              nullptr, 0xa) == 7)
          {
              sub_402924();
              rbp = 1;
          }
          else if (sub_403b1f(__isoc23_strtol, "stoi", input, 
              nullptr, 0xa) == 0xf)
          {
              sub_4029a2();
              rbp = 1;
          }
          else if (sub_403b1f(__isoc23_strtol, "stoi", input, 
              nullptr, 0xa) == 9)
          {
              sub_402a20();
              rbp = 1;
          }
          else if (sub_403b1f(__isoc23_strtol, "stoi", input, 
              nullptr, 0xa) == 0xa)
          {
              sub_402a9e();
              rbp = 1;
          }
          else
          {
              rbp = rcx;
              int64_t var_220;
              
              if (var_220 == 8)
              {
                  if (!memcmp(input, "00111111", 8))
                  {
                      sub_4025e9();
                      exit(0);
                      /* no return */
                  }
                  
                  rbp = rcx;
              }
          }
      }
```
So, it looks like the code executes different functions based off what number we input, let's take a look at each.
## Analysis of Mutations
The first function is:
```c
  int64_t sub_402bb1()

  {
      int64_t result = data_4062a8;
      
      if (result > 0)
      {
          result = result - 1;
          data_4062a0[result] = 0x74;
      }
      
      return result;
  }
```
`data_4062a0` looks to be the mutated string based off cross references, similarly, `data_4062a8` looks to be the array index pointing to the current char, also based off cross references. So, after cleaning up, we have:
```c
  {
      int64_t charptr_1 = charptr;
      
      if (charptr_1 > 0)
      {
          charptr_1 = charptr_1 - 1;
          string_for_comp[charptr_1] = 't';
      }
      
      return charptr_1;
  }
```
So it just sets the current character to `t`. But do note that it does not increment `charptr` at all. The next function is:
```c
  void sub_402c4f()
  {
      int64_t charptr_1 = charptr;
      [...]  
      int64_t __pos = charptr_1 - 1;  
      [...]
    
      // should always be one
      std::string::size_type __n = charptr_1 - __pos;
      
      if (__n > 0)
          __n = 1;
      
      std::string::_M_erase(&string_for_comp, __pos, __n); // erase one byte
  }
```
This is just a backspace. The next function is:
```c
  char* sub_402bd1()

  {
      int64_t charptr_1 = charptr;
      int64_t rax;
      
      if (string_for_comp == &data_4062b0)
          rax = 0xf;
      else
          rax = data_4062b0;
      
      if (rax < charptr_1 + 1)
          std::string::_M_mutate(&string_for_comp, charptr_1, 0, 
              nullptr, 1);
      
      string_for_comp[charptr_1] = 'f'; // Sets current char to f
      charptr = charptr_1 + 1;
      char* string_for_comp_1 = string_for_comp;
      string_for_comp_1[charptr_1 + 1] = 0;
      return string_for_comp_1;
  }
```
This is similar to the first function we look at, it sets the current char to `f`. But this function, unlike the other, increments the `charptr`. The next function is:
```c
  void* sub_402cad()

  {
      void* result = &string_for_comp[*charptr - 1];
      char rdx = *result;
      
      if (rdx > 0x21)
          *result = rdx - 1;
      
      return result;
  }
```
This is pretty simple, it just subtracts one from the current char (if set to `t` by the first function it would set the character before `t`, but if set to `f` by the `f` function it would modify `f`). But the current character must be over `0x21`, so we can not just use this to craft the entire string (using an underflow). The next function is similar:
```c
  void* sub_402900()

  {
      void* result = &string_for_comp[*charptr - 1];
      char rdx = *result;
      
      if (rdx <= 0x7a)
          *result = rdx + 3;
      
      return result;
  }
```
It adds 3 to the current char. Using these 2 functions, the function creating `f`, and the backspace function, any string can be created.
# Solve
To recap:

| Input | Affect                                                          |
| ----- | --------------------------------------------------------------- |
| 11    | sets the current_char-1 to t and doesn't increment the char ptr |
| 13    | is similar to a backspace                                       |
| 4     | sets the current char to f and increments the char ptr          |
| 5     | subtracts 1 from the current_char-1                             |
| 6     | adds 3 to the current_char-1                                    |

Using this information (excluding the `t` function), we can solve this with:
```python
base = ord('f')
target = "inagalaxyfarfaraway"
cur_char = 0
while True:
    try:
        cur_int = ord(target[cur_char]) # No if statement needed :)
    except:
        exit()
    print("4") # New char, starts at f
    if (cur_int == base): # Already at target
        () 
    else:
        i = base-cur_int
        if (i < 0):
            while (i < 0):
                print("6")
                i += 3
        while (i != 0):
            print("5")
            i -= 1
    cur_char += 1
```
This looks pretty good, but it only gets to `ingagalaxyfarfaraway`. Why is there an extra g? Our initial analysis was **wrong**, the set_7th_char_g inserts g on the 7th mutation, not the 7th char! With a quick and dirty patch using the backspace character, we get:
```python
base = ord('f')
target = "inagalaxyfarfaraway"
cur_char = 0
while True:
    try:
        cur_int = ord(target[cur_char])
    except:
        exit()
    print("4") # Start with f
    if (cur_int == base):
        () # If the curr char is f
    else:
        i = base-cur_int
        if (i < 0):
            while (i < 0):
                print("6") # Add 3
                i += 3
        while (i != 0):
            print("5") # Subtract one
            i -= 1
    if (cur_char == 1):
        print("13") # Backspace
    cur_char += 1
```
And...
```bash
[h@eab598aa6922 share]$  (python solve.py) | nc isitdata.chals.damctf.xyz 39531
[...] dam{I_dont_like_silicon_it_makes_cpus_and_theyre_everywhere}
```
