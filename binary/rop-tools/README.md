# ROP
## Contents
- [1. Command cheatsheet](#1-command-cheatsheet)
  * [Find strings in binary](#find-strings-in-binary)
- [2. Library Documentation](#2-library-documentation)
  * [ROP Object](#rop-object)
  * [Manual Payload Generation](#manual-payload-generation)
  * [Automatic Payload Generation](#automatic-payload-generation)
  * [Process Interaction](#process-interaction)
  * [Misc/Helper Functions](#misc-helper-functions)
- [3. Calling functions examples](#3-calling-functions-examples)
  * [General](#general)
    + [x86](#x86)
    + [x64](#x64)
  * [System](#system)
    + [x86](#x86)
    + [x64](#x64)

### 1. Command cheatsheet
#### Find strings in binary
`rabin2 -z <binary>`


### 2. Library Documentation
#### ROP Object
##### \_\_init\_\_(filename)
Creates a ROP object for the binary with the given `filename`.  
The `payload` member can be used as a buffer for process interaction.

#### Manual Payload Generation
##### get_padding()
Generate padding up until overflow occurs.
##### get_functions()
Get all the functions in the binary.
##### get_function_addr(function)
Get the address of the `function` in the binary.
##### get_string_addr(string)
Get the address of the `string` in the binary.
##### p(value)
Uses p32/p64 to pack `value` depending on the binary architecture.

#### Automated Payload Generation
##### system(command)
Add to the ROP chain to call system with the given `command`.
##### call(function, args=[])
Add to the ROP chain to call a function with the given args.
##### chain()
Get the ROP chain payload

#### Process Interaction
##### start_process(args=[])
Starts a process of the binary with `args` optionally specified.
##### sendafter(self, delim, payload)
Wait until `delim` hass been received before sending `payload`.
##### recvline()
Return the next line of output from the process.
##### recvall()
Return all data until EOF is reached.

#### Misc/Helper Functions
##### log_all(status)
Turns verbose logging on/off via `status` being set to True/False respectively.
##### get_padding_length()
Returns the number of bytes before overflow occurs.


### 3. Calling functions examples
#### General
##### x86
```
Arugments are pushed onto the stack in reverse order.
```
##### x64
```
Integer Arguments: %rdi, %rsi, %rdx, %rcx, %r8 and %r9
Floating Point Arguments: %xmm0-7
Note: If more than 6/8 arguments are required, the rest are passed on the stack.
```
#### System
##### x86
```
SYSTEM_ADDRESS
RETURN_ADDRESS
COMMAND_STRING_ADDRESS
```
##### x64
```
POP_RDI
COMMAND_STRING_ADDRESS
SYSTEM_ADDRESS
```
