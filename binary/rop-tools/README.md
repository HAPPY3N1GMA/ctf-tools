# ROP
## Contents
- [1. Command cheatsheet](#1-command-cheatsheet)
  * [Find strings in binary](#find-strings-in-binary)
- [2. Library Documentation](#2-library-documentation)
  * [ROP Object](#rop-object)
  * [Payload Generation](#payload-generation)
  * [Process Interaction](#process-interaction)
  * [Misc/Helper Functions](#misc-helper-functions)
- [3. Calling funmctions examples](#3-calling-funmctions-examples)
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

#### Payload Generation
##### get_padding()
Generate padding up until overflow occurs.
##### get_functions()
Get all the functions in the binary.
##### get_function_addr(function)
Get the address of the `function` in the binary.
##### get_string_addr(string)
Get the address of the `string` in the binary.
##### system(command)
Produce payload to execute `command` via system.
##### p(value)
Uses p32/p64 to pack `value` depending on the binary architecture.

#### Process Interaction
##### start_process(args=[])
Starts a process of the binary with `args` optionally specified.
##### sendafter(self, delim, payload)
Wait until `delim` hass been received before sending `payload`.
##### recvline()
Return the next line of output from the process.

#### Misc/Helper Functions
##### log_all(status)
Turns verbose logging on/off via `status` being set to True/False respectively.
##### get_padding_length()
Returns the number of bytes before overflow occurs.


### 3. Calling funmctions examples
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
