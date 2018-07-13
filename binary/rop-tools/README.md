# ROP
## Contents
- [1. Command cheatsheet](#1-command-cheatsheet)
  * [Find strings in binary](#find-strings-in-binary)
  * [Find ROP gadgets with blacklisted characters](#find-rop-gadgets-with-blacklisted-characters)
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


## 1. Command cheatsheet
#### Find strings in binary
`rabin2 -z <binary>`
#### Find ROP gadgets with blacklisted characters
`ropper -f <binary> -b <bad chars in hex>`


## 2. Library Documentation
#### ROP Object
##### \_\_init\_\_(filename)
Creates a ROP object for the binary with the given `filename`.  
The `payload` member can be used as a buffer for process interaction.  
The `args` list member are the command line arguments to be run with the process.  
The `auto_construct_payload` member option determines whether payload construction automatically fills the `payload` member.

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
##### pop_mov_write(pop, mov, what, where, reverse=False)
Writes `what` to `where` using the `pop` and `mov` gadgets.  
The gadgets are specifically:
```
pop rDST; pop rSRC; ret (pop gadget)
mov [rDST], rSRC; ret   (mov gadget)
```
The `reverse` parameter implies that rDST and rSRC are not in the same order between the gadgets.
##### xor_decrypt(pop, xor, cipher_addr, key, reverse=False)
XOR the bytes at `cipher_addr` with `key` using the `pop` and `xor` gadgets.  
The gadgets are specifically:
```
pop rCIP; pop rKEY; ret      (pop gadget)
xor byte ptr rCIP, rKEY; ret (xor gadget)
```
The `reverse` parameter implies that rCIP and rKEY are not in the same order between the gadgets.

#### Automated Payload Generation
##### system(command)
Add to the ROP chain to call system with the given `command`.
##### call(function, args=[])
Add to the ROP chain to call a `function` with the given `args`.
##### chain()
Get the ROP chain payload

#### Process Interaction
##### start_process()
Starts a process of the binary with `self.args` optionally specified.
##### start_debug(dbg_cmds='continue\n')
Starts a debug process of the binary with `self.args` optionally specified.  
The optional `dbg_cmds` parameter specifies any initial debugging commands to be run.
##### sendafter(self, delim, payload)
Wait until `delim` hass been received before sending `payload`.
##### recvline()
Return the next line of output from the process.
##### recvall()
Return all data until EOF is reached.
##### interactive()
Allow the user to directly interact with the process
##### pwn(prompt='', pwn_type='SHELL')
Automatically start a process and send `self.payload` after `prompt` has been received.  
Depedning on the `pwn_type`, one of a few actions can occur:  
- SHELL = process becomes interactive
- READ_ALL = all received output is sent back
- READ_LINE = a single line of output is sent back

#### Misc/Helper Functions
##### log_all(status)
Turns verbose logging on/off via `status` being set to True/False respectively.
##### payload_append(payload)
Append payload component if `self.auto_construct_payload` is set to True.
##### get_padding_length()
Returns the number of bytes before overflow occurs.
##### xor_encode(what, avoid)
XOR encode `what` to ensure there are no bytes that exist in `avoid`.  
Returns a (cipher, decrypt_key) tuple that also avoids the bad characters.


## 3. Calling functions examples
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
