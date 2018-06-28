#!/usr/bin/python

import sys
from pwn import *

# Load binary
elf = ELF(sys.argv[1])
p = process(elf.path)

# Send a known pattern to overflow buffer
pattern = cyclic(256)
p.sendline(pattern) # May need to make bigger
p.wait()

# Calculate the offset
context.delete_corefiles = True
core = p.corefile
try:
    sub = core.read(core.esp-4, 4)
except:
    sub = core.read(core.rsp, 4)
length = cyclic_find(sub)
info("Padding length: " + str(length))
info("Sample padding: " + "A"*length)

