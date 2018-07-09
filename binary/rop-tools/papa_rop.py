#!/usr/bin/env python

from pwn import *

class PAPA_ROP:

    def __init__(self, filename):
        self.filename = filename
        self.elf = context.binary = ELF(filename)
        self.arch = self.elf.get_machine_arch()

    # Get the number of bytes before overflow occurs
    def get_padding_length(self):
        context.delete_corefiles = True
        p = process(self.elf.path)
        p.sendline(cyclic(4096))
        p.wait()
        core = p.corefile
        try:
            sub = core.read(core.esp-4, 4)
        except:
            sub = core.read(core.rsp, 4)
        return cyclic_find(sub)

    # Generate padding before overflow
    def gen_padding(self):
        return "A"*self.get_padding_length()

    # Get all the functions of the binary
    def get_functions(self):
        return self.elf.functions

    # Get the specified function address
    def get_function_addr(self, function):
        return self.elf.functions[function].address

    # Pack a value based on the binary architecture
    def p(self, value):
        if (self.arch == "i386"):
            return p32(value)
        elif (self.arch == "amd64"):
            return p64(value)
        else:
            log.failure("Unknown architecture: " + arch)
            exit(1)

