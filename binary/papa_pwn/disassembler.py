#!/usr/bin/env python
import sys
from pwn import *

class Disassembler():

    def __init__(self, filename):
        context.log_level = 'CRITICAL'
        self.elf = context.binary = ELF(filename)

    #############################
    ##### Pwntools Wrappers #####
    #############################

    # Get the specified function address
    def get_function_addr(self, function):
        return self.elf.functions[function].address

    # Get the specified symbol address
    def get_symbol_addr(self, symbol):
        return self.elf.symbols[symbol]

    # Get the specified plt entry address
    def get_plt_addr(self, entry):
        return self.elf.plt[entry]

    # Get the specified got entry address
    def get_got_addr(self, entry):
        return self.elf.got[entry]

    # Get the specified string address
    def get_string_addr(self, string):
        return list(self.elf.search(string, False))[0]


def test_module(argv):
    if (len(sys.argv) != 2):
        log.failure("Usage: "+argv[0]+" <test_binary>")
        exit(1)
    d = Disassembler(sys.argv[1])

if __name__ == "__main__":
    test_module(sys.argv)
