#!/usr/bin/env python
import sys
from disassembler import Disassembler
from rop import PAPA_ROP
from format_string import Format_String
from process import Process
from misc import Misc
from pwn import *

class PWN(Disassembler, PAPA_ROP, Format_String, Process, Misc):

    def __init__(self, filename):
        Disassembler.__init__(self, filename)
        PAPA_ROP.__init__(self, filename)
        Format_String.__init__(self, filename)
        Process.__init__(self, filename)
        Misc.__init__(self, filename)
        context.log_level = 'INFO'


def test_module(argv):
    if (len(sys.argv) != 2):
        log.failure("Usage: "+argv[0]+" <test_binary>")
        exit(1)
    d = PWN(sys.argv[1])

if __name__ == "__main__":
    test_module(sys.argv)
