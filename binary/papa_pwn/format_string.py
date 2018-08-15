#!/usr/bin/env python
import sys
from process import Process
from pwn import *

class Format_String(Process):

    def __init__(self, filename):
        Process.__init__(self, filename)
        context.log_level = 'CRITICAL'
        context.delete_corefiles = True
        self.elf = context.binary = ELF(filename)
        self.rop = ROP(self.elf)

    ##########################################
    ##### General Format String Exploits #####
    ##########################################
    # Find where the user input is
    # Optional arguments:
    #   - exploit_fstring: function(fstring, *args) -> output
    def get_buf_addr(self, buf_len=0x100, exploit_fstring=None, *args):
        if (exploit_fstring == None):
            exploit_fstring = self.start_and_sendline_line

        max_stack = buf_len / 4 
        for i in xrange(1000):
            payload = "%08x"*max_stack
            out = exploit_fstring(payload, *args)
        print u32("%08x")
        print out
        print out.find(str(u32("x80%")))
        return 0



###################
##### TESTING #####
###################

def test_module(argv):
    if (len(sys.argv) != 2):
        log.failure("Usage: "+argv[0]+" <test_binary>")
        exit(1) 
    fstring = Format_String(sys.argv[1])
    print fstring.get_buf_addr(0x40)

if __name__ == "__main__":
    test_module(sys.argv)
