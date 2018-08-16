#!/usr/bin/env python
import sys
from pwn import *

class Misc():

    def __init__(self, filename):
        context.log_level = 'CRITICAL'
        self.elf = context.binary = ELF(filename)
        self.arch = self.elf.get_machine_arch()

    # Pack a value based on the binary architecture
    def p(self, value):
        if ("64" in self.arch):
            return p64(value)
        elif ("32" in self.arch or "86" in self.arch):
            return p32(value)
        else:
            log.failure("Unknown architecture: " + arch)
            exit(1)

    # XOR encode to avoid bad characters in a string
    # "plain" is the string to encode
    # "avoid" is a byte array of bad chars
    # Returns a (cipher, decrypt_key) tuple
    def xor_encode(self, plain, avoid):
        cipher = ""
        decrypt_key = ""
        # Encode each character
        for char in plain:
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


def test_module(argv):
    if (len(sys.argv) != 2):
        log.failure("Usage: "+argv[0]+" <test_binary>")
        exit(1)
    d = Misc(sys.argv[1])

if __name__ == "__main__":
    test_module(sys.argv)
