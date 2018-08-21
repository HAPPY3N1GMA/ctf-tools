#!/usr/bin/env python
import sys
from pwn import *

class Process():

    def __init__(self, filename):
        context.log_level = 'CRITICAL'
        context.delete_corefiles = True
        self.elf = context.binary = ELF(filename)
        self.process = None
        self.host = ''
        self.port = ''
        self.payload = ""

    #############################
    ##### Pwntools Wrappers #####
    #############################

    def start_process(self, **args):
        self.process = process(self.elf.path, **args)
        return

    def start_remote(self, **args):
        self.process = remote(self.host, self.port, **args)
        return

    def start_debug(self, breaks=[], **args):
        cmds = ""
        for addr in breaks:
            cmds += "break *" + hex(addr) + "\n"
        cmds += "continue\n"
        self.process = gdb.debug(self.elf.path, cmds, **args)
        return

    def sendafter(self, delim, payload, **args):
        self.process.sendafter(delim, payload, **args)
        return

    def sendline(self, payload, **args):
        self.process.sendline(payload, **args)
        return

    def recv(self, nbytes, **args):
        return self.process.recv(nbytes, **args)

    def recvline(self, **args):
        return self.process.recvline(**args)

    def recvall(self, **args):
        return self.process.recvall(**args)
    
    def recvuntil(self, pattern, **args):
        return self.process.recvuntil(pattern, **args)
    
    def recvregex(self, regex, **args):
        return self.process.recvregex(regex, **args)

    def interactive(self, **args):
        self.process.interactive(**args)
        return

    def wait(self, **args):
        self.process.wait(**args)
        return

    #####################################
    ##### GENERIC DEFAULT FUNCTIONS #####
    #####################################

    def start_and_sendline_core(self, buf):
        self.start_process()
        self.sendline(buf)
        self.wait()
        return self.process.corefile

    def start_and_sendline_out(self, buf):
        self.start_process()
        self.sendline(buf)
        return self.recvall()

    def win(self, prompt='', pwn_type='SHELL', process='LOCAL'):
        # Start either local or remote process
        if (process == 'REMOTE'):
            self.start_remote()
        elif (process == 'LOCAL'):
            self.start_process()
        else:
            log.failure("Unknown process type " + process)
            exit(1)

        # Send payload
        self.payload = self.payload.rstrip() + '\n'
        self.sendafter(prompt, self.payload)

        # Do appropriate following action
        if (pwn_type == 'READ_ALL'):
            return self.recvall()
        elif (pwn_type == 'READ_LINE'):
            return self.recvline()
        elif (pwn_type == 'SHELL'):
            return self.interactive()
        return


def test_module(argv):
    if (len(sys.argv) != 2):
        log.failure("Usage: "+argv[0]+" <test_binary>")
        exit(1)
    d = Process(sys.argv[1])

if __name__ == "__main__":
    test_module(sys.argv)
