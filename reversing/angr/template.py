#!/usr/bin/python

import angr
from pwn import *

# Binary Variables
BINARY =                # TODO - filename
INPUT_LENGTH =          # TODO - input number of bytes
BASE = 0x400000         # TODO - check in IDA (unlikely to change) 
START_ADDR = BASE +     # TODO - address of instruction to start at
FIND_ADDR = BASE +      # TODO - address of instruction to try and get to
AVOID_ADDRS = []        # TODO - address of instructions avoid

# Modify registers and memory (instead of getting stdin to work)
def read(state):
    global buf
    buf = state.regs.rdi   # TODO - register to modify
    # Let every input character be an unkown value
    for i in xrange(INPUT_LENGTH):
        state.mem[buf+i].char = state.se.BVS('c', 8)
    # Set number of bytes read in as return value
    state.regs.eax = INPUT_LENGTH

# Setup and run angr
def main():
    # Create an angr project
    log.info('loading binary')
    p = angr.Project(BINARY, load_options={'auto_load_libs': False})

    # Construct the initial program state
    log.info('setting up state')
    state = p.factory.blank_state(addr=START_ADDR)

    # TODO - Add any hooks
    # e.g. Avoid reading from stdin:
    #       1. Skip past read function
    #       2. Directly modify the registers via read() above
    p.hook(BASE+0x274a, hook=read, length=5)

    # Construct a simulation manager to perform symbolic execution
    # and explore to the given address.
    log.info('exploring')
    sim = p.factory.simulation_manager(state)
    sim.explore(find=FIND_ADDR, avoid=AVOID_ADDRS)

    # Display results
    if sim.found:
        result = sim.found[0].state.se.eval(
                sim.found[0].state.memory.load(
                    buf, INPUT_LENGTH), cast_to=str)
        log.success(result)
    else:
        log.error('No path found')


if __name__ == "__main__":
    before = time.time()
    main()
    after = time.time()
    log.info("Time elapsed: {}".format(after - before))

