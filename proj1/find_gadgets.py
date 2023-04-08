#! /usr/bin/python3

"""
This script finds gadgets in 64-bit ELF executables.

Usage: ./find_gadgets.py [filename]

Author: George Hosono
"""

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section
from iced_x86 import *
import binascii
import sys

return_insts = {Code.RETFD, \
                Code.RETFQ, \
                Code.RETFW, \
                Code.RETND, \
                Code.RETNQ, \
                Code.RETNW, \
                Code.RETFD_IMM16, \
                Code.RETFQ_IMM16, \
                Code.RETFW_IMM16, \
                Code.RETND_IMM16, \
                Code.RETNQ_IMM16, \
                Code.RETNW_IMM16}

def get_text_section(filename):
    f = open(filename, "rb")
    elf_file = ELFFile(f)
    text_section = elf_file.get_section_by_name(".text")
    return text_section

def read_snippets(text_section: Section):
    binary = text_section.data()
    start_addr = text_section["sh_addr"]

    snippets = []
    start_point = 0
    while True:
        next_pos = binary.find(0xc3, start_point)
        if next_pos == -1:
            break

        for i in range(1, 20):
            if i > next_pos:
                break
            snippets.append( \
                list(Decoder(64, binary[next_pos - i: next_pos+1], ip=start_addr+next_pos-i)))
        start_point = next_pos + 1

    return snippets

def disassemble(data: bytes) -> None:
    formatter = Formatter(FormatterSyntax.GAS)
    decoder = Decoder(64, data)
    for instruction in decoder:
        disasm = formatter.format(instruction)
        print(f"{instruction.ip:016X} {disasm}")
        print()

def find_gadgets(snippets):
    gadgets = []
    for snip in snippets:
        if snip[-1].code not in return_insts:
            continue

        ok = True
        for inst in snip:
            if inst.is_invalid:
                ok = False
                break
        if not ok:
            continue

        gadgets.append(snip)
    return gadgets

formatter = Formatter(FormatterSyntax.GAS)
def print_gadgets(gadgets):
    for gadget in gadgets:
        if len(gadget) == 0:
            continue
        insts = "; ".join([formatter.format(instruction) for instruction in gadget])
        encoder = BlockEncoder(64)
        encoder.add_many(gadget)
        binary = encoder.encode(gadget[0].ip).hex()
        print(f"position: {gadget[0].ip:#08x}. insts: {insts}. bytes: {binary}")

def main():
    if len(sys.argv) < 2:
        print("Usage: find_gadgets: [binary]")
        sys.exit(1)

    text_section = get_text_section(sys.argv[1])
    snippets = read_snippets(text_section)
    gadgets = find_gadgets(snippets)
    print_gadgets(gadgets)

if __name__ == "__main__":
    main()
