from elftools.elf.elffile import ELFFile
from elf_info import *
from template import *
from judge_addr_location import *
import logging


def get_symtab_function(library):
    symbols = {}
    with open(library, "rb") as f:
        elf_file = ELFFile(f)

        symtab = elf_file.get_section_by_name(".symtab")
        if not symtab:
            logging.error(f"can't find symtab section in {library}")

        for symbol in symtab.iter_symbols():
            if (symbol.entry.st_info.type == "STT_FUNC") & (symbol["st_value"] != 0):
                st_value = symbol["st_value"]
                name = symbol.name
                symbols[st_value] = {
                    "st_name": symbol.name,
                    "st_value": st_value,
                    "ori_value": st_value,
                    "maxsize": symbol["st_size"],
                }

        new_symbols = {}
        for key, value in symbols.items():
            name = value["st_name"]
            st_value = value["ori_value"]
            new_symbols[(name, st_value)] = value

    return new_symbols


def get_dynamic_function(library):
    symbols = {}
    with open(library, "rb") as f:
        elf_file = ELFFile(f)

        symtab = elf_file.get_section_by_name(".dynsym")
        if not symtab:
            logging.error(f"can't find dynsym section in {library}")

        for symbol in symtab.iter_symbols():
            if (symbol.entry.st_info.type == "STT_FUNC") & (symbol["st_value"] != 0):
                st_value = symbol["st_value"]
                st_name = symbol.name
                symbols[(st_name, st_value)] = {
                    "st_name": symbol.name,
                    "st_value": st_value,
                    "ori_value": st_value,
                    "maxsize": symbol["st_size"],
                }

    return symbols
