from elftools.elf.elffile import ELFFile
from template import RelocationInterinfo
from elf_info import relocation_types
from get_insturctions import *
import struct
import logging


def parse_rela_text_section(filename):

    with open(filename, "rb") as f:
        elf_file = ELFFile(f)
        rela_text_rela_type = []

        # 获取.rela.text节
        rel_text_section = elf_file.get_section_by_name(".rela.text")
        if not rel_text_section:
            print(f"{filename} No .rela.text section found")
            return []

        # 解析重定位项
        for relocation in rel_text_section.iter_relocations():
            offset = relocation["r_offset"]
            r_addend = relocation["r_addend"] if "r_addend" in relocation.entry else 0
            r_type = relocation["r_info_type"]
            rela_text_rela_type.append(r_type)

            print(
                f"rela.text relocation: {hex(offset)} type:{r_type} addend: {hex(r_addend)} "
            )

    print(f"rela_text_type:{list(set(rela_text_rela_type))}")
    return


def parse_rela(file_name):
    with open(file_name, "rb") as file:
        elffile = ELFFile(file)

        for section in elffile.iter_sections():
            if section.header["sh_type"] in ("SHT_RELA", "SHT_REL"):
                for relocation in section.iter_relocations():
                    offset = relocation["r_offset"]
                    r_addend = (
                        relocation["r_addend"] if "r_addend" in relocation.entry else 0
                    )
                    r_type = relocation["r_info_type"]
                    print(
                        f"rela.text relocation: {hex(offset)} type:{r_type} addend: {hex(r_addend)} "
                    )


parse_rela("/home/ning/Desktop/Ning/hot_function_combind/lib/librocksdb.so.9")
