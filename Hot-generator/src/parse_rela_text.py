from elftools.elf.elffile import ELFFile
from template import RelocationInterinfo
from elf_info import relocation_types
from get_insturctions import *
import struct
import logging

# 配置日志输出格式和级别
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


def get_plt_sections_ranges(elf_file_path):
    plt_sections = {}
    with open(elf_file_path, "rb") as f:
        elf_file = ELFFile(f)

        for section in elf_file.iter_sections():
            if section.name in (".plt.got", ".plt.sec"):
                plt_sections[section.name] = (
                    section["sh_addr"],
                    section["sh_addr"] + section["sh_size"],
                )

    return plt_sections


def targetaddr_in_pltsections(plt_sections, target_addr):
    for keyword, values in plt_sections.items():
        plt_start = values[0]
        plt_end = values[1]
        if (target_addr >= plt_start) & (target_addr < plt_end):
            return True
    return False


def parse_rela_text_section(filename, index,lib_instructions):
    print(f"paser {filename} rela_text")
    instructions=lib_instructions
    relocations_internal = []

    with open(filename, "rb") as f:
        elf_file = ELFFile(f)

        # 获取.rela.text节
        rel_text_section = elf_file.get_section_by_name(".rela.text")
        if not rel_text_section:
            print(f"{filename} No .rela.text section found")
            return []

        plt_sections = get_plt_sections_ranges(filename)

        # 解析重定位项
        for relocation in rel_text_section.iter_relocations():
            offset = relocation["r_offset"]
            r_addend = relocation["r_addend"] if "r_addend" in relocation.entry else 0
            r_type = relocation["r_info_type"]
            symbol_index = relocation["r_info_sym"]
            
            if r_type==relocation_types["R_X86_64_DTPOFF32"]:
                logging.warning(f"R_X86_64_DTPOFF32 internal relocation parse may fault:{hex(offset)}")
                continue

            # 相对偏移地址计算：
            target_address = 0
            if r_type in [
                relocation_types["R_X86_64_PLT32"],
                relocation_types["R_X86_64_GOTTPOFF"],
                relocation_types["R_X86_64_GOTPCREL"],
                relocation_types["R_X86_64_REX_GOTPCRELX"],
                relocation_types["R_X86_64_PC32"],
                relocation_types["R_X86_64_TLSGD"],
                relocation_types["R_X86_64_TLSLD"],
            ]:
                f.seek(offset)
                four_bytes = f.read(4)
                instr_imm = struct.unpack("<i", four_bytes)[0]

                if r_type != relocation_types["R_X86_64_PC32"]:
                    if r_addend not in [-4, -5]:
                        logging.warning(
                            f"internal relocation parse fault:  {hex(offset)} type:{r_type} addend: {hex(r_addend)} {hex(instr_addend)}"
                        )
                    instr_addend = r_addend
                else:
                    instr_address, instr_size = find_instruction(
                        offset, instructions=instructions
                    )

                    if instr_address == 0:
                        logging.error(
                            f"can not find instruction of this internal rela {hex(offset)}"
                        )
                    instr_addend = offset - instr_address - instr_size
                    if instr_addend not in [-4, -5, -8]:
                        logging.warning(
                            f"internal relocation parse fault:  instr:{hex(instr_address)} size:{instr_size} r_offset:{hex(offset)} type:{r_type} addend: {hex(r_addend)} {hex(instr_addend)}"
                        )

                target_address = offset - instr_addend + instr_imm

            else:
                logging.error(
                    f"unprocess .rela.text internal relocation {hex(offset)} type {r_type} {hex(r_addend)}"
                )
            target_address_ori = target_address

            if r_type == relocation_types["R_X86_64_PLT32"]:
                if targetaddr_in_pltsections(plt_sections, target_address):
                    r_type = relocation_types["R_X86_64_PLT32_GOT"]

            rel_internal = RelocationInterinfo(
                offset=offset,
                ori_offset=offset,
                ori_target=target_address_ori,
                r_type=r_type,
                r_sym=symbol_index,
                r_addend=instr_addend,
                r_l_index=index,
                target_addr=target_address,
            )
            relocations_internal.append(rel_internal)

    return relocations_internal
