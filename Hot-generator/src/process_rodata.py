from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS
from judge_addr_location import *
import struct
import logging

# 配置日志输出格式和级别
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


def get_target_in_rodata_relocations(library, rel_internals, symbol_infos):
    pending_relocations = []
    rodata_entries = {}

    with open(library, "rb") as file:
        elffile = ELFFile(file)
        rodata_section = elffile.get_section_by_name(".rodata")
        rodata_start = rodata_section.header["sh_addr"]
        rodata_end = rodata_start + rodata_section.header["sh_size"]
        print(f"{library} rodata section {hex(rodata_start)} {hex(rodata_end)}")

        rela_rodata_section = elffile.get_section_by_name(".rela.rodata")
        if rela_rodata_section==None:
            logging.info(f"{library} no target_in_rodata_relocations")
            return rodata_entries, pending_relocations
        
        for relocation in rela_rodata_section.iter_relocations():
            r_offset = relocation["r_offset"]
            r_type = relocation["r_info_type"]

            if r_offset < rodata_start:
                continue
            if r_offset >= rodata_end:
                continue
            if r_type != 2:
                logging.error(
                    f"unpreocess rodata section relocation type {hex(r_offset)} r_type:{r_type}"
                )
                continue

            symbol = elffile.get_section(
                rela_rodata_section.header["sh_link"]
            ).get_symbol(relocation.entry.r_info_sym)

            if symbol == None:
                continue

            symbol_offset = symbol.entry["st_value"]
            symbol_type = symbol["st_info"]["type"]

            if symbol_type == "STT_OBJECT":
                logging.info(
                    f"rodata section relocation target is STT_OBJECT {hex(r_offset)}"
                )
                continue

            r_addend = relocation["r_addend"]

            # 计算目标地址
            file.seek(r_offset)
            four_bytes = file.read(4)
            instru_imm = struct.unpack("<i", four_bytes)[0]

            r_target = symbol_offset + r_addend
            func_value = is_address_in_hot_function(r_target, symbol_infos)

            if func_value:
                r_hot_target = (
                    r_target - func_value["ori_value"] + func_value["st_value"]
                )

                rodata_entries[r_offset] = {
                    "r_target": r_target,
                    "r_hot_target": r_hot_target,
                    "instru_imm": instru_imm,
                }

        print(f"number of relocations in rodata section {len(rodata_entries.keys())}")
        pre_item = 0
        for item in rodata_entries.keys():
            distance = item - pre_item
            if distance != 4:
                print(f"distance is not 4 {hex(pre_item)} {hex(item)}")
            pre_item = item

        for relocation in rel_internals:
            target_address = relocation.target_address
            if target_address in rodata_entries:
                pending_relocations.append(relocation.ori_offset)
        logging.info(f"pending_relocations number: {len(pending_relocations)}")
        
        count=0
        for item in pending_relocations:
            count+=1
            logging.info(f"pending_relocations: {count} {hex(item)}")
        
        if "librocksdb.so" in library:
            tmp_array=[]
            delete_array=["0x59c113","0x6325d0","0x3e8eb9","0xabd150"]
            for item in pending_relocations:
                if hex(item) in delete_array:
                    logging.info(f"delete target_in_readonly_relocations {hex(item)}")
                    continue
                tmp_array.append(item)
            pending_relocations=tmp_array
        
        if "libapr-1.so" in library:
            tmp_array=[]
            delete_array=[]
            for item in pending_relocations:
                if hex(item) in delete_array:
                    logging.info(f"delete target_in_readonly_relocations {hex(item)}")
                    continue
                tmp_array.append(item)
            pending_relocations=tmp_array
        
        pending_relocations=[]
        
        
        
        
    return rodata_entries, pending_relocations


def process_target_in_readonly_relocations(
    hot_template, total_relocations, pending_relocations, rodata_entries, text_header
):
    # 创建自己的hot rodata数据
    cur_hot_addr = len(hot_template.template_data)
    rodata_size = 4 * len(rodata_entries)
    print(f"rodata_size: {rodata_size}")
    hot_template.template_data.extend([0] * rodata_size)

    hot_targets = []
    for entry in rodata_entries:
        rodata_entries[entry]["hot_offset"] = cur_hot_addr

        if hot_template.merge_mode != 3:
            logging.info(
                f"rela.rodata can't process in merge_mode {hot_template.merge_mode}"
            )
            return []

        """
        if hot_template.keep_funcorder:
            r_hot_target = (
                rodata_entries[entry]["r_target"]
                - text_header["vaddr"]
                + text_header["hot_vaddr"]
            )
        else:"""

        r_hot_target = rodata_entries[entry]["r_hot_target"]

        new_relative_offset = r_hot_target - cur_hot_addr
        print(f"rodata offset: {entry} {hex(cur_hot_addr)} {hex(new_relative_offset)}")
        packed_int = struct.pack("i", new_relative_offset)
        hot_template.template_data[cur_hot_addr : cur_hot_addr + 4] = packed_int
        cur_hot_addr += 4
        hot_targets.append([rodata_entries[entry]["r_hot_target"], r_hot_target])

    # 完成原本重定位目标项为rela.rodata的text段重定位项的重定位
    pending_relocations.sort()
    count = 0
    tmp_relocations = []
    for rela in total_relocations:
        if rela.ori_offset in pending_relocations:
            count += 1
            r_offset = rela.offset
            r_target = rodata_entries[rela.ori_target]["hot_offset"]
            instr_imm = r_target - r_offset + rela.r_addend
            print(
                f"process_target: offset: {hex(rela.offset)} ori_target:{hex(rela.ori_target)} instr_imm:{hex(instr_imm)} addend:{rela.r_addend} r_target:{hex(r_target)}"
            )
            packed_int = struct.pack("i", instr_imm)
            hot_template.template_data[r_offset : r_offset + 4] = packed_int
        else:
            tmp_relocations.append(rela)
    logging.info(f"process_target_in_readonly_relocations number {count}")
    return tmp_relocations
