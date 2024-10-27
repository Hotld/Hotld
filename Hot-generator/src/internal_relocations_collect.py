from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS
from elf_info import *
from template import *
from parse_rela_text import *
from external_relocations_collect import *
from judge_addr_location import *
from process_rodata import *
import logging

# 配置日志输出格式和级别
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


def judge_local_rela(fd, offset, r_addend, r_l_index, r_type):
    fd.seek(offset)
    value = fd.read(4)
    offset_value = int.from_bytes(value, byteorder="little", signed=True)
    target_address = offset - r_addend + offset_value

    fd.seek(offset - 1)
    opcode = int.from_bytes(fd.read(1), byteorder="little", signed=False)
    fd.seek(offset - 3)
    bytes_read = fd.read(3)
    hex_representation = bytes_read.hex()

    if (hex(opcode) in ["0xe8", "0xe9"]) | (
        hex_representation
        in [
            "488d05",
            "488d0d",
            "488d15",
            "488d1d",
            "488d2d",
            "488d35",
            "488d3d",
            "4c8d0d",
            "4c8d05",
            "4c8d15",
            "4c8d1d",
            "4c8d2d",
            "4c8d25",
            "4c8d35",
            "4c8d3d",
        ]
    ):
        print(
            f"R_X86_64_LOCALCALL cur_rela: offset:{hex(offset)} addend:{r_addend} offset_value:{hex(offset_value)} target_offset:{hex(target_address)} opcode:{hex(opcode)}"
        )
        rel_internal = RelocationInterinfo(
            offset=offset,
            ori_offset=offset,
            ori_target=target_address,
            r_type=r_type,
            r_sym=-1,
            r_addend=r_addend,
            r_l_index=r_l_index,
            target_addr=target_address,
        )
        return rel_internal, False
    elif hex(opcode) == "0xeb":
        return None, True

    return None, False


def get_hot_functions_local_funcall(library, hot_function_info, hot_template):
    function_info = hot_function_info[library]["order"]
    local_rela = hot_function_info[library]["local_rel"]
    print(f"function info\n {function_info}")

    relocations = []

    with open(library, "rb") as f:
        for rela in local_rela:
            offset = rela["r_offset"]
            r_addend = rela["r_addend"]
            target_address=rela["target"]
            r_type = relocation_types["R_X86_64_LOCALCALL"]
            r_l_index = hot_template.depend_table[library]
            
            rel_internal = RelocationInterinfo(
            offset=offset,
            ori_offset=offset,
            ori_target=target_address,
            r_type=r_type,
            r_sym=-1,
            r_addend=r_addend,
            r_l_index=r_l_index,
            target_addr=target_address,
            )
            relocations.append(rel_internal)


    return relocations


def get_hot_functions_internal_rela(
    rel_internals,
    hot_template,
    hot_functions_info,
    library,
):
    # 添加本地函数调用重定位项
    local_relocations = get_hot_functions_local_funcall(
        library, hot_functions_info, hot_template
    )

    rel_internals.extend(local_relocations)
    print(f"num of relacation internal with localcall {len(local_relocations)}")

    tmp_rel_internals = []
    text_header = hot_template.data_infos[library][0]
    print(f"hotlib text_info: {text_header}")

    fun_info = hot_functions_info[library]["text_info"]
    sorted_fun_info = []
    for key, value in fun_info.items():
        sorted_fun_info.append([value["ori_value"], value["maxsize"], value])

    sorted_fun_info.sort(key=lambda x: x[0])

    for relocation in rel_internals:
        offset = relocation.offset
        target_address_ori = relocation.target_address
        offset_sym_infos = is_address_in_hot_function(offset, sorted_fun_info)

        # 如果重定位项不属于热点函数
        if offset_sym_infos == None:
            continue

        print(f"offset_sym_info:{offset_sym_infos}")

        func_start_ori = offset_sym_infos["ori_value"]
        func_start_hot = offset_sym_infos["st_value"]

        # 将重定位项偏移转换到热点函数代码中
        offset_hot = offset - func_start_ori + func_start_hot

        # 将重定位项偏移转换到代码模版中
        offset_template = (
            offset_hot - text_header["sh_addr"] + text_header["sh_hot_addr"]
        )

        modify_relocation = relocation
        modify_relocation.offset = offset_template

        # 如果目标地址仍然属于热点函数
        target_sym_infos = is_address_in_hot_function(
            target_address_ori, sorted_fun_info
        )
        if target_sym_infos != None:
            start = target_sym_infos["ori_value"]
            hot_start = target_sym_infos["st_value"]
            target_addr_hot = target_address_ori - start + hot_start
            target_addr_template = (
                target_addr_hot - text_header["sh_addr"] + text_header["sh_hot_addr"]
            )

            modify_relocation.r_info_type = relocation_types[
                "R_X86_64_LOCALCALL_IN_TMP"
            ]
            modify_relocation.target_address = target_addr_template

        tmp_rel_internals.append(modify_relocation)
        print(
            f"{library} hot function internal relocation r_type: {modify_relocation.r_info_type} offset_ori: {hex(offset)} offset: {hex(modify_relocation.offset)} target_ori: {hex(target_address_ori)} target:{hex(modify_relocation.target_address)}"
        )

    rel_internals = tmp_rel_internals
    print(f"num of hot function relacation internal {len(rel_internals)}")
    return rel_internals


def collect_total_internal_relocations(
    hot_template, need_merge_library, hot_functions_info,hotlib_instructions
):

    relocation_internal = {}
    for hotlib in need_merge_library:
        logging.info(f"collect internal relocation of {hotlib}")
        index = hot_template.depend_table[hotlib]
        lib_instructions=hotlib_instructions[hotlib]["instructions"]
        rel_internals = parse_rela_text_section(hotlib, index,lib_instructions)
        print(f"num of {hotlib} total relacation internal {len(rel_internals)}")
        text_header = hot_template.data_infos[hotlib][0]

        # 1）过滤掉不属于hot template text中的重定位项
        # 2）去除掉重定位目标地址仍在text段的重定位项
        if hot_functions_info[hotlib] != {}:
            rel_internals = get_hot_functions_internal_rela(
                rel_internals=rel_internals,
                hot_template=hot_template,
                hot_functions_info=hot_functions_info,
                library=hotlib,
            )
            logging.info(
                f"internal relocation number of {hotlib}: {len(rel_internals)}"
            )
        else:
            tmp_rel_internals = []
            for relocation in rel_internals:
                offset = relocation.offset
                # 判断目标地址是否仍在text中
                target_address = relocation.target_address
                text_start = text_header["vaddr"]
                text_end = text_header["vaddr"] + text_header["memsize"]
                if (target_address > text_start) & (target_address < text_end):
                    # print(f"debug info: {hex(offset)} {hex(target_addr)}")
                    continue

                offset_template = (
                    offset - text_header["vaddr"] + text_header["hot_vaddr"]
                )
                modify_relocation = relocation
                modify_relocation.offset = offset_template
                tmp_rel_internals.append(modify_relocation)
                print(
                    f"debug info: offset {hex(offset)} template offset {hex(offset_template)} target:{hex(relocation.target_address)}"
                )
            rel_internals = tmp_rel_internals

            logging.info(
                f"internal relocation number of {hotlib}: {len(rel_internals)}"
            )

        print(f"{hotlib} num of relacation internal {len(rel_internals)}")

        """
        if ("libc.so.6" not in hotlib):
            if hot_functions_info[hotlib] != {}:
                fun_info = hot_functions_info[hotlib]["text_info"]
                sorted_fun_info = []
                for key, value in fun_info.items():
                    sorted_fun_info.append(
                        [value["ori_value"], value["maxsize"], value]
                    )

                sorted_fun_info.sort(key=lambda x: x[0])

                rodata_entries, pending_relocations = get_target_in_rodata_relocations(
                    hotlib, rel_internals, sorted_fun_info
                )

                if pending_relocations!=[]:
                    rel_internals = process_target_in_readonly_relocations(
                        hot_template,
                        rel_internals,
                        pending_relocations,
                        rodata_entries,
                        text_header,
                    )
            else:
                logging.info(f"{hotlib} rela.rodata don't process")
            """
        
        
        relocation_internal[hotlib] = rel_internals

    for keyword, value in relocation_internal.items():
        print(f"num of hot hot function relacation internal {len(rel_internals)}")
        hot_template.relocationInternal.extend(value)
