from elftools.elf.elffile import ELFFile
from elftools.elf.constants import P_FLAGS
from elf_info import *
from template import *
from judge_addr_location import *
import struct
import logging
from get_library_function import *

# 配置日志输出格式和级别
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


def is_address_in_text(text_sections, r_target):
    text_offset = None
    for section in text_sections:
        text_offset = section["sh_addr"]
        text_end = text_offset + section["sh_size"]
        if (r_target >= text_offset) & (r_target < text_end):
            return True
    return False


# 获取hotlib 指向text的got表项
def get_external_relocations_of_hotlib(file_path, symbol_infos):

    with open(file_path, "rb") as file:
        elffile = ELFFile(file)
        writable_segments = []
        for segment in elffile.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                if segment["p_flags"] & P_FLAGS.PF_W:
                    writable_segments.append(segment.header)
        for item in writable_segments:
            print(f"{file_path} writable_segments {item}")

        program_sections = []
        for section in elffile.iter_sections():
            if section.name in [".text"]:
                program_sections.append(section.header)
                
        relocations = {}
        for section in elffile.iter_sections():
            if section.name == ".rela.text":
                continue
            if section.header["sh_type"] in ("SHT_RELA", "SHT_REL"):
                for relocation in section.iter_relocations():
                    r_offset = relocation["r_offset"]

                    if is_address_in_text(program_sections, r_offset):
                        continue
                    

                    if (
                        is_address_in_load_write_segment(writable_segments, r_offset)
                        == False
                    ):
                        continue

                    r_type = relocation["r_info_type"]

                    symbol = elffile.get_section(section.header["sh_link"]).get_symbol(
                        relocation.entry.r_info_sym
                    )
                    cure_rela = {}

                    if symbol != None:
                        symbol_offset = symbol.entry["st_value"]
                        symbol_name = symbol.name
                        symbol_type = symbol["st_info"]["type"]

                        if symbol_type == "STT_OBJECT":
                            continue

                        # 去除重复的重定位信息
                        if hex(r_offset) in relocations:
                            r_another_offset = relocations[hex(r_offset)]["r_type"]
                            if r_type in [
                                relocation_types["R_X86_64_32"],
                            ]:
                                continue
                            if r_type not in [
                                relocation_types["R_X86_64_RELATIVE"],
                                relocation_types["R_X86_64_64"],
                            ]:
                                if r_another_offset not in [
                                    relocation_types["R_X86_64_RELATIVE"],
                                    relocation_types["R_X86_64_64"],
                                ]:
                                    logging.error(
                                        f"hotlib duplicate relocation parse fault {hex(r_offset)} {r_type}"
                                    )
                            continue

                        # 计算重定位项的目标地址
                        if r_type in [
                            relocation_types["R_X86_64_NONE"],
                            relocation_types["R_X86_64_DTPMOD64"],
                            relocation_types["R_X86_64_DTPOFF64"],
                            relocation_types["R_X86_64_TPOFF64"],
                            relocation_types["R_X86_64_DTPOFF32"],
                            relocation_types["R_X86_64_32"],
                        ]:
                            continue
                        elif r_type == relocation_types["R_X86_64_PC32"]:
                            if is_address_in_load_write_segment(
                                writable_segments, r_offset
                            ):
                                logging.error(
                                    f"R_X86_64_PC32 may parse falut {hex(r_offset)}!"
                                )
                            continue

                        elif r_type in [
                            relocation_types["R_X86_64_JUMP_SLOT"],
                            relocation_types["R_X86_64_GLOB_DAT"],
                            relocation_types["R_X86_64_REX_GOTPCRELX"],
                        ]:
                            if symbol_name in symbol_infos:
                                if symbol_offset not in symbol_infos[symbol_name]:
                                    continue
                                r_addend = relocation["r_addend"]

                                cure_rela = {
                                    "r_type": r_type,
                                    "r_offset": r_offset,
                                    "sym_name": symbol_name,
                                    "sym_offset": symbol_offset,
                                    "sym_type": symbol_type,
                                    "r_target": symbol_offset,
                                    "r_hot_target": symbol_offset,
                                    "r_addend": r_addend,
                                }

                                relocations[hex(r_offset)] = cure_rela
                                continue
                        elif (r_type == relocation_types["R_X86_64_64"]) | (
                            r_type == relocation_types["R_X86_64_RELATIVE"]
                        ):
                            r_addend = relocation["r_addend"]
                            r_target = symbol_offset + r_addend

                            if is_address_in_text(program_sections, r_target) == False:
                                continue

                            cure_rela = {
                                "r_type": r_type,
                                "r_offset": r_offset,
                                "sym_name": symbol_name,
                                "sym_offset": symbol_offset,
                                "sym_type": symbol_type,
                                "r_target": r_target,
                                "r_hot_target": r_target,
                                "r_addend": r_addend,
                            }
                            relocations[hex(r_offset)] = cure_rela
                            continue
                        else:
                            logging.error(
                                f"hotlib unprocess relacation type {r_type} {hex(r_offset)}"
                            )
    return relocations


# 获取hotlib指向热点函数的got表项
def filter_external_relocations_of_hotlib(hot_relocations, hotlib_hot_functions):

    new_relocations = {}
    sorted_symbol_infos = []
    for key, value in hotlib_hot_functions.items():
        sorted_symbol_infos.append([value["ori_value"], value["maxsize"], value])

    sorted_symbol_infos.sort(key=lambda x: x[0])
    for item in sorted_symbol_infos:
        print(f"sorted symbol infos: {item}")

    for key, rela in hot_relocations.items():
        r_target = rela["r_target"]

        func = is_address_in_hot_function(r_target, sorted_symbol_infos)
        if func != None:
            func_start = func["ori_value"]
            func_hot_start = func["st_value"]
            r_hot_target = r_target - func_start + func_hot_start
            new_relocations[key] = rela
            new_relocations[key]["r_hot_target"] = r_hot_target

    return new_relocations


def convert_external_relocations_of_hotlib(
    hot_relocations, text_info, hotlib, hotlib_index
):
    cur_lib_rela_exter = []
    for key, rela in hot_relocations.items():

        # print(f"rela: {rela}")
        offset = rela["r_offset"]
        r_target = rela["r_target"]
        r_hot_target = rela["r_hot_target"]
        r_addend = rela["r_addend"]

        r_temp_target = r_hot_target - text_info["vaddr"] + text_info["hot_vaddr"]

        if rela["r_type"] == relocation_types["R_X86_64_IRELATIVE"]:
            r_target = text_info["vaddr"]
            r_temp_target = text_info["hot_vaddr"]
            r_addend = text_info["sh_size"]

            print(
                f"collect hotlib external R_X86_64_IRELATIVE {hex(r_target)} {hex(r_temp_target)}"
            )

        print(
            f"collect hotlib external: r_target: {hex(r_target)} r_hot_target:{hex(r_hot_target)} r_temp_target:{hex(r_temp_target)}"
        )
        l_index = hotlib_index
        rela_entry = RelocationExterinfo(
            r_offset=offset,
            st_value=r_temp_target,
            ori_value=r_target,
            r_l_index=l_index,
            sour_l_index=l_index,
            r_type=rela["r_type"],
            r_addend=r_addend,
        )
        cur_lib_rela_exter.append(rela_entry)

    print(f"{hotlib} exter relocation number: {len(cur_lib_rela_exter)}")

    total_lib_rela_exter = cur_lib_rela_exter

    print(f"{hotlib} self exter relocation number: {len(total_lib_rela_exter)}")
    logging.info(f"{hotlib} self exter relocation number: {len(total_lib_rela_exter)}")

    return total_lib_rela_exter


def get_external_relocations_of_parentlib(parlib, dynamic_functions):
    with open(parlib, "rb") as file:
        elffile = ELFFile(file)
        writable_segments = []
        for segment in elffile.iter_segments():
            if segment["p_type"] == "PT_LOAD":
                if segment["p_flags"] & P_FLAGS.PF_W:
                    writable_segments.append(segment.header)
        for item in writable_segments:
            print(f"{parlib} writable_segments {item}")

        relocations = {}
        for section in elffile.iter_sections():
            if section.name == ".rela.text":
                continue

            if section.header["sh_type"] in ("SHT_RELA", "SHT_REL"):
                for relocation in section.iter_relocations():
                    symbol = elffile.get_section(section.header["sh_link"]).get_symbol(
                        relocation.entry.r_info_sym
                    )
                    cur_rela = {}
                    if symbol != None:
                        symbol_offset = symbol.entry["st_value"]
                        symbol_name = symbol.name
                        symbol_type = symbol["st_info"]["type"]

                        if (symbol_offset != 0) | (symbol_type == "STT_OBJECT"):
                            continue

                        r_offset = relocation["r_offset"]
                        r_type = relocation["r_info_type"]

                        # 去除r_offset在代码段的偏移
                        if (
                            is_address_in_load_write_segment(
                                writable_segments, r_offset
                            )
                            == False
                        ):
                            continue

                        if r_type in [
                            relocation_types["R_X86_64_32"],
                        ]:
                            continue

                        if hex(r_offset) in relocations:
                            if r_type not in [
                                relocation_types["R_X86_64_RELATIVE"],
                                relocation_types["R_X86_64_64"],
                            ]:
                                logging.error(
                                    f"parlib duplicate relocation parse fault {hex(r_offset)} {r_type}"
                                )
                            continue

                        if symbol_name not in dynamic_functions:
                            continue

                        if r_type in [
                            relocation_types["R_X86_64_JUMP_SLOT"],
                            relocation_types["R_X86_64_GLOB_DAT"],
                            relocation_types["R_X86_64_64"],
                        ]:
                            r_addend = relocation["r_addend"]
                        else:
                            logging.error(
                                f"unprocess parlib exter relocation {hex(r_offset)} type:{r_type} func: {symbol_name}"
                            )
                            continue

                        st_value = dynamic_functions[symbol_name]

                        cur_rela = {
                            "r_type": r_type,
                            "r_offset": r_offset,
                            "sym_name": symbol_name,
                            "sym_offset": symbol_offset,
                            "r_offset_value": 0,
                            "sym_type": symbol_type,
                            "r_target": st_value,
                            "r_addend": r_addend,
                        }
                        relocations[hex(r_offset)] = cur_rela
                        if cur_rela == {}:
                            print(
                                f"can't find this rela symbol: {symbol_name} {cur_rela} {hex(r_offset)} "
                            )

    return relocations


def convert_external_relocations_of_parentlib(
    relocations, hot_functions, text_info, parlib, parlib_index, hotlib_index
):
    cur_lib_rela_exter = []
    for key, rela in relocations.items():
        symbol_name = rela["sym_name"]
        ori_value = rela["r_target"]
        offset = rela["r_offset"]

        if (symbol_name, ori_value) in hot_functions:
            print(f"hot_function parlib {hot_functions[(symbol_name, ori_value)]}")
            sym_value = hot_functions[(symbol_name, ori_value)]["st_value"]
            ori_value = hot_functions[(symbol_name, ori_value)]["ori_value"]
            sym_value_hot = sym_value - text_info["vaddr"] + text_info["hot_vaddr"]

            rela_entry = RelocationExterinfo(
                offset,
                sym_value_hot,
                ori_value,
                r_l_index=parlib_index,
                sour_l_index=hotlib_index,
                r_type=rela["r_type"],
                r_addend=rela["r_addend"],
            )
            print(
                f"parlib: {parlib}:  r_offset: {offset} r_type:{rela['r_type']} ori_value:{hex(ori_value)} st_value: {hex(sym_value)} st_hot_value: {hex(sym_value_hot)}"
            )
            cur_lib_rela_exter.append(rela_entry)
        else:
            logging.error(f"exter rela parse fault: {hex(offset)} {symbol_name}")

    return cur_lib_rela_exter


def get_dynamic_and_sym_func_in_hotfunction(hotlib, hot_function_info):
    hotlib_dynamic_functions = get_dynamic_function(hotlib)
    hotlib_symtab_functions = get_symtab_function(hotlib)

    if hot_function_info[hotlib] != {}:
        hotlib_hot_functions = hot_function_info[hotlib]["text_info"]
    else:
        hotlib_hot_functions = {}

    dynamic_functions_keys = list(hotlib_dynamic_functions.keys())
    hot_functions_keys = list(hotlib_hot_functions.keys())
    symtab_functions_keys = list(hotlib_symtab_functions.keys())

    dynamic_functions_dict = {}
    for func, st_value in dynamic_functions_keys:
        if func in dynamic_functions_dict:
            if (func, st_value) in hot_functions_keys:
                logging.error(
                    f"dynamic function parse error,dynamic function may duplicate, {func}"
                )
        else:
            dynamic_functions_dict[func] = st_value

    symtab_function_dict = {}
    for func, st_value in symtab_functions_keys:
        if func in symtab_function_dict:
            print(f"{hotlib} has symtab functions of the same name {func}")
            symtab_function_dict[func].append(st_value)
        else:
            symtab_function_dict[func] = []
            symtab_function_dict[func].append(st_value)

    same_hot_functions=[]
    hot_functions_dict = {}
    if hotlib_hot_functions != {}:
        for func, st_value in hot_functions_keys:
            if func in hot_functions_dict:
                same_hot_functions.append(func)
                hot_functions_dict[func].append(st_value)
            else:
                hot_functions_dict[func] = []
                hot_functions_dict[func].append(st_value)
    same_hot_functions=list(set(same_hot_functions))
    for x in same_hot_functions:
        logging.info(f"{hotlib} has hot functions of the same name {x}")

    if hotlib_hot_functions != {}:
        new_dynamic_dict = {}
        count = 0
        for key, value in dynamic_functions_dict.items():
            if key in hot_functions_dict:
                if value in hot_functions_dict[key]:
                    new_dynamic_dict[key] = value
                    count += 1
        logging.info(f"{hotlib} {count} dynamic functions in hot functions")

        new_symtab_dict = {}
        for key, value in symtab_function_dict.items():
            if key in hot_functions_dict:
                new_value = []
                for item in value:
                    if item in hot_functions_dict[key]:
                        new_value.append(item)
                if new_value != []:
                    new_symtab_dict[key] = new_value
        logging.info(f"{hotlib} {count} symtab functions in hot functions")

        dynamic_functions_dict = new_dynamic_dict
        symtab_function_dict = new_symtab_dict

    for func, value in dynamic_functions_dict.items():
        print(f"dynamic function: {func} {hex(value)}")
    return dynamic_functions_dict, symtab_function_dict, hot_functions_dict


def collect_total_external_relocations(
    hot_template,
    need_merge_library,
    dependency_parent,
    hot_function_info,
    special_names,
):
    for hotlib in need_merge_library:
        logging.info(f"collect external relocation of {hotlib}")
        text_info = hot_template.data_infos[hotlib][0]

        print(f"text_info:{text_info}")
        hotlib_dynamic_functions = get_dynamic_function(hotlib)

        dynamic_functions, symtab_functions, hot_functions = (
            get_dynamic_and_sym_func_in_hotfunction(hotlib, hot_function_info)
        )

        # 收集依赖该库的动态库的外部引用
        for parlib in dependency_parent[hotlib]:
            logging.info(f"collect external relocation of {hotlib} {parlib}")

            print(f"hotlib:{hotlib},parlib:{parlib}")
            relocations = get_external_relocations_of_parentlib(
                parlib, dynamic_functions
            )

            target_sym_info = hotlib_dynamic_functions
            if hot_functions != {}:
                target_sym_info = hot_function_info[hotlib]["text_info"]

            cur_lib_rela_exter = convert_external_relocations_of_parentlib(
                relocations,
                target_sym_info,
                text_info,
                parlib,
                hot_template.depend_table[parlib],
                hot_template.depend_table[hotlib],
            )
            logging.info(
                f"The number of exter relocation of {parlib}: {len(cur_lib_rela_exter)}"
            )
            hot_template.relocationExternal.extend(cur_lib_rela_exter)

        # 收集该库本身的外部引用
        logging.info(f"collect external relocation of {hotlib} {hotlib}")

        if "libc.so.6" in hotlib:
            hot_relocations = {}
        else:
            if hot_functions != {}:
                hot_relocations = get_external_relocations_of_hotlib(
                    hotlib, hot_functions
                )
                logging.info(f"filter exter relocation of {hotlib} {hotlib}")

                hot_relocations = filter_external_relocations_of_hotlib(
                    hot_relocations, hot_function_info[hotlib]["text_info"]
                )

                cur_lib_rela_exter = convert_external_relocations_of_hotlib(
                    hot_relocations,
                    text_info,
                    hotlib,
                    hot_template.depend_table[hotlib],
                )
            else:
                hot_relocations = get_external_relocations_of_hotlib(
                    hotlib, symtab_functions
                )
                cur_lib_rela_exter = convert_external_relocations_of_hotlib(
                    hot_relocations,
                    text_info,
                    hotlib,
                    hot_template.depend_table[hotlib],
                )

        hot_template.relocationExternal.extend(cur_lib_rela_exter)
