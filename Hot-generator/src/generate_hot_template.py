from elftools.elf.elffile import ELFFile

from template import *
from elf_info import *
from parse_rela_text import *
from generate_hot_template import *
from parse_cfg import *
import os

pagesize = 4096


def get_depend_table(need_merge_library, dependency_parent, cold_library):
    elf_file_keywords = []
    for item in need_merge_library:
        elf_file_keywords.append(item)
        if item in dependency_parent:
            elf_file_keywords.extend(dependency_parent[item])
        else:
            print(f"{item}: can't find parent Elf object")
    elf_file_keywords = list(set(elf_file_keywords))

    tmp_array = []
    for item in elf_file_keywords:
        if item not in cold_library:
            tmp_array.append(item)

    elf_file_keywords = tmp_array

    print(f"elf_file_keywords\n{elf_file_keywords}")
    return elf_file_keywords


def get_hot_functions_for_library(library, args,hotlib_instructions):
    order_path = os.path.join(args.hf_order, os.path.basename(library)+".order")
    cfg_path_file = os.path.join(args.hf_order, os.path.basename(library)+".cfg")
    
    if not os.path.exists(order_path):
        logging.info(f"{order_path} doesn't exists")
        return {}
    
    if not os.path.exists(cfg_path_file):
        logging.info(f"{cfg_path_file} doesn't exists")
        return {}

    functions_order = []
    
    with open(order_path, "r") as file:
        for line in file:
            substring = line.split("\n")[0]
            if substring in functions_order:
                logging.error(f"duplicate hot functions: {substring}")
            functions_order.append(substring)
    print(f"len of functions order {len(functions_order)}")
    
    function_cfg_info = parse_cfg_information(
        cfg_path_file, library, functions_order,hotlib_instructions
    )
    
    local_rela_internal = []
    function_text_info = {}
    for item in function_cfg_info:
        maxsize = item["MaxSize"]
        name = item["Function_name"]
        offset = item["Offset"]
        function_text_info[(name, offset)] = {
            "ori_value": offset,
            "maxsize": maxsize,
        }
        if item["rela_internal"] != []:
            local_rela_internal.extend(item["rela_internal"])

    logging.info(f"{library} local rela num {len(local_rela_internal)}")

    # 判断所有热点代码的text信息是否收集完毕
    tmp_function_order = []
    function_keys = function_text_info.keys()
    all_names = []
    for item in function_keys:
        all_names.append(item[0])
    for fun in functions_order:
        if fun not in all_names:
            logging.info(f"can't find {fun} in function_text_info")
        else:
            tmp_function_order.append(fun)
    functions_order = tmp_function_order

    return {
        "order": functions_order,
        "text_info": function_text_info,
        "cfg_info": function_cfg_info,
        "local_rel": local_rela_internal,
    }
    
