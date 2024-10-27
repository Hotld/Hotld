import sys
import os
import json
from parse_dependency import build_dependency_relation, print_dependency_tree
from template import *
from generate_hot_template import *
from parse_cfg import *
from external_relocations_collect import *
from internal_relocations_collect import *
from get_insturctions import *

from merge_library import *
import logging

# 配置日志输出格式和级别
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)

import argparse


def main(args):
    # 获取频繁使用的库和使用较少的库
    dso_infos = args.dso_infos
    merge_type = args.merge_type
    hot_template_savepath = args.ht_savepath

    with open(dso_infos, "r") as file:
        librarys_info = json.load(file)
    exe_file = librarys_info["exe_file"]
    need_merge_library = librarys_info["hot_library"]
    cold_library = librarys_info["cold_library"]
    special_symbols = librarys_info["special_symbols"]
    print(exe_file)
    print(f"hot_library:\n{need_merge_library}")
    for item in cold_library:
        print(item)

    # 解析可执行文件的依赖关系
    dependency_tree, dependency_parent = build_dependency_relation(exe_file)

    print_dependency_tree(dependency_tree)
    print_dependency_tree(dependency_parent)
    
    # 获取热点动态库的指令
    hotlib_instructions={}
    for item in need_merge_library:
        curlib_instructions,notracks=disassemble_instr(item)
        hotlib_instructions[item]={}
        hotlib_instructions[item]["instructions"]=curlib_instructions
        hotlib_instructions[item]["notracks"]=notracks

    # 获取每个动态库的热点函数
    print("get hot functions for pet library")
    hot_functions_info = {}
    for item in need_merge_library:
        if merge_type <= 2:
            hot_functions_info[item] = {}
        else:
            hot_functions_info[item] = get_hot_functions_for_library(item, args,hotlib_instructions)

    
    # 新建一个热点代码模版
    hot_template = TemplatePage()

    # 去除dependency_parent的cold library
    tmp_dict = {}
    for keywords, values in dependency_parent.items():
        if keywords not in cold_library:
            tmp_value = []
            for item in values:
                if item not in cold_library:
                    tmp_value.append(item)
            tmp_dict[keywords] = tmp_value
    dependency_parent = tmp_dict

    # 生成热点代码页面的dependies table,包括热点模版中所有涉及到的二进制文件
    # 设置depend_table的值
    print("set depend_table")
    elf_file_keywords = get_depend_table(
        need_merge_library, dependency_parent, cold_library
    )
    for index, item in enumerate(elf_file_keywords):
        hot_template.depend_table[item] = index

    hot_template.merge_mode = merge_type
    if merge_type == 3:
        hot_template.keep_funcorder = False
    # 合并热点函数
    print("merge hot functions texts")
    temp_text_header, temp_text_data = merge_library(
        merge_type=merge_type,
        hot_template=hot_template,
        need_merge_library=need_merge_library,
        hot_functions_info=hot_functions_info,
    )
    hot_template.template_data = temp_text_data
    hot_template.data_infos = temp_text_header

    hot_template.print_data_infos()

    
    
    # 获取relocation_external信息
    print("get relocation_external")
    collect_total_external_relocations(
        hot_template=hot_template,
        need_merge_library=need_merge_library,
        dependency_parent=dependency_parent,
        hot_function_info=hot_functions_info,
        special_names=special_symbols,
    )

    # 获取relocation intelnal信息
    print("get relocation intelnal")
    collect_total_internal_relocations(
        hot_template, need_merge_library, hot_functions_info,hotlib_instructions
    )

    # 如果是合并执行段，则去除目标地址在执行段的内部重定位项
    if merge_type == 1:
        remove_non_plt_related_rela(
            hot_template=hot_template,
            need_merge_library=need_merge_library,
        )

    print("generate hot template")
    print(hot_template.depend_table)
    hot_template.generate_section_and_segment_table()
    hot_template_pages = hot_template.write_pages()

    
    with open(hot_template_savepath, "wb") as binary_file:
        binary_file.write(hot_template_pages)

    print("relocation_external")
    for item in hot_template.relocationExternal:
        item.print_self()

    print("relocation intelnal")
    for item in hot_template.relocationInternal:
        item.print_self()
    
    
    


if __name__ == "__main__":
    # 创建ArgumentParser对象
    parser = argparse.ArgumentParser(description="Process some integers.")

    # 添加参数
    parser.add_argument(
        "--dso_infos", type=str, help="the dynamic library informations file path"
    )
    parser.add_argument(
        "--merge_type",
        type=int,
        help="the merge type: 1:exe segment 2:text section 3: hot function",
    )
    parser.add_argument("--ht_savepath", type=str, help="the hot template save path")
    parser.add_argument("--hf_cfgs", type=str, help="the hot function cfgs file path")
    parser.add_argument("--hf_order", type=str, help="the hot function order file path")

    # 解析参数
    args = parser.parse_args()

    main(args)
