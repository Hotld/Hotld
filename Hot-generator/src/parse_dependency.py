import elftools.elf.elffile as elffile
import os
from merge_library import *
import logging

LD_LIBRARY_PATH = [
    "",
    "/home/ning77/Desktop/stonedb/libs/",
    "/home/ning77/Desktop/DLCO/lib/",
]


def parse_dependencies(filepath):
    abs_filepath = ""
    for directory in LD_LIBRARY_PATH:
        abs_path = directory + filepath
        if os.path.exists(abs_path):
            abs_filepath = abs_path
            break
    if abs_filepath == "":
        logging.error(f"can't find lib {filepath}")
        return [], abs_filepath
    dependencies = []

    with open(abs_filepath, "rb") as f:
        elf = elffile.ELFFile(f)

        # Parse dynamic section to find shared libraries
        dynamic_section = elf.get_section_by_name(".dynamic")
        for tag in dynamic_section.iter_tags():
            if tag.entry.d_tag == "DT_NEEDED":
                dependencies.append(tag.needed)

    return dependencies, abs_filepath


def build_dependency_relation(filepath):
    dependency_tree = {}
    parsed_depends = []
    need_parse_depends = []
    need_parse_depends.append(filepath)
    while len(need_parse_depends) > 0:
        cur_depend = need_parse_depends[0]
        print(f"get denpendcy of {cur_depend}")
        dependencies, abs_filepath = parse_dependencies(cur_depend)
        if abs_filepath != "":
            parsed_depends.append(abs)
            dependency_tree[abs_filepath] = dependencies
            for item in dependencies:
                if (item not in need_parse_depends) & (item not in parsed_depends):
                    need_parse_depends.append(item)

        parsed_depends.append(cur_depend)
        need_parse_depends.remove(cur_depend)
    print("dependency tree")
    print(dependency_tree)

    dependency_parent = {}
    keyword_list = list(dependency_tree.keys())
    for keyword, value in dependency_tree.items():
        dependency_parent[keyword] = []
    for keyword, value in dependency_tree.items():
        for item in value:
            for item_abspath in keyword_list:
                if item in item_abspath:
                    dependency_parent[item_abspath].append(keyword)
    return dependency_tree, dependency_parent


def print_dependency_tree(tree, indent=0):
    print("print dependency tree")
    for key, value in tree.items():
        print(key)
        print(value)
