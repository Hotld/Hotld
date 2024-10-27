from elftools.elf.elffile import ELFFile
from parse_rela_text import (
    get_plt_sections_ranges,
    targetaddr_in_pltsections,
)
import logging
import re

# 配置日志输出格式和级别
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


# 根据偏移获取所属的segment
def get_segment(address, elf_file):
    for segment in elf_file.iter_segments():
        seg_start = segment["p_vaddr"]
        seg_end = seg_start + segment["p_memsz"]

        if seg_start <= address < seg_end:
            return seg_start

    return 0


def get_text_section(library):
    with open(library, "rb") as file:
        elf_file = ELFFile(file)

        for section in elf_file.iter_sections():
            if section.name == ".text":
                # print(f"text section {library}")
                # print_hex_bytes(section.data())
                return section.header, section.data()

    return None, None


def generate_hot_function_text(hot_functions_info, library, text_header):
    cur_addr = 0
    text_data = bytearray()
    function_order = hot_functions_info[library]["order"]
    function_info = hot_functions_info[library]["text_info"]
    function_new_info = {}
    with open(library, "rb") as file:
        for func in function_order:
            fun_infos = []
            for key, value in function_info.items():
                if func in key:
                    fun_infos.append(value)

            if len(fun_infos) == 0:
                logging.error(f"can't find {func} when merge libs")
            elif len(fun_infos) > 1:
                logging.error(f"{func} number {len(fun_infos)} larger 1 when merge libs")

            for cur_fun in fun_infos:
                offset = int(cur_fun["ori_value"], 16)
                maxsize = int(cur_fun["maxsize"], 16)

                # 将当前函数添加到热点代码页中
                file.seek(offset)
                data = file.read(maxsize)
                text_data.extend(data)

                # 更新相关信息
                new_offset = cur_addr
                cur_addr += maxsize

                # 函数保持2字节对齐
                if cur_addr % 2 != 0:
                    paddind = 2 - cur_addr % 2
                    cur_addr += paddind
                    text_data.extend([0] * paddind)
                    print(f"merge function align {hex(new_offset)}")
                
                func_name = func
                index = func.find('/')
                if index != -1:
                    func_name = func[:index]   
                    print(f"Warning: The {func} contains a '/', removing everything after it {func_name}.")
                
                function_new_info[(func_name, offset)] = {
                    "maxsize": maxsize,
                    "st_value": new_offset,
                    "ori_value": offset,
                    "func_end": new_offset + maxsize,
                }
                print(
                    f"mergelib {func_name} ori_value: {hex(offset)} st_value: {hex(new_offset)} maxsize: {maxsize}"
                )

    hot_functions_info[library]["text_info"] = function_new_info
    text_header["ori_sh_addr"] = text_header["sh_addr"]
    text_header["ori_memsize"] = text_header["sh_size"]
    text_header["sh_addr"] = 0
    text_header["sh_offset"] = 0
    text_header["sh_size"] = len(text_data)

    return text_header, text_data


def merge_hot_function_text(hot_template, need_merge_library, hot_functions_info):
    print("-----Merge hot function texts-----")

    text_infos = {}
    for item in need_merge_library:
        text_infos[item] = []
        text_header, text_data = get_text_section(item)
        if text_header == None:
            logging.error(f"can't find text section in {item}")

        if hot_functions_info[item] != {}:
            print(f"reorder functions for {item}")
            text_header, text_data = generate_hot_function_text(
                hot_functions_info=hot_functions_info,
                library=item,
                text_header=text_header,
            )

        text_infos[item].append({"header": text_header, "data": text_data})

    for keyword, values in text_infos.items():
        print(keyword)
        for item in values:
            print(item["header"])

    cur_addr = 0
    hdr_dict = {}
    template_data = bytearray()
    for item in need_merge_library:
        cur_text_info = {}

        cur_text_info = text_infos[item][0]
        hdr_dict[item] = []
        # 添加header信息
        shdr = cur_text_info["header"]
        shdr["sh_hot_offset"] = cur_addr
        shdr["sh_hot_addr"] = cur_addr
        shdr["l_index"] = hot_template.depend_table[item]
        if "libc.so" in item:
            shalignsize = shdr["sh_addralign"]
        else:
            shalignsize = 4096
        # print(f"{item} hot text section")
        # print_hex_bytes(template_data[cur_addr : shdr["sh_size"]])
        cur_addr = (
            shdr["sh_hot_offset"]
            + shdr["sh_size"]
            - (shdr["sh_size"] % shalignsize)
            + shalignsize
        )
        hdr_dict[item].append(shdr)

        # 将当前text section的数据添加到模版中
        section_data = cur_text_info["data"]
        template_data.extend(section_data)

        ## 与16字节对齐
        zero_size = cur_addr - len(template_data)
        template_data.extend([0] * zero_size)
        print(f"cur addr:{cur_addr},template_data size:{len(template_data)}")
    return hdr_dict, template_data


def get_executable_segments(filename):
    segments = []
    with open(filename, "rb") as f:
        elffile = ELFFile(f)

        # 遍历 ELF 文件中的所有段
        for segment in elffile.iter_segments():
            # 如果段类型是 PT_LOAD 且标志指定了可执行权限，则打印段的内容
            if segment.header.p_type == "PT_LOAD" and segment.header.p_flags & 1:
                data = segment.data()
                # print(f"Executable Segment: Virtual Address {hex(segment.header.p_vaddr)}, Size {segment.header.p_memsz}")
                # print(data.hex())
                print(segment.header)
                segments.append({"header": segment.header, "data": data})
        if len(segments) > 1:
            logging.error(f"{filename} has {len(segments)} executable segments")
    return segments


def merge_execute_segments(hot_template, need_merge_library):
    print("-----merge executable segments-----")
    exe_segment_dict = {}
    for item in need_merge_library:
        exe_segment_dict[item] = []
        exe_segment_dict[item] = get_executable_segments(item)

    align_size = 16
    cur_addr = 0
    hdr_dict = {}
    template_data = bytearray()
    for item in need_merge_library:
        segments_info = exe_segment_dict[item]
        hdr_dict[item] = []
        for segment in segments_info:
            ## 添加header信息
            phdr = segment["header"]
            phdr["p_hot_offset"] = cur_addr
            phdr["p_hot_vaddr"] = cur_addr
            phdr["p_hot_paddr"] = cur_addr
            phdr["l_index"] = hot_template.depend_table[item]
            cur_addr = (
                phdr["p_hot_vaddr"]
                + phdr["p_memsz"]
                - (phdr["p_memsz"] % align_size)
                + align_size
            )
            hdr_dict[item].append(phdr)

            ## 将当前段的数据添加到模版中
            segment_data = segment["data"]
            template_data.extend(segment_data)

            ## 最后一页不足4096字节的补零
            zero_size = cur_addr - len(template_data)
            template_data.extend([0] * zero_size)
            print(f"cur addr:{cur_addr},template_data size:{len(template_data)}")
    return hdr_dict, template_data


def remove_non_plt_related_rela(hot_template, need_merge_library):
    relocation_inter_tmp = []
    for item in need_merge_library:
        ## 获取热点代码模版中对应动态库的plt段的起始地址和终止地址
        plt_sections = get_plt_sections_ranges(item)
        lib_index = hot_template.depend_table[item]
        print(item)
        print(plt_sections)
        with open(item, "rb") as f:
            elf_file = ELFFile(f)
            for rela_entry in hot_template.relocationInternal:
                if rela_entry.r_l_index == lib_index:
                    target_addr = rela_entry.target_address
                    if targetaddr_in_pltsections(plt_sections, target_addr):
                        relocation_inter_tmp.append(rela_entry)
                        # print(f"offset:{hex(rela_entry.offset)}, target_addr:{hex(target_addr)}")
                        continue
                    source_addr_segment = get_segment(rela_entry.offset, elf_file)
                    dest_addr_segment = get_segment(target_addr, elf_file)
                    if source_addr_segment != dest_addr_segment:
                        relocation_inter_tmp.append(rela_entry)
    hot_template.relocationInternal = relocation_inter_tmp


# merge_type=1: 合并执行段
# merge_type=2: 合并代码段
# merge_type=3: 存在热点代码需要合并
def merge_library(merge_type, hot_template, need_merge_library, hot_functions_info):
    if merge_type == 1:
        template_header, template_data = merge_execute_segments(
            hot_template=hot_template,
            need_merge_library=need_merge_library,
        )
        for key in template_header.keys():
            template_header[key][0]["vaddr"] = template_header[key][0]["p_vaddr"]
            template_header[key][0]["hot_vaddr"] = template_header[key][0][
                "p_hot_vaddr"
            ]
            template_header[key][0]["memsize"] = template_header[key][0]["p_memsz"]

        print(f"template_header:/n{template_header}")
    if merge_type > 1:
        template_header, template_data = merge_hot_function_text(
            hot_template=hot_template,
            need_merge_library=need_merge_library,
            hot_functions_info=hot_functions_info,
        )
        print(f"template_header:/n{template_header}")
        for key in template_header.keys():
            template_header[key][0]["vaddr"] = template_header[key][0]["sh_addr"]
            template_header[key][0]["hot_vaddr"] = template_header[key][0][
                "sh_hot_addr"
            ]
            template_header[key][0]["memsize"] = template_header[key][0]["sh_size"]
        print(f"template_header:/n{template_header}")
    return template_header, template_data
