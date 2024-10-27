import re
import logging
from elftools.elf.elffile import ELFFile
from rewrite_instruction_infos import *
from get_insturctions import *
from search_local_rela import *
import bisect

# 配置日志输出格式和级别
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


def get_rela_text_entry(filename):
    print(f"paser {filename} rela_text")
    relocations_internal = []

    with open(filename, "rb") as f:
        elf_file = ELFFile(f)

        # 获取.rel.text节
        rel_text_section = elf_file.get_section_by_name(".rela.text")
        if not rel_text_section:
            logging.error(f"{filename} No .rela.text section found")
            return []

        # 解析重定位项
        for relocation in rel_text_section.iter_relocations():
            rel_internal = relocation["r_offset"]  # 重定位项的偏移量
            relocations_internal.append(rel_internal)

    return relocations_internal


def extract_cfg_information_from_file(file_path):
    cfg_information = []
    with open(file_path, "r") as file:
        cfg_text = ""
        for line in file:
            if line.startswith("Binary Function"):
                cfg_text = line
            elif line.startswith("End of Function"):
                cfg_text += line
                cfg_information.append(cfg_text)
            else:
                cfg_text += line

    return cfg_information


def parse_cfg_information(cfg_file, library, function_order,hotlib_instructions):
    logging.info(f"parse cfg file {cfg_file}")
    function_cfg_information = []
    # 提取cfg块
    cfg_texts = extract_cfg_information_from_file(cfg_file)

    # 获取rela.text项
    rela_text_rel = get_rela_text_entry(library)

    # 获取notrack信息
    lib_instructions = hotlib_instructions[library]["instructions"]
    notrack_infos = hotlib_instructions[library]["notracks"]

    """
    for item in lib_instructions:
        print(f"lib_ins: {hex(item[0])}, {item[1]}, {hex(item[2])}, {item[3]}")
    """

    
    rela_text_rel_instrstart = []
    """
    for r_offset in rela_text_rel:
        instr, size = find_instruction(r_offset, lib_instructions)
        if instr != 0:
            rela_text_rel_instrstart.append(instr)
        else:
            logging.error(f"can't find instructions of rela in cfg {hex(r_offset)}")
    """

    # 解析函数信息

    cfg_count=0
    for cfg_text in cfg_texts:
        cfg_count+=1
        function_info = parse_cfg_info(
            cfg_text,
            rela_text_rel,
            rela_text_rel_instrstart,
            lib_instructions,
            notrack_infos,
            library,
            function_order,
        )
        if function_info != {}:
            function_cfg_information.append(function_info)
    print(f"total cfg infos len :{cfg_count}")

    print(f"function_cfg_information")
    for item in function_cfg_information:
        for key, value in item.items():
            if key == "rela_internal":
                print(f"{key}: {value}")

    return function_cfg_information


def parse_cfg_info(
    cfg_info_text,
    rel_text_rel,
    rela_text_rel_instrstart,
    lib_instructions,
    notrack_infos,
    library,
    function_order,
):
    first_line = cfg_info_text.split("\n")[0]
    
    # 使用正则表达式提取双引号内的内容
    match = re.search(r'"(.*?)"', first_line)
    if match:
        name = match.group(1)
        # 移除括号及其内容
        name = re.sub(r'\(.*?\)', '', name).strip()
    else:
        return {}
    
    if name not in function_order:
        return {}
    
    
    cfg_info = {}
    cfg_info["Function_name"] = name
    address = extract_attribute(cfg_info_text, "Address")
    print(f"parse cfg of {name} {address}")
    
    # 使用正则表达式解析函数信息的各个属性
    cfg_info["Number"] = extract_attribute(cfg_info_text, "Number")
    cfg_info["State"] = extract_attribute(cfg_info_text, "State")
    cfg_info["Address"] = extract_attribute(cfg_info_text, "Address")
    cfg_info["Size"] = extract_attribute(cfg_info_text, "Size")
    cfg_info["MaxSize"] = extract_attribute(cfg_info_text, "MaxSize")
    cfg_info["Offset"] = extract_attribute(cfg_info_text, "Offset")
    cfg_info["Section"] = extract_attribute(cfg_info_text, "Section")
    cfg_info["Orc Section"] = extract_attribute(cfg_info_text, "Orc Section")
    cfg_info["LSDA"] = extract_attribute(cfg_info_text, "LSDA")
    cfg_info["IsSimple"] = extract_attribute(cfg_info_text, "IsSimple")
    cfg_info["IsMultiEntry"] = extract_attribute(cfg_info_text, "IsMultiEntry")
    cfg_info["IsSplit"] = extract_attribute(cfg_info_text, "IsSplit")
    cfg_info["BB Count"] = extract_attribute(cfg_info_text, "BB Count")
    cfg_info["Hash"] = extract_attribute(cfg_info_text, "Hash")
    cfg_info["CFI Instrs"] = extract_attribute(cfg_info_text, "CFI Instrs")
    cfg_info["BB Layout"] = extract_attribute(cfg_info_text, "BB Layout")
    cfg_info["Exec Count"] = extract_attribute(cfg_info_text, "Exec Count")
    cfg_info["Branch Count"] = extract_attribute(cfg_info_text, "Branch Count")
    cfg_info["Profile Acc"] = extract_attribute(cfg_info_text, "Profile Acc")

    # 解析每个基本块的信息

    # 提取每个基本块的信息
    basic_blocks = re.findall(
        r"\.(.*?)\s+\((\d+)\s+instructions,\s+align\s+:\s+\d+\)(.*?)CFI State: \d+",
        cfg_info_text,
        re.DOTALL,
    )
    
    if len(basic_blocks)==0:
        basic_blocks=re.findall(
        r"(\.\w+)\s+\((\d+)\s+instructions,\s+align\s+:\s+\d+\)([\s\S]*?)(?=\.\w+\s+\(|\Z)",
        cfg_info_text,
        re.DOTALL,
    )
    if str(len(basic_blocks)) != cfg_info["BB Count"]:
        logging.error(
            f"extract basic block fail,{cfg_info['Hash']}, {cfg_info['BB Count']}, len: {len(basic_blocks)}"
        )
        
        for item in basic_blocks:
            print("[parse cfg] basic basic")
            print(item)

    cfg_info["basic_blocks"] = []
    for item in basic_blocks:
        cur_block = parse_basic_block(item)
        cur_block["Instruction Count"] = item[1]
        cfg_info["basic_blocks"].append(cur_block)
    # cfg_info["Basic Blocks"] = [{"Name": bb[0], "Instruction Count": bb[1], "CFI State": bb[2]} for bb in basic_blocks]
    # print(cfg_info)

    # 使用正则表达式提取指令地址、操作码和操作元素
    pattern = re.compile(
        r"(?P<address>[0-9a-fA-F]+):\s+(?P<opcode>\w+)\s+(?P<operands>.*)"
    )

    # 查看基本块中是否包含本地函数跳转指令

    function_addr = int(cfg_info["Offset"][2:], 16)
    function_end = function_addr + int(cfg_info["MaxSize"][2:], 16)

    if cfg_info["Offset"] != hex(function_addr):
        logging.error(cfg_info["Offset"], hex(function_addr))

    cfg_info["rela_internal"] = search_local_calls_in_function(
        basic_blocks=cfg_info["basic_blocks"],
        bb_layout=cfg_info["BB Layout"],
        function_addr=function_addr,
        function_end=function_end,
        rel_text_rel=rel_text_rel,
        library=library,
        instructions=lib_instructions,
        notrack_infos=notrack_infos,
    )
    # logging.info(f"{cfg_info['Function_name']} bbc num: {bbc_num}")
    return cfg_info


def parse_basic_block(block_text):
    block_text_lines = [line.rstrip() for line in block_text[2].split("\n")]
    block_info = {
        "exec_count": 0,
        "cfi_state": 0,
        "input_offset": 0,
        "instructions": [],
        "ctl_switch": [],
        "successors": [],
    }
    for line in block_text_lines:
        # 解析Exec Count、CFI State和Input offset
        if line.startswith("Exec Count"):
            exec_count = int(line.split(":")[-1].strip())
            block_info["exec_count"] = exec_count
        elif line.startswith("CFI State"):
            cfi_state = int(line.split(":")[-1].strip())
            block_info["cfi_state"] = cfi_state
        elif line.startswith("Input offset"):
            input_offset = line.split(":")[-1].strip()
            block_info["input_offset"] = input_offset

        # 解析指令行
        elif line.strip().startswith("000"):
            instruction = line.strip()
            block_info["instructions"].append(instruction)

        # 解析后继基本块
        elif line.startswith("Successors"):
            successors = line.split(":")[1].strip().split(",")
            block_info["successors"] = [s.strip().split()[0] for s in successors]

    if int(block_text[1]) != len(block_info["instructions"]):
        logging.error(
            f"size of instructions in block text diff with block_info:{block_text[1]} {len(block_info['instructions'])}"
        )
        for item in block_text:
            logging.error(item)

    return block_info


def extract_attribute(cfg_info_text, attribute_name):
    # 从文本中提取属性值
    match = re.search(rf"{attribute_name}\s*:\s+(.*?)\n", cfg_info_text)
    return match.group(1) if match else None


# 示例文本
"""
cfg_file = (
    "/home/ning/Desktop/Ning/hot_function_combind/cfg_information/libzstd_main.so.cfg"
)
library = "/home/ning/Desktop/Ning/smart_gloader/lib/libzstd_main.so"
function_info = parse_cfg_information(cfg_file, library)
"""
