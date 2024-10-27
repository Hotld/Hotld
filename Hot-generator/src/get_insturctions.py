import subprocess
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import re
import bisect
import logging
from capstone import Cs, CS_ARCH_X86, CS_MODE_64,CsError
import sys
import distorm3

# 配置日志输出格式和级别
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)


def find_instruction(address, instructions):
    low, high = 0, len(instructions) - 1
    while low <= high:
        mid = (low + high) // 2
        instr_address = instructions[mid][0]
        instr_size = instructions[mid][1]
        if address < instr_address:
            high = mid - 1
        elif address >= instr_address + instr_size:
            low = mid + 1
        else:
            return instr_address, instr_size
    return 0, 0



def parse_objdump_output(file_path):
    result=subprocess.run(['objdump','-d',file_path],capture_output=True,text=True,check=True)
    output=result.stdout
    instructions=[]
    notrack_instructions = []
    lines = output.splitlines()

    # 正则表达式匹配指令行
    instruction_re = re.compile(r'^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s)+)\s*(.*)?$')
    for line in lines:
        match = instruction_re.match(line)
        if match:
            address = int(match.group(1), 16)
            opcode_bytes = match.group(2).strip().split()
            size = len(opcode_bytes)
            asm_instruction = match.group(3).strip() if match.group(3) else ''
            notrack = "notrack" in line
            if notrack == True:
                print(f"notrack instruction {hex(address)} {size}")
                notrack_instructions.append(address)
            
            current_instruction = [address,size,address+size]
            if asm_instruction!='':
                instructions.append(current_instruction)
            else:
                pre_instr_index=len(instructions)-1
                instructions[pre_instr_index][1]+=size
                instructions[pre_instr_index][2]+=size
         
    return instructions,notrack_instructions

def find_function(address, functions):
    start_addresses = [func[0] for func in functions]
    index = bisect.bisect_right(start_addresses, address) - 1
    if index >= 0 and functions[index][0] <= address < functions[index][1]:
        return functions[index]
    return None


def get_elf_instructions(file_path):
    instructions = []
    notrack_instructions = []
    # 打开 ELF 文件
    with open(file_path, "rb") as f:
        elffile = ELFFile(f)

        # 获取代码段
        code_section = None
        for section in elffile.iter_sections():
            if section.name == ".text":
                code_section = section
                break

        if not code_section:
            print("No .text section found in the ELF file.")
            return

        # 读取代码段数据
        code = code_section.data()
        code_addr = code_section["sh_addr"]
        size=len(code)
        
        print(f"size of {file_path} text: start {code_addr} {len(code)}")

        # 使用 capstone 反汇编
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md_instructions=[]
        try:
            md_instructions= md.disasm(code, code_addr)
        except CsError as e:
            logging.info(f"{file_path} instruction error ")
        
            
        for instr in md_instructions:
            instructions.append(
                [
                    instr.address,
                    instr.size,
                    instr.address + instr.size,
                ]
            )
            if "notrack" in instr.mnemonic:
                print(f"notrack instruction {hex(instr.address)} {instr.size}")
                notrack_instructions.append(instr.address)
            size-=instr.size
    if size!=0:
        logging.info(f"{file_path} left size {hex(size)}")
        instructions=[]
        notrack_instructions = []
        instructions,notrack_instructions=parse_objdump_output(file_path)
        
        
        
    print(f"number of notrack instructions: {len(notrack_instructions)}")
    return instructions, notrack_instructions


def disassemble_instr(binary_file_path):
    try:
        instructions, notrack_instructions = get_elf_instructions(binary_file_path)
        return instructions, notrack_instructions
    except Exception as e:
        print(f"Error: {e}")
        return [], {}


"""
file = "/home/ning/Desktop/DLCO/lib/libncnn.so.1.0.20240801"


instructions, notrack_infos = disassemble_instr(file)

for item in instructions:
    print(hex(item[0]), item[1], hex(item[2]))
"""
