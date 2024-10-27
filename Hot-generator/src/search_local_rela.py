import re
import logging
from elftools.elf.elffile import ELFFile
from rewrite_instruction_infos import *
from get_insturctions import *
from search_local_rela import *
import sys

logging.warning(f"check short jmp")

def get_empty_insturction_of_functions(instructions, fd, function_start, function_end):
    empty_prefix_list = []
    short_jump = []
    index = next(
        (i for i, row in enumerate(instructions) if row[0] == function_start), None
    )
    if index == None:
        logging.error(
            f"[get_empty_inst] can't find cfg function start instruction: {hex(function_start)}"
        )
        sys.exit()

    for i in range(index, len(instructions)):
        if instructions[i][0] >= function_end:
            break
        instr_start = instructions[i][0]
        fd.seek(instr_start)
        prefix_1 = fd.read(1)
        hex_prefix_1 = prefix_1.hex()

        if hex_prefix_1 == "eb":
            short_jump.append(instructions[i][0])
            continue
        if hex_prefix_1 != "66":
            continue

        fd.seek(instr_start)
        prefix_2 = fd.read(2)
        hex_prefix_2 = prefix_2.hex()
        if hex_prefix_2 in empty_instruction_prefix:
            continue

        fd.seek(instr_start)
        prefix_3 = fd.read(3)
        hex_prefix_3 = prefix_3.hex()

        if hex_prefix_3 in empty_instruction_prefix:
            continue

        fd.seek(instr_start)
        prefix_4 = fd.read(4)
        hex_prefix_4 = prefix_4.hex()
        if hex_prefix_4 in empty_instruction_prefix:
            continue
        
        if hex_prefix_4 =="666648e8":
            empty_prefix_list.append([instr_start, 3])
        elif hex_prefix_3 == "666648":
            empty_prefix_list.append([instr_start, 3])
        else:
            print(f"empty_instr_start: {hex(instr_start)} {hex_prefix_1}")
            empty_prefix_list.append([instr_start, 1])

    return empty_prefix_list, short_jump


def search_local_calls_in_function(
    basic_blocks,
    bb_layout,
    function_addr,
    function_end,
    rel_text_rel,
    library,
    instructions,
    notrack_infos,
):

    # 收集在当前函数的empty_prefix 前缀指令
    # logging.info(f"cur_functions: {name}")
    fd = open(library, "rb")

    empty_prefix_list, total_short_jmp = get_empty_insturction_of_functions(
        instructions, fd, function_addr, function_end
    )

    notrack_in_func = []
    for per_ins in notrack_infos:
        if function_addr <= per_ins < function_end:
            notrack_in_func.append(per_ins)

    # 使用正则表达式提取指令地址、操作码和操作元素
    pattern = re.compile(
        r"(?P<address>[0-9a-fA-F]+):\s+(?P<opcode>\w+)\s+(?P<operands>.*)"
    )

    func_name_pattern = r'"([^"]*)"'

    local_rela_entry = []

    short_jmp = []

    for bblock in basic_blocks:
        bbc_parts = bb_layout.split(", ")

        for instruction in bblock["instructions"]:
            match = pattern.match(instruction)
            if match == None:
                continue

            address = match.group("address")
            address = int(address, 16)
            opcode = match.group("opcode")
            operands = match.group("operands")

            """

            if hex(function_addr) == "0xfcbe0":
                cfg_ins = distance + function_addr + address
                if cfg_ins not in function_startss:
                    logging.warning(
                        f"nnnnnninstr {hex(cfg_ins)} {hex(function_addr)} {hex(address)} {distance}"
                    )
                    for value in function_startss:
                        if value > cfg_ins:
                            distance = value - cfg_ins
                            break
            """

            isskip = False
            for value in skip_opcodes:
                if value in opcode:
                    isskip = True
                    break
            if isskip:
                continue

            if operands in bbc_parts:
                continue

            if "@PLT" in operands:
                continue

            matches = re.findall(func_name_pattern, operands)

            if matches == None:
                logging.error(f"cfg match pattern2 error {instruction}")

            if ("/" not in operands):
                continue
            else:
                call_fun_name = operands.split("/")[0]

            if ".got" in operands:
                continue
            
            if "PG.LC" in operands:
                continue

            if opcode not in rewrite_instructions:
                logging.error(
                    f"unprocessed rewrite instruction {hex(function_addr)} {hex(function_addr+address)} {opcode}"
                )
                logging.error(f"instr: {instruction}")
                continue

            instr = function_addr + address
            r_offset = instr + rewrite_instructions[opcode]["r_offset"]
            r_addend = rewrite_instructions[opcode]["addend"]

            # 调整r_offset
            count = 0
            for per_ins in notrack_in_func:
                if r_offset + count > per_ins:
                    print(
                        f"The local inter rela maybe error becasue no_track {hex(r_offset)} func: {hex(function_addr)} addr: {hex(address)} notrack:{hex(per_ins)}"
                    )
                    count += 1
            if count != 0:
                print(
                    f"cfg r_offset change because notrack {hex(r_offset)} count: {count}"
                )
            r_offset += count

            count = 0
            
            for per_ins in empty_prefix_list:
                if len(per_ins) == 0:
                    break
                if r_offset + count > per_ins[0]:
                    print(
                        f"The local inter rela maybe error becasue empty_prefix r_offset: {hex(r_offset)} func_start: {hex(function_addr)} addr: {hex(address)} empty_prefix:{hex(per_ins[0])} {per_ins[1]}"
                    )

                    count += per_ins[1]
            if count != 0:
                print(
                    f"cfg r_offset change because empty_prefix before: {hex(r_offset)} after: {hex(r_offset+count)} "
                )
            r_offset += count
            
            fd.seek(r_offset - 1)
            bytes_read = fd.read(1)
            hex_representation = bytes_read.hex()
            if len(short_jmp) != 0:
                r_offset -= 3 * len(short_jmp)
                logging.warning(f"r_offset change because short jmp before: {hex(r_offset+3 * len(short_jmp))} {hex(r_offset)}")
            
            if hex_representation == "eb":
                logging.warning(f"find short jmp {hex(r_offset)}")
                short_jmp.append(r_offset)
            
                
            # 判断是否需要将r_offset加入到local_rel中
            if r_offset in rel_text_rel:
                # print(f"{hex(r_offset)} in rel_text_rel")
                continue
            if r_offset - r_addend > function_end:
                logging.error(
                    f"cfg r_offset too max instr: {hex(instr)} function_start: {hex(function_addr)} address: {hex(address)}"
                )
                continue
            if opcode == "movdqa":
                r_another_offset = r_offset - 1
                if r_another_offset in rel_text_rel:
                    print(
                        f"The movdqa r_another_offset in rela.text {hex(r_another_offset)}"
                    )
                    continue
                logging.warning(f"movdqa local rela {hex(r_offset)} may error")

            elif opcode == "callq":
                r_another_offset = r_offset + 1
                if r_another_offset in rel_text_rel:
                    print(
                        f"The callq r_another_offsetin rela.text {hex(r_another_offset)}"
                    )
                    continue
            elif opcode == "movl":
                r_another_offset = r_offset + 1
                if r_another_offset in rel_text_rel:
                    print(
                        f"The movl r_another_offsetin rela.text {hex(r_another_offset)}"
                    )
                    continue
            elif opcode == "movzbl":
                r_another_offset = r_offset + 1
                if r_another_offset in rel_text_rel:
                    print(
                        f"The movzbl r_another_offsetin rela.text {hex(r_another_offset)}"
                    )
                    continue
            elif opcode == "movq":
                r_another_offset = r_offset + 1
                if r_another_offset in rel_text_rel:
                    print(
                        f"The movl r_another_offsetin rela.text {hex(r_another_offset)}"
                    )
                    continue

            elif "leaq" in opcode:
                r_another_offset = function_addr + address + 1
                if r_another_offset in rel_text_rel:
                    logging.info(
                        f"The leaq r_another_offsetin in rela.text {hex(r_another_offset)}"
                    )
                    continue


            cur_rela = judge_local_rela(fd,r_offset,r_addend,instruction,opcode,function_addr)
            if cur_rela !=None:
                local_rela_entry.append(cur_rela)
            
    print(f"{library} local rela num per {len(local_rela_entry)}")
    fd.close()
    return local_rela_entry

def judge_local_rela(fd, r_offset, r_addend,instruction,opcode,function_addr):
    fd.seek(r_offset)
    value = fd.read(4)
    offset_value = int.from_bytes(value, byteorder="little", signed=True)
    target_address = r_offset - r_addend + offset_value

    if "jmp" in opcode:
        fd.seek(r_offset - 1)
        bytes_read = fd.read(1)
        hex_representation=bytes_read.hex()
        if hex_representation =="eb":
            logging.error(
                    f"short jmp does't process offset:0xeb {hex(r_offset)} function_addr: {hex(function_addr)}"
                )
            logging.error(instruction)
            return None
        if hex_representation != "e9":
            logging.error(
                    f"unprocess local internal relacation: r_offset {hex(r_offset)} opcode: {hex_representation} function_addr: {hex(function_addr)}"
                )
            logging.error(instruction)
            return None
    elif "call" in opcode:
        fd.seek(r_offset - 1)
        bytes_read = fd.read(1)
        hex_representation=bytes_read.hex()
        
        if hex_representation != "e8":
            logging.error(
                    f"unprocess local internal relacation: r_offset {hex(r_offset)} opcode: {hex_representation} function_addr: {hex(function_addr)}"
                )
            logging.error(instruction)
            return None 
    elif "leaq" in opcode:
        
        fd.seek(r_offset - 3)
        bytes_read = fd.read(3)
        hex_representation = bytes_read.hex()
       
        if hex_representation not in leaq_instruction_prefix:
            logging.error(
                    f"unprocess local internal relacation: r_offset {hex(r_offset)} opcode: {hex_representation} function_addr: {hex(function_addr)}"
                )
            logging.error(instruction)
            return None
    else:
        
        logging.error(
                    f"unprocess local internal relacation: r_offset {hex(r_offset)} opcode: {opcode} function_addr: {hex(function_addr)}"
                )
        logging.error(instruction)
        

    cur_rela = {
                "r_offset": r_offset,
                "r_addend": r_addend,
                "target":target_address
                
            }

    print(
            f"cur_rela: function_start:{hex(function_addr)} offset: {hex(r_offset)} target_fun: {hex(target_address)}"

            )
     
    return cur_rela