import struct
import sys

pagesize = 4096
endian = sys.byteorder

print(f"endian: {endian}")
section_types = {
    "depend_table": 0,
    "relocation_intelnal_table": 1,
    "relocation_external_table": 2,
    "ro_string": 3,
    "text_info": 4,
    "text_data": 5,
}

segment_type = {"read_write": 0, "execute": 1}

segment_flgs = {"read_write": 0, "execute": 1}

Elf_Addr = 8  # x86-64位系统中，每个地址占8个字节


# Template Header
class Templatehdr:
    def __init__(self):
        self.phoff = 0
        self.phentsize = 4 * 4  # 每个属性占4个字节
        self.phnum = 0
        self.shoff = 0
        self.shentsize = 4 * 4  # 每个属性占4个字节
        self.shnum = 0

    def size_of(self):
        return 4 * 6

    def print_self(self):
        print(
            f"phoff: {hex(self.phoff)}, phentsize: {self.phentsize}, phnum: {self.phnum}"
        )
        print(
            f"shoff: {hex(self.shoff)}, shentsize: {self.shentsize}, shnum: {self.shnum}"
        )


class ProgramHeader:
    def __init__(self):
        self.type = 0
        self.offset = 0
        self.memsize = 0
        self.flgs = 0

    def print_self(self):
        print(
            f"type: {self.type},offset: {hex(self.offset)},memsize:{self.memsize},flgs:{self.flgs}"
        )


class SectionHeader:
    def __init__(self):
        self.type = 0
        self.offset = 0
        self.size = 0
        self.entsize = 0

    def set_values(self, type, offset, size, entsize):
        self.type = type
        self.offset = offset
        self.size = size
        self.entsize = entsize

    def print_self(self):
        print(
            f"type: {self.type},offset: {hex(self.offset)},size:{self.size},entsize:{self.entsize}"
        )


class RelocationInterinfo:
    def __init__(
        self,
        offset,
        ori_offset,
        ori_target,
        r_type,
        r_sym,
        r_addend,
        r_l_index,
        target_addr,
    ):
        self.offset = offset
        self.ori_offset = ori_offset
        self.ori_target = ori_target
        self.r_info_type = r_type  # 16bits
        # self.r_info_sym=r_sym
        self.r_l_index = r_l_index  # 16bits
        self.r_addend = r_addend  # 32bits
        self.target_address = target_addr  # 32bits

        # target_address r_offset-r_addend+*(r_offset)

    def print_self(self):
        print(
            f"internal relocation type:{self.r_info_type} offset:{hex(self.offset)} target_address:{hex(self.target_address)} addend: {self.r_addend} lib:{self.r_l_index}"
        )


class RelocationExterinfo:
    def __init__(
        self, r_offset, st_value, ori_value, r_l_index, sour_l_index, r_type, r_addend
    ):
        self.r_offset = r_offset
        self.r_type = r_type
        self.st_value = st_value
        self.ori_value = ori_value
        self.r_l_index = r_l_index
        self.sour_l_index = sour_l_index
        self.r_addend = r_addend

    def print_self(self):
        print(
            f"r_offset: {hex(self.r_offset)} r_type:{self.r_type} st_value: {hex(self.st_value)} r_ori_target: {hex(self.ori_value)} r_l_index: {self.r_l_index} sour_l_index:{self.sour_l_index} r_addend:{self.r_addend}"
        )


class Textinfo:
    def __init__(self, p_vaddr, p_hot_vaddr, p_memsz, l_index):
        self.p_vaddr = p_vaddr
        self.p_hot_vaddr = p_hot_vaddr
        self.p_memsz = p_memsz
        self.l_index = l_index

    def print_self(self):
        print(
            f"p_vaddr:{self.p_vaddr} hot vaddr:{self.p_hot_vaddr} p_memsz:{self.p_memsz} l_index:{self.l_index}"
        )


class TemplatePage:
    def __init__(self):
        self.hdr = Templatehdr()
        self.programhdr = []

        self.program_table = []
        self.section_table = []

        self.depend_table = {}
        self.relocationExternal = []
        self.relocationInternal = []

        self.template_data = bytearray()
        self.data_infos = {}

        self.depend_table_entsize = 8
        self.relocationInternalentsize = 4 * 5
        self.relocationExternalentsize = 4 * 6
        self.textInfoentsize = 4 * 4

        self.merge_mode = 1
        self.keep_funcorder = True

    def print_relocation_internal(self):
        for item in self.relocationInternal:
            print(
                f"offset:{hex(item.offset)},r_info_type:{item.r_info_type},target_address:{hex(item.target_address)}"
            )

    def remove_duplicates_in_exter_rela(self):
        # 去除重复项
        offset_keywords = []
        uni_result = []
        for item in self.relocationExternal:
            got_offset = item.r_offset
            l_index = item.r_l_index
            tmp_key = (got_offset, l_index)
            if tmp_key in offset_keywords:
                continue
            else:
                offset_keywords.append(tmp_key)
                uni_result.append(item)
        print(f"len of result:{len(self.relocationExternal)}")
        print(f"len of uni_result:{len(uni_result)}")

    def print_data_infos(self):
        print("-----data header infos-----")
        for keyword, values in self.data_infos.items():
            print(keyword)
            print(values)

    def generate_section_and_segment_table(self):
        cur_offset = 0
        section_table = []
        program_table = []

        # 为template header预留空间
        tmphdr_size = self.hdr.size_of()
        cur_offset += tmphdr_size

        # 生成可写的segment的header
        cur_segment_header = ProgramHeader()
        cur_segment_header.type = segment_type["read_write"]
        cur_segment_header.flgs = segment_flgs["read_write"]

        print(f"offset phdr: {cur_offset}")
        # 为program Header table 预留空间，hot_template中只包含2个程序段
        program_hdr_size = self.hdr.phentsize
        self.hdr.phnum = 2
        self.hdr.phoff = cur_offset
        cur_offset += program_hdr_size * 2
        cur_segment_header.offset = cur_offset

        print(f"offset depend: {hex(cur_offset)}")
        # 为depend table 预留空间,这个表中的每一项包含一个指向动态库名的指针
        dep_num = len(self.depend_table.keys())
        dep_entsize = self.depend_table_entsize
        cur_section_entry = SectionHeader()
        cur_section_entry.set_values(
            section_types["depend_table"],
            cur_offset,
            dep_entsize * dep_num,
            dep_entsize,
        )
        section_table.append(cur_section_entry)
        cur_offset += dep_entsize * dep_num

        print(f"offset inter: {hex(cur_offset)}")
        # 为relocation internal entry 预留空间
        rela_internal_entsize = self.relocationInternalentsize
        rela_internal_num = len(self.relocationInternal)
        cur_section_entry = SectionHeader()
        cur_section_entry.set_values(
            section_types["relocation_intelnal_table"],
            cur_offset,
            rela_internal_entsize * rela_internal_num,
            rela_internal_entsize,
        )
        section_table.append(cur_section_entry)
        cur_offset += rela_internal_entsize * rela_internal_num

        print(f"offset exter: {hex(cur_offset)}")
        # 为relocation external entry 预留空间
        rela_external_entsize = self.relocationExternalentsize
        rela_external_num = len(self.relocationExternal)
        cur_section_entry = SectionHeader()
        cur_section_entry.set_values(
            section_types["relocation_external_table"],
            cur_offset,
            rela_external_entsize * rela_external_num,
            rela_external_entsize,
        )
        section_table.append(cur_section_entry)
        cur_offset += rela_external_entsize * rela_external_num

        print(f"text_info offset: {hex(cur_offset)}")
        # 为text info预留空间
        text_infoensize = self.textInfoentsize
        text_info_num = 0
        for keywords, values in self.data_infos.items():
            text_info_num += len(values)

        cur_section_entry = SectionHeader()
        cur_section_entry.set_values(
            section_types["text_info"],
            cur_offset,
            text_infoensize * text_info_num,
            text_infoensize,
        )
        section_table.append(cur_section_entry)
        cur_offset += text_infoensize * text_info_num

        print(f"offset string: {hex(cur_offset)}")
        # 为只读字符串预留空间(相关动态库的名称)
        librarys_names = self.depend_table.keys()
        ro_string_size = 0
        for lib_name in librarys_names:
            ro_string_size += len(lib_name) + 1  # +1 表示字符串以‘\0’结尾
        cur_section_entry = SectionHeader()
        cur_section_entry.set_values(
            section_types["ro_string"], cur_offset, ro_string_size, 0
        )
        section_table.append(cur_section_entry)
        cur_offset += ro_string_size

        print(f"offset section : {hex(cur_offset)}")
        # 为section Header table 预留空间,+1表示text section
        section_table_size = self.hdr.shentsize * (len(section_table) + 1)
        self.hdr.shnum = len(section_table) + 1
        self.hdr.shoff = cur_offset
        cur_offset += section_table_size

        print(f"offset text : {hex(cur_offset)}")
        cur_segment_header.memsize = cur_offset - cur_segment_header.offset
        program_table.append(cur_segment_header)

        # 为text段预留空间
        text_size = len(self.template_data)
        cur_section_entry = SectionHeader()
        cur_section_entry.set_values(
            section_types["text_data"], cur_offset, text_size, 0
        )
        section_table.append(cur_section_entry)

        cur_segment_header = ProgramHeader()
        cur_segment_header.flgs = segment_flgs["execute"]
        cur_segment_header.memsize = text_size
        cur_segment_header.offset = cur_offset
        cur_segment_header.type = segment_type["execute"]
        program_table.append(cur_segment_header)

        self.program_table = program_table
        self.section_table = section_table

    def package_hdr_into_binaries(self):
        data = []
        data.append(self.hdr.phoff)
        data.append(self.hdr.phentsize)
        data.append(self.hdr.phnum)
        data.append(self.hdr.shoff)
        data.append(self.hdr.shentsize)
        data.append(self.hdr.shnum)
        fmt = "<" + "i" * len(data)
        return struct.pack(fmt, *data)

    def package_phdr_into_binaries(self):
        data = []
        for item in self.program_table:
            data.append(item.type)
            data.append(item.offset)
            data.append(item.memsize)
            data.append(item.flgs)
        fmt = "<" + "i" * len(data)
        return struct.pack(fmt, *data)

    def package_rela_inter_into_binaries(self):
        tmp_data = []
        for item in self.relocationInternal:
            tmp_data.extend(struct.pack("<i", item.offset))
            tmp_data.extend(struct.pack("<i", item.ori_target))
            tmp_data.extend(struct.pack("<h", item.r_info_type))
            tmp_data.extend(struct.pack("<h", item.r_l_index))
            tmp_data.extend(struct.pack("<i", item.target_address))
            tmp_data.extend(struct.pack("<i", item.r_addend))

        return tmp_data

    def package_rela_exter_into_binaries(self):
        tmp_data = []
        for item in self.relocationExternal:
            tmp_data.extend(struct.pack("<i", item.r_offset))
            tmp_data.extend(struct.pack("<i", item.st_value))
            tmp_data.extend(struct.pack("<i", item.ori_value))
            tmp_data.extend(struct.pack("<i", item.r_addend))
            tmp_data.extend(struct.pack("<i", item.r_type))
            tmp_data.extend(struct.pack("<h", item.r_l_index))
            tmp_data.extend(struct.pack("<h", item.sour_l_index))
        return tmp_data

    def package_read_only_strings_into_binaries(self):
        tmp_data = []
        string_table = [""] * len(self.depend_table.keys())
        string_offset = []
        cur_offset = 0

        for keyword, value in self.depend_table.items():
            string_table[value] = keyword

        for item in string_table:
            string_offset.append(cur_offset)
            item += "\0"
            byte_array = item.encode("utf-8")
            tmp_data.extend(byte_array)
            cur_offset += len(byte_array)
            print(
                f"{item} length:{len(item)} byte_array_length:{len(byte_array)} cur_offset:{cur_offset}"
            )

        return tmp_data, string_offset

    def package_shdr_into_binaries(self):
        data = []
        for item in self.section_table:
            data.append(item.type)
            data.append(item.offset)
            data.append(item.size)
            data.append(item.entsize)
        fmt = "<" + "i" * len(data)
        return struct.pack(fmt, *data)

    def package_textinfo_into_binaries(self):
        data = []
        for keywords, values in self.data_infos.items():
            for phdr in values:
                data.append(phdr["vaddr"])
                data.append(phdr["hot_vaddr"])
                data.append(phdr["memsize"])
                data.append(phdr["l_index"])

        fmt = "<" + "I" * len(data)
        return struct.pack(fmt, *data)

    def write_pages(self):
        page_datas = bytearray()

        # 写入模版头
        print("write hot template header")
        self.hdr.print_self()
        tmp_data = self.package_hdr_into_binaries()
        page_datas.extend(tmp_data)

        # 写入program header table
        print("write program header table")
        for item in self.program_table:
            item.print_self()
        tmp_data = self.package_phdr_into_binaries()
        page_datas.extend(tmp_data)

        # 写入depend table
        print("write depend table")
        number = len(self.depend_table.keys()) * self.depend_table_entsize
        page_datas.extend([0] * number)

        # 写入relocation internal table
        print("write relocation intenal table")
        tmp_data = self.package_rela_inter_into_binaries()
        page_datas.extend(tmp_data)

        # 写入relocation external table
        print("write relocation external table")
        tmp_data = self.package_rela_exter_into_binaries()
        page_datas.extend(tmp_data)

        # 写入text_info
        print("write text info")
        tmp_data = self.package_textinfo_into_binaries()
        page_datas.extend(tmp_data)

        # 写入只读字符串
        print(f"write read-only strings {hex(len(page_datas))}")
        tmp_data, strings_offset = self.package_read_only_strings_into_binaries()
        print(tmp_data)
        section_offset = 0
        section_entsize = 0
        for section in self.section_table:
            if section.type == section_types["depend_table"]:
                section_offset = section.offset
                section_entsize = section.entsize
                break
        if section_offset == 0:
            print("can't find reda-only strings section")

        for item in strings_offset:
            item_bytes = struct.pack("<Q", item + len(page_datas))
            page_datas[section_offset : section_offset + 8] = item_bytes
            section_offset += section_entsize

        page_datas.extend(tmp_data)

        # 写入section header table
        print("write section header table")
        tmp_data = self.package_shdr_into_binaries()
        page_datas.extend(tmp_data)

        # 写入text段
        page_datas.extend(self.template_data)

        # 读取program header table
        print("read program header table")
        for item in self.program_table:
            item.print_self()
        offset = self.hdr.phoff
        size = self.hdr.phnum * self.hdr.phentsize
        tmp_data = page_datas[offset : offset + size]
        hex_representation = " ".join(["{:02x}".format(b) for b in tmp_data])
        for i in range(0, len(hex_representation), 24):
            print(hex_representation[i : i + 24])

        # 读取depend table
        print("read depend table")
        for keyword, value in self.depend_table.items():
            print(keyword, value)

        # 根据depend table的指针读取对应的动态库的名字
        offset = 0
        size = 0
        entsize = 0
        for section in self.section_table:
            if section.type == section_types["depend_table"]:
                offset = section.offset
                size = section.size
                entsize = section.entsize
                break
        if offset == 0:
            print("can't find depend_table section")
        else:
            print(f"depend table: {hex(offset)}")
            section_end = offset + size
            while offset < section_end:
                uint_offset = struct.unpack_from("<Q", page_datas, offset)[0]
                decode_string = ""
                for byte in page_datas[uint_offset:]:
                    if byte == 0:
                        break
                    decode_string += chr(byte)
                print(f"uint_offset:{hex(uint_offset)}, {decode_string}")
                offset += entsize

        print(f"relocation internal number : {len(self.relocationInternal)}")
        print(f"relocation external number : {len(self.relocationExternal)}")

        # 读取section header table
        print("read section header table")
        for item in self.section_table:
            item.print_self()
        offset = self.hdr.shoff
        size = self.hdr.shnum * self.hdr.shentsize
        tmp_data = page_datas[offset : offset + size]
        hex_representation = " ".join(["{:02x}".format(b) for b in tmp_data])
        for i in range(0, len(hex_representation), 24):
            print(hex_representation[i : i + 24])

        self.print_text_data(page_datas)
        return page_datas

    def print_text_data(self, page_data):

        for keyword, values in self.data_infos.items():
            print("-----text section pages-----")
            """
            print(keyword)
            for item in self.section_table:
                if item.type == 5:
                    text_offset = item.offset

            cur_text_offset = text_offset + values[0]["sh_hot_offset"]
            size = values[0]["sh_size"]
            print(f"offset {cur_text_offset}, size:{size}")
            
            data = page_data[568170 : 568170 + 160]
            bytes_per_line = 16
            for i in range(0, len(data), bytes_per_line):
                line = data[i : i + bytes_per_line]
                hex_line = " ".join(f"{byte:02X}" for byte in line)
                print(hex_line)
            """
