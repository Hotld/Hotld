from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
import logging

# 配置日志输出格式和级别
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)

relocation_types = {
    "R_X86_64_NONE": 0,
    "R_X86_64_64": 1,
    "R_X86_64_PC32": 2,  # 目标地址会访问可写的数据段
    "R_X86_64_PLT32": 4,  # 目标地址会访问plt section
    "R_X86_64_GLOB_DAT": 6,
    "R_X86_64_JUMP_SLOT": 7,
    "R_X86_64_RELATIVE": 8,
    "R_X86_64_GOTPCREL": 9,  # 目标地址会访问 got表
    "R_X86_64_32": 10,
    "R_X86_64_DTPMOD64": 16,
    "R_X86_64_DTPOFF64": 17,
    "R_X86_64_TPOFF64": 18,
    "R_X86_64_TLSGD": 19,
    "R_X86_64_TLSLD": 20,
    "R_X86_64_DTPOFF32": 21,
    "R_X86_64_GOTTPOFF": 22,
    "R_X86_64_IRELATIVE": 37,
    "R_X86_64_REX_GOTPCRELX": 42,  # 目标地址会访问 got表
    "R_X86_64_LOCALCALL": 777,
    "R_X86_64_LOCALCALL_IN_TMP": 779,
    "R_X86_64_PLT32_GOT": 780,
}
