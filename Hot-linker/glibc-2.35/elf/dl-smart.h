#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

#include "dl-smart-args.h"

struct HT_header {
    u_int32_t phoff;
    u_int32_t phentsize;
    u_int32_t phnum;
    u_int32_t shoff;
    u_int32_t shentsize;
    u_int32_t shnum;
};

struct HT_ProgramHeader {
    u_int32_t type;
    u_int32_t offset;
    u_int32_t memsize;
    u_int32_t flgs;
};

struct HT_SectionHeader {
    u_int32_t type;
    u_int32_t offset;
    u_int32_t size;
    u_int32_t entsize;
};

struct HT_RelaInter {
    u_int32_t offset;
    u_int32_t ori_target;
    uint16_t r_type;
    uint16_t r_l_index;
    u_int32_t target_addr;
    int32_t r_addend;
};

struct HT_RelaExter {
    uint32_t r_offset;
    uint32_t st_value;
    u_int32_t ori_value;
    int32_t r_addend;
    u_int32_t r_type;
    uint16_t r_l_index;
    uint16_t sour_l_index;
};

struct HT_Textinfo {
    u_int32_t sh_addr;
    u_int32_t sh_hot_aaddr;
    u_int32_t sh_size;
    u_int32_t l_index;
};

#define HT_CTL_SEGMENT 0
#define HT_EXE_SEGMENT 1
#define HT_HUGEPAGESIZE 2 * 1024 * 1024

inline void get_dso_infos(size_t dso_num, unsigned char **dso_info) {
    struct link_map *cur = NULL;
    int offset = 0;
    for (Lmid_t ns = 0; ns < GL(dl_nns); ++ns) {
        for (cur = GL(dl_ns)[ns]._ns_loaded; cur != NULL; cur = cur->l_next) {
            dso_info[offset] = (unsigned char *)cur->l_name;
            offset++;
            dso_info[offset] = (unsigned char *)cur->l_addr;
            offset++;
            dso_info[offset] = (unsigned char *)cur->l_map_end;
            offset++;
        }
    }
    dso_info[0] = (unsigned char *)_dl_argv[0];

    for (int i = 0; i < dso_num; i++) {
        _dl_debug_printf("dso_info: %s %lx %lx\n", dso_info[i * 3],
                         (size_t)dso_info[i * 3 + 1],
                         (size_t)dso_info[i * 3 + 2]);
    }
}

void hot_process_exter_relacation(struct HT_RelaExter *rela_exter,
                                  u_int32_t rela_exter_num,
                                  uint64_t *depend_table,
                                  void *hot_text_start) {
    _dl_debug_printf("process exter relacation start!\n");
    struct HT_RelaExter *cur_Relaexter = rela_exter;
    for (int i = 0; i < rela_exter_num; i++) {
        size_t sour_l_index = cur_Relaexter->sour_l_index;
        u_int64_t sour_lib_baseaddr = depend_table[sour_l_index * 3 + 1];
        //   uint64_t sour_lib_endaddr = depend_table[sour_l_index * 3 + 2];
        u_int64_t r_lib_baseaddr =
            depend_table[(cur_Relaexter->r_l_index) * 3 + 1];
        if (__glibc_unlikely(r_lib_baseaddr == 0)) {
            _dl_debug_printf("exter relocation r_lib_base_addr=0 dso: %d\n",
                             cur_Relaexter->r_l_index);
            cur_Relaexter++;
            continue;
        }
        u_int64_t *r_offset =
            (uint64_t *)((u_int64_t)cur_Relaexter->r_offset + r_lib_baseaddr);
        u_int32_t r_type = cur_Relaexter->r_type;
        if (dl_print_debug)
            _dl_debug_printf("exter relocation: r_type: %d, r_offset: %lx\n",
                             r_type, (u_int64_t)r_offset);
        switch (r_type) {
            case R_X86_64_64:
            case R_X86_64_RELATIVE:
            case R_X86_64_GLOB_DAT:
            case R_X86_64_JUMP_SLOT:
                u_int64_t got_value = *r_offset;
                uint64_t ori_value =
                    sour_lib_baseaddr + (u_int64_t)cur_Relaexter->ori_value;

                if (__glibc_unlikely(ori_value != got_value)) {
                    if ((r_type == R_X86_64_64) ||
                        ((r_type == R_X86_64_RELATIVE))) {
                        if (dl_print_debug)
                            _dl_debug_printf(
                                "exter parse may error type: %d, R_OFFSET: %lx "
                                "got_value: %lx, s_value: %lx ori_target: "
                                "%lx\n",
                                r_type, (u_int64_t)cur_Relaexter->r_offset,
                                got_value, (uint64_t)(cur_Relaexter->st_value),
                                ori_value);
                        break;
                    }
                }

                uint64_t target_addr = (uint64_t)(cur_Relaexter->st_value) +
                                       (u_int64_t)hot_text_start;

                *r_offset = target_addr;
                if (dl_print_debug)
                    _dl_debug_printf(
                        "got_value: %lx, s_value: %lx target_addr: %lx\n",
                        got_value, (uint64_t)(cur_Relaexter->st_value),
                        target_addr);
                break;
            case R_X86_64_IRELATIVE:
                got_value = *r_offset;
                u_int64_t got_value_static = got_value - r_lib_baseaddr;
                u_int64_t text_start = cur_Relaexter->ori_value;
                u_int64_t text_size = cur_Relaexter->r_addend;

                if (got_value_static >= text_start)
                    if (got_value_static < (text_start + text_size)) {
                        uint64_t target_addr = got_value_static - text_start +
                                               cur_Relaexter->st_value +
                                               (u_int64_t)hot_text_start;
                        *r_offset = target_addr;
                        if (dl_print_debug)
                            _dl_debug_printf(
                                "R_X86_64_IRELATIVE got_value: %lx, s_value: "
                                "%lx target_addr: %lx hot_text: %lx\n",
                                got_value, (uint64_t)(cur_Relaexter->st_value),
                                target_addr, (uint64_t)hot_text_start);
                    }
                break;
            default:
                _dl_debug_printf("[ERROR] unprocess exter relocation \n");
                break;
        }

        cur_Relaexter++;
    }
    _dl_debug_printf("process exter relacation finish!\n");
}

/*
relocation_types={
    "R_X86_64_PC32":2,  # 目标地址会访问可写的数据段
    "R_X86_64_PLT32":4, # 目标地址会访问plt section
    "R_X86_64_GOTPCREL":9, # 目标地址会访问 got表
    "R_X86_64_REX_GOTPCRELX":42,  # 目标地址会访问 got表
    "R_X86_64_GOTTPOFF":22,
}
*/
#define R_X86_64_LOCALCALL 777
#define R_X86_64_LOCALCALL_IN_TMP 779
#define R_X86_64_PLT32_GOT 780

void hot_process_inter_relacation(struct HT_RelaInter *rela_inter,
                                  u_int32_t rela_inter_num,
                                  uint64_t *depend_table,
                                  void *hot_text_start) {
    struct HT_RelaInter *cur_Relainter = rela_inter;
    if (dl_rewrite_indictCall) {
        _dl_debug_printf("dl_rewrite_indictCall: %d \n",
                         (u_int32_t)dl_rewrite_indictCall);
    }
    for (int i = 0; i < rela_inter_num; i++) {
        Elf64_Addr rela_offset =
            cur_Relainter->offset + (Elf64_Addr)hot_text_start;
        uint32_t l_index = cur_Relainter->r_l_index;
        Elf64_Addr l_baseaddr = depend_table[l_index * 3 + 1];
        if (dl_print_debug)
            _dl_debug_printf(
                "cur_rela_inter: type: %d offset %lx target_addr %lx \n",
                cur_Relainter->r_type, (u_int64_t)cur_Relainter->offset,
                (u_int64_t)cur_Relainter->target_addr);
        switch (cur_Relainter->r_type) {
            case R_X86_64_PC32:
            case R_X86_64_GOTPCREL:
            case R_X86_64_REX_GOTPCRELX:
            case R_X86_64_TLSGD:
            case R_X86_64_TLSLD:
            case R_X86_64_GOTTPOFF:
            case R_X86_64_PLT32:
            case R_X86_64_LOCALCALL: {
                Elf64_Addr target_addr =
                    cur_Relainter->target_addr + l_baseaddr;
                int64_t offset = (int64_t)target_addr - (int64_t)rela_offset +
                                 (int64_t)cur_Relainter->r_addend;
                if ((__glibc_unlikely(offset <= INT32_MIN)) |
                    (__glibc_unlikely(offset >= INT32_MAX))) {
                    _dl_debug_printf(
                        "[ERROR] The distance between got value and rela "
                        "offset is too big %lx %lx\n",
                        rela_offset, offset);
                }

                *((int32_t *)rela_offset) = (int32_t)offset;
                if (dl_print_debug)
                    _dl_debug_printf(
                        "type:%d, rela_offset: %lx, target_offset:%lx, offset: "
                        "%ld\n",
                        cur_Relainter->r_type, rela_offset, target_addr,
                        offset);
                break;
            }
            case R_X86_64_LOCALCALL_IN_TMP: {
                Elf64_Addr target_addr =
                    cur_Relainter->target_addr + (Elf64_Addr)hot_text_start;
                int64_t offset = ((int64_t)target_addr - (int64_t)rela_offset) +
                                 cur_Relainter->r_addend;

                if ((__glibc_unlikely(offset <= INT32_MIN)) |
                    (__glibc_unlikely(offset >= INT32_MAX))) {
                    _dl_debug_printf(
                        "[ERROR] The distance between got value and rela "
                        "offset is too big %lx %lx\n",
                        rela_offset, offset);
                }

                *((int32_t *)rela_offset) = (int32_t)offset;
                if (dl_print_debug)
                    _dl_debug_printf(
                        "type:%d, rela_offset: %lx, target_offset:%lx, offset: "
                        "%ld\n",
                        cur_Relainter->r_type, rela_offset, target_addr,
                        offset);

                break;
            }
            case R_X86_64_PLT32_GOT:
                Elf64_Addr plt_addr = cur_Relainter->target_addr + l_baseaddr;
                Elf64_Addr target_addr = plt_addr;
                Elf64_Addr got_addr = plt_addr;

                if (dl_rewrite_indictCall) {
                    Elf64_Addr plt_got_offset = 0;
                    uint8_t *byte_address = (uint8_t *)plt_addr;

                    if (byte_address[0] == 0xff && byte_address[1] == 0x25)
                        plt_got_offset = plt_addr + 2;
                    else if (__glibc_likely((byte_address[0] == 0xf3 &&
                                             byte_address[1] == 0x0f)))
                        plt_got_offset = plt_addr + 4 + 3;
                    else
                        _dl_debug_printf(
                            "[ERROR] unprocess plt type, not gcc and llvm\n");

                    if (plt_got_offset != 0) {
                        int32_t *int_address = (int32_t *)plt_got_offset;
                        int32_t value = *int_address;
                        got_addr = plt_got_offset + 4 + value;
                        Elf64_Addr func_addr = *((Elf64_Addr *)got_addr);
                        target_addr = func_addr;
                    }
                }

                int64_t offset = (int64_t)target_addr - (int64_t)rela_offset +
                                 cur_Relainter->r_addend;

                if ((__glibc_unlikely(offset <= INT32_MIN)) |
                    (__glibc_unlikely(offset >= INT32_MAX))) {
                    offset = (int64_t)plt_addr - (int64_t)rela_offset +
                             (int64_t)cur_Relainter->r_addend;
                    *((int32_t *)rela_offset) = (int32_t)offset;
                    if (dl_print_debug)
                        _dl_debug_printf(
                            "The distance between got value and rela offset is "
                            "too big, target_function: %lx rela_offset: %lx "
                            "plt_offset: %lx\n",
                            target_addr, rela_offset, plt_addr);
                } else {
                    *((int32_t *)rela_offset) = (int32_t)offset;
                }
                if (dl_print_debug)
                    _dl_debug_printf(
                        "type:%d, rela_offset: %lx, got_addr:%lx, fun_addr:%lx "
                        "offset: %ld\n",
                        cur_Relainter->r_type, rela_offset, got_addr,
                        target_addr, offset);
                break;

            default:
                _dl_debug_printf(
                    "[ERROR] unprocess relocation inter item %lx, type: %d\n",
                    rela_offset, cur_Relainter->r_type);
                break;
        };
        cur_Relainter++;
    }
    _dl_debug_printf("process inter relacation finish!\n");
}

void hot_template_operation(void) {
    // 1、 判断可执行文件对应的hot_template是否存在
    char *abs_app_name = _dl_argv[0];

    /*
    char *exe_name = strrchr(abs_app_name, '/');
    if (exe_name == NULL)
      exe_name = abs_app_name;
    else
      exe_name++;*/

    _dl_debug_printf("hot template path: %s\n", _dl_hot_template_path);
    char *ht_total_path = _dl_hot_template_path;

    // 遍历所有dso对象，获取它们的名称和映射基地址
    size_t dso_num = 0;
    _dl_debug_printf("%s\n", "baseaddr");
    _dl_debug_printf("%s", abs_app_name);

    struct link_map *cur = NULL;
    for (Lmid_t ns = 0; ns < GL(dl_nns); ++ns) {
        for (cur = GL(dl_ns)[ns]._ns_loaded; cur != NULL; cur = cur->l_next) {
            dso_num++;
            /*
            const ElfW(Phdr) *dso_phdr = cur->l_phdr;
            ElfW(Half) l_phnum = cur->l_phnum;
            for (int i = 0; i < l_phnum; i++)
            {

              Elf64_Addr p_flags = dso_phdr->p_flags;
              Elf64_Word p_type = dso_phdr->p_type;
              if ((p_flags & PF_W) && (p_type == PT_LOAD))
              {
                Elf64_Addr p_vaddr = dso_phdr->p_vaddr + cur->l_addr;
                Elf64_Xword p_memsz = dso_phdr->p_memsz;
                Elf64_Addr start_page = p_vaddr & ~(GLRO(dl_pagesize) - 1);
                Elf64_Addr end_page = ((p_vaddr + p_memsz) & ~(GLRO(dl_pagesize)
            - 1)) + GLRO(dl_pagesize);


              int res = mprotect((void *)(start_page), end_page - start_page,
            PROT_READ | PROT_WRITE); if (res != 0)
              {
                _dl_debug_printf("%s: %lx\n", "change r/w segment fail",
            p_vaddr); return;
              }
              //_dl_debug_printf("change r/w segment sucess %lx\n", p_vaddr);
            }
            dso_phdr++;*/
            if (cur->l_relro_addr != 0) {
                Elf64_Addr start_page = (cur->l_relro_addr + cur->l_addr) &
                                        ~(GLRO(dl_pagesize) - 1);
                Elf64_Addr end_page = ((start_page + cur->l_relro_size) &
                                       ~(GLRO(dl_pagesize) - 1)) +
                                      GLRO(dl_pagesize);
                int res = mprotect((void *)(start_page), end_page - start_page,
                                   PROT_READ | PROT_WRITE);
                if (res != 0) {
                    _dl_debug_printf("%s: %lx\n", "change r/w segment fail",
                                     start_page);
                    return;
                }
            }
        }
    }

    _dl_debug_printf("%s\n", "baseaddr end");

    int fd;

    fd = open(ht_total_path, O_RDONLY);
    if (fd == -1) {
        _dl_debug_printf("open %s fail\n", ht_total_path);
        return;
    }

    struct stat ht_file_st;
    // 获取文件状态
    if (fstat(fd, &ht_file_st) == -1) {
        _dl_debug_printf("fstat");
        close(fd);
        return;
    }

    // 2、获取已加载的二进制对象的信息
    unsigned char **dso_info =
        (unsigned char **)malloc(sizeof(char *) * dso_num * 3);
    if (dso_info == NULL) {
        _dl_debug_printf("%s\n", "malloc dso_info failed");
        return;
    }

    get_dso_infos(dso_num, dso_info);
    // 3、解析hot_template
    // 3.1 解析hot_template 的header和program header

    void *ctl_addr = mmap(NULL, ht_file_st.st_size, PROT_READ,
                          MAP_PRIVATE | MAP_POPULATE, fd, 0);
    if (ctl_addr == MAP_FAILED) {
        _dl_debug_printf("ctl mmap failed\n");
        return;
    }

    struct HT_header *ht_hdr = (struct HT_header *)ctl_addr;
    _dl_debug_printf("phoff: %d phentsize: %d phnum: %d\n", ht_hdr->phoff,
                     ht_hdr->phentsize, ht_hdr->phnum);
    _dl_debug_printf("shoff: %d shentsize: %d shnum: %d\n", ht_hdr->shoff,
                     ht_hdr->shentsize, ht_hdr->shnum);

    struct HT_ProgramHeader *ht_phdr =
        (struct HT_ProgramHeader *)((char *)ctl_addr + ht_hdr->phoff);
    struct HT_ProgramHeader *cur_phdr = ht_phdr;
    for (int i = 0; i < (ht_hdr->phnum); i++) {
        _dl_debug_printf("type: %d offset: %lx memsize: %d flgs: %d\n",
                         cur_phdr->type, (size_t)(cur_phdr->offset),
                         cur_phdr->memsize, cur_phdr->flgs);
        cur_phdr++;
    }

    // 3.2 读取控制信息段
    cur_phdr = ht_phdr;
    for (int i = 0; i < (ht_hdr->phnum); i++) {
        if (cur_phdr->type == HT_CTL_SEGMENT)
            break;
        else
            cur_phdr++;
    }

    _dl_debug_printf("hot template ctl segment %lx\n", (u_int64_t)cur_phdr);
    // 3.2.1 获取section table，然后解析各段
    /*
    section_types={
      "depend_table":0,
      "relocation_intelnal_table":1,
      "relocation_external_table":2,
      "ro_string":3,
      "text_data":4,
    }
    */
    struct HT_SectionHeader *section_table =
        (struct HT_SectionHeader *)((char *)ctl_addr + ht_hdr->shoff);
    struct HT_SectionHeader *cur_section = section_table;
    uint64_t *depend_table = NULL;
    struct HT_RelaInter *rela_inter = NULL;
    struct HT_RelaExter *rela_exter = NULL;
    struct HT_Textinfo *text_info = NULL;
    u_int32_t rela_inter_num = 0, rela_exter_num = 0, depend_num = 0,
              text_info_ennum = 0;

    if (dso_info == NULL) {
        _dl_debug_printf("%s\n", "malloc dso_info failed");
        return;
    }
    for (int i = 0; i < ht_hdr->shnum; i++) {
        switch (cur_section->type) {
            case 0:
                uint64_t *depend_table_addr =
                    (uint64_t *)((char *)ctl_addr + cur_section->offset);
                depend_num = cur_section->size / cur_section->entsize;
                _dl_debug_printf("depend table : %lx %d\n",
                                 (size_t)(depend_table_addr), depend_num);

                depend_table =
                    (uint64_t *)malloc(depend_num * 3 * sizeof(uint64_t));
                if (depend_table == NULL) {
                    _dl_debug_printf("malloc depend_table fail\n");
                    return;
                }

                for (int j = 0; j < depend_num; j++) {
                    char *depend_name =
                        (char *)ctl_addr + *(depend_table_addr + j);
                    _dl_debug_printf("%d depend table : %s\n", j, depend_name);

                    for (int k = 0; k < dso_num; k++) {
                        if (strcmp(depend_name, (char *)dso_info[k * 3]) == 0) {
                            depend_table[j * 3] = (u_int64_t)(dso_info[k * 3]);
                            depend_table[j * 3 + 1] =
                                (u_int64_t)(dso_info[k * 3 + 1]);
                            depend_table[j * 3 + 2] =
                                (u_int64_t)(dso_info[k * 3 + 2]);
                            _dl_debug_printf("%s %lx %lx\n",
                                             (char *)(depend_table[j * 3]),
                                             depend_table[j * 3 + 1],
                                             depend_table[j * 3 + 2]);
                        }
                    }
                }
                cur_section++;
                break;

            case 1:
                rela_inter = (struct HT_RelaInter *)((char *)ctl_addr +
                                                     cur_section->offset);
                rela_inter_num = cur_section->size / cur_section->entsize;
                _dl_debug_printf("rela inter info: %lx, %d\n",
                                 (size_t)rela_inter, rela_inter_num);
                /* code */
                cur_section++;
                break;
            case 2:
                rela_exter = (struct HT_RelaExter *)((char *)ctl_addr +
                                                     cur_section->offset);
                rela_exter_num = cur_section->size / cur_section->entsize;
                _dl_debug_printf("rela exter info: %lx, %d\n",
                                 (size_t)rela_exter, rela_exter_num);
                cur_section++;
                break;
            case 4:
                text_info = (struct HT_Textinfo *)((char *)ctl_addr +
                                                   cur_section->offset);
                text_info_ennum = cur_section->size / cur_section->entsize;
                _dl_debug_printf("text info: %lx, %d\n", (size_t)text_info,
                                 text_info_ennum);

                for (int j = 0; j < text_info_ennum; j++) {
                    _dl_debug_printf(
                        "text_info_l_index:%d,p_vaddr:%lx,p_hot_vaddr:%lx,p_"
                        "memsz:%lx\n",
                        text_info[j].l_index, (size_t)text_info[j].sh_addr,
                        (size_t)text_info[j].sh_hot_aaddr,
                        (size_t)text_info[j].sh_size);
                }
                cur_section++;
            default:
                break;
        }
    }

    // 3.3 读取代码段

    cur_phdr = ht_phdr;
    for (int i = 0; i < (ht_hdr->phnum); i++) {
        if (cur_phdr->type == HT_EXE_SEGMENT) {
            _dl_debug_printf("HT_EXE_SEGMENT %lx,%d\n",
                             (size_t)cur_phdr->offset, cur_phdr->memsize);
            break;
        } else
            cur_phdr++;
    }

    int text_offset = cur_phdr->offset;
    int text_size = cur_phdr->memsize;
    void *hot_text_start = NULL;

    if(dl_small_page){
        hot_text_start =
        mmap(NULL, text_size, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_POPULATE | MAP_ANONYMOUS, -1, 0);
        if (hot_text_start == MAP_FAILED) {
        _dl_debug_printf("small hot text mmap failed\n");
        return;
    } else {
        _dl_debug_printf("small hot text mmap suss\n");
    }

    }else{
        hot_text_start =
        mmap(NULL, text_size, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_PRIVATE | MAP_POPULATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
        if (hot_text_start == MAP_FAILED) {
        _dl_debug_printf("huge hot text mmap failed\n");
        return;
    } else {
        _dl_debug_printf("huge hot text mmap suss\n");
    }

    }

    memcpy(hot_text_start, ctl_addr + text_offset, text_size);
    _dl_debug_printf("HOT TEXT: %lx text_offset:%d memsize:%d\n ",
                     (size_t)hot_text_start, text_offset, text_size);

    // 4 patch hot template
    // 4.1 处理外部的 jump_slot 重定位项
    hot_process_exter_relacation(rela_exter, rela_exter_num, depend_table,
                                 hot_text_start);
    // 4.2 处理内部的 jump_slot 重定位项
    hot_process_inter_relacation(rela_inter, rela_inter_num, depend_table,
                                 hot_text_start);

    munmap(ctl_addr, ht_file_st.st_size);
    close(fd);
    _dl_debug_printf("enter application\n ");

    /*
    if (text_size > 0)
    {
      int huge_page_size = ((int)((text_size - 1) / HT_HUGEPAGESIZE) + 1) *
    HT_HUGEPAGESIZE; int ht_res = mprotect((void *)(hot_text_start),
    huge_page_size, PROT_READ | PROT_EXEC); if (ht_res != 0)
      {
        _dl_debug_printf("%s: %lx\n", "mprotect huge text fail",
    (u_int64_t)hot_text_start); return;
      }
      else
      {
        _dl_debug_printf("%s: %lx\n", "mprotect huge text succss",
    (u_int64_t)huge_page_size);
      }
    }
    for (Lmid_t ns = 0; ns < GL(dl_nns); ++ns)
    {
      for (cur = GL(dl_ns)[ns]._ns_loaded; cur != NULL; cur = cur->l_next)
      {
        dso_num++;
        if (cur->l_relro_addr != 0)
        {
          Elf64_Addr start_page = (cur->l_relro_addr + cur->l_addr) &
    ~(GLRO(dl_pagesize) - 1); Elf64_Addr end_page = ((start_page +
    cur->l_relro_size) & ~(GLRO(dl_pagesize) - 1)) + GLRO(dl_pagesize); int res
    = mprotect((void *)(start_page), end_page - start_page, PROT_READ); if (res
    != 0)
          {
            _dl_debug_printf("%s: %lx\  n", "change relo-only to read-only
    segment fail", start_page); return;
          }
        }
      }
    }*/
    return;
}

static void __attribute_used__ smart_dynamic_loader_operations(void) {
    if (dl_print_libs) {
        char *abs_app_name = _dl_argv[0];

        /*
        char *exe_name = strrchr(abs_app_name, '/');
        if (exe_name == NULL)
          exe_name = abs_app_name;
        else
          exe_name++;*/

        // 遍历所有dso对象，获取它们的名称和映射基地址
        _dl_debug_printf("%s\n", "baseaddr");
        _dl_debug_printf("%s", abs_app_name);

        struct link_map *cur = NULL;
        for (Lmid_t ns = 0; ns < GL(dl_nns); ++ns) {
            for (cur = GL(dl_ns)[ns]._ns_loaded; cur != NULL;
                 cur = cur->l_next) {
                _dl_debug_printf("%s %lx %lx %lx\n", cur->l_name, cur->l_addr,
                                 cur->l_text_end, cur->l_map_end);
            }
        }

        _dl_debug_printf("%s\n", "baseaddr end");
    }
    if (_dl_hot_template_path != NULL) {
        hot_template_operation();
        //_dl_debug_printf("smart operation finish!\n");
    }
}