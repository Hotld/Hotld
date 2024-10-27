rewrite_instructions = {
    # 2881d:	8b 0d 15 d7 0c 00    	mov    0xcd715(%rip),%ecx
    "movl": {"r_offset": 2, "addend": -4},
    # e76ae:	66 0f 5c 0d 2a 17 01 00	subpd  0x1172a(%rip),%xmm1        # f8de0 <.LCPI15_3>
    "subpd": {"r_offset": 4, "addend": -4},
    # 187c3:	0f 28 05 16 d1 0d 00 	movaps 0xdd116(%rip),%xmm0        # f58e0 <.LCPI0_9>
    "movaps": {"r_offset": 3, "addend": -4},
    # 1b02c:	66 44 0f 6f 05 bb a8 0d 00	movdqa 0xda8bb(%rip),%xmm8        # f58f0 <.LCPI13_1>
    # 17629:	66 0f 6f 05 8f e2 0d 00	movdqa 0xde28f(%rip),%xmm0        # f58c0 <.LCPI0_7>
    "movdqa": {"r_offset": 5, "addend": -4},
    # 19b355f:	0f b6 05 6a 92 95 00 	movzbl 0x95926a(%rip),%eax        # 230c7d0 <_ZGVZN7rocksdb9SyncPoint11GetInstanceEvE10sync_point>
    "movzbl": {"r_offset": 3, "addend": -4},
    # 14a78:	66 0f d4 05 10 0d 0e 00	paddq  0xe0d10(%rip),%xmm0        # f5790 <.LCPI14_0>
    "paddq": {"r_offset": 4, "addend": -4},
    # 21f94:	66 0f ef 05 a4 38 0d 00	pxor   0xd38a4(%rip),%xmm0        # f5840 <.LCPI134_1>
    "pxor": {"r_offset": 4, "addend": -4},
    # e771c:	48 83 3d 94 d8 02 00 00	cmpq   $0x0,0x2d894(%rip)        # 114fb8 <g_artefact>
    "cmpq": {"r_offset": 3, "addend": -5},
    # e75c8:	66 0f 28 15 00 18 01 00	movapd 0x11800(%rip),%xmm2        # f8dd0 <.LCPI15_2>
    "movapd": {"r_offset": 4, "addend": -4},
    # 1656a:	e9 31 02 00 00       	jmp    167a0 <HIST_count_parallel_wksp>
    # 15551:	eb 0d                	jmp    15560 <FSE_writeNCount_generic>
    "jmp": {"r_offset": 1, "addend": -4},
    # 21f8c:	66 0f fe 05 3c 4c 0d 00	paddd  0xd4c3c(%rip),%xmm0        # f6bd0 <.LCPI70_0>
    "paddd": {"r_offset": 4, "addend": -4},
    # 15a0d:	48 8d 0d 8c fd 0d 00 	lea    0xdfd8c(%rip),%rcx        # f57a0 <FSE_normalizeCount.rtbTable>
    "leaq": {"r_offset": 3, "addend": -4},
    # 1831a:	e8 f1 32 00 00       	call   1b610 <HUF_simpleQuickSort>
    "callq": {"r_offset": 1, "addend": -4},
    # e5e15:	f2 0f 59 05 e3 2f 01 00	mulsd  0x12fe3(%rip),%xmm0        # f8e00 <.LCPI0_1>
    "mulsd": {"r_offset": 4, "addend": -4},
    # eb9d6:	f2 0f 5c 0d c2 ff 00 00	subsd  0xffc2(%rip),%xmm1        # fb9a0 <.LCPI26_8>
    "subsd": {"r_offset": 4, "addend": -4},
    # 2880f:	48 8b 0d 1a d7 0c 00 	mov    0xcd71a(%rip),%rcx        # f5f30 <repStartValue>
    # 63689:	66 0f d6 05 0b ab 0e 00	movq   %xmm0,0xeab0b(%rip)        # 14e19c <pcache1_g+0x5c>
    "movq": {"r_offset": 3, "addend": -4},
    # eb9c0:	66 0f 2e 05 38 d4 00 00	ucomisd 0xd438(%rip),%xmm0        # f8e00 <.LCPI0_1>
    "ucomisd": {"r_offset": 4, "addend": -4},
    # e76a6:	66 0f 62 0d 22 17 01 00	punpckldq 0x11722(%rip),%xmm1        # f8dd0 <.LCPI15_2>
    "punpckldq": {"r_offset": 4, "addend": -4},
    # e76c2:	f2 0f 5e 05 76 43 01 00	divsd  0x14376(%rip),%xmm0        # fba40 <.LCPI3_4>
    "divsd": {"r_offset": 4, "addend": -4},
    # 1d5be:	80 3d 0b 70 02 00 00 	cmpb   $0x0,0x2700b(%rip)        # 445d0 <gomp_display_affinity_var>
    "cmpb": {"r_offset": 2, "addend": -5},
    # 1d9b8:	48 01 05 51 69 02 00	lock add %rax,0x26951(%rip)        # 44310 <gomp_managed_threads>
    "addq": {"r_offset": 3, "addend": -4},
    # 1f8a0:	81 25 aa 4a 02 00 7f ff ff ff	andl   $0xffffff7f,0x24aaa(%rip)        # 44354 <gomp_futex_wake>
    "andl": {"r_offset": 2, "addend": -8},
    # 7af3d:	87 05 cd a7 17 00    	xchg   %eax,0x17a7cd(%rip)        # 1f5710 <__gconv_lock>
    "xchgl": {"r_offset": 2, "addend": -4},
    # 7af1e:	f0 0f b1 15 ea a7 17 00	lock cmpxchg %edx,0x17a7ea(%rip)        # 1f5710 <__gconv_lock>
    "cmpxchgl": {"r_offset": 3, "addend": -4},
    # 9be1f:	83 3d 1a 75 15 00 00 	cmpl   $0x0,0x15751a(%rip)        # 1f3340 <may_shrink_heap.12>
    "cmpl": {"r_offset": 2, "addend": -5},
    # 18039b:	f7 05 d3 ae 07 00 01 00 00 00	testl  $0x1,0x7aed3(%rip)        # 1fb278 <__x86_string_control>
    "testl": {"r_offset": 2, "addend": -8},
    # 571bc:	66 0f db 05 3c 9c 16 00 	pand   0x169c3c(%rip),%xmm0        # 1c0e00 <.LC0>
    "pand": {"r_offset": 4, "addend": -4},
    # 573f8:	db 2d 12 99 16 00    	fldt   0x169912(%rip)        # 1c0d10 <.LC0>
    "fldt": {"r_offset": 2, "addend": -4},
    # 57602:	66 0f 54 0d 26 97 16 00	andpd  0x169726(%rip),%xmm1        # 1c0d30 <othermask>
    "andpd": {"r_offset": 4, "addend": -4},
    # 8e811:	f0 ff 0d 90 4a 16 00 	lock decl 0x164a90(%rip)        # 1f32a8 <__nptl_nthreads>
    "decl": {"r_offset": 2, "addend": -4},
    # 33e0b:	d9 05 eb 08 0f 00    	flds   0xf08eb(%rip)        # 1246fc <.LC41>
    "flds": {"r_offset": 2, "addend": -4},
    # 33e1d:	dc 0d 85 0a 0f 00    	fmull  0xf0a85(%rip)        # 1248a8 <.LC192>
    "fmull": {"r_offset": 2, "addend": -4},
    # 354f0:	dd 05 92 f3 0e 00    	fldl   0xef392(%rip)        # 124888 <.LC182>
    "fldl": {"r_offset": 2, "addend": -4},
    # 34d15:	0f b7 3d 7a fe 0e 00 	movzwl 0xefe7a(%rip),%edi        # 124b96 <.LC180>
    "movzwl": {"r_offset": 3, "addend": -4},
    # 554ff:	f2 0f 10 0d d1 f3 0c 00 	movsd  0xcf3d1(%rip),%xmm1        # 1248d8 <.LC417>
    "movsd": {"r_offset": 4, "addend": -4},
    # 20145:	ff 25 1d a8 12 00    	jmpq    *0x12a81d(%rip)        # 14a968 <sqlite3Config+0xe8>
    "jmpq": {"r_offset": 2, "addend": -4},
    "jmpl": {"r_offset": 2, "addend": -4},
    #  1b082:	48 29 05 f7 32 13 00 	sub    %rax,0x1332f7(%rip)        # 14e380 <sqlite3Stat>
    "subq": {"r_offset": 3, "addend": -4},
    #  4768c:	66 0f 6e 0d 84 d0 0d 00	movd   0xdd084(%rip),%xmm1        # 124718 <.LC347>
    "movd": {"r_offset": 4, "addend": -4},
    # 7f49c:	c6 05 7d ee 0c 00 40 	movb   $0x40,0xcee7d(%rip)        # 14e320 <sqlite3Prng+0x80>
    "movb": {"r_offset": 2, "addend": -5},
    #    7f557:	28 05 c3 ed 0c 00    	sub    %al,0xcedc3(%rip)        # 14e320 <sqlite3Prng+0x80>
    "subb": {"r_offset": 2, "addend": -4},
    # a47a17:    83 2d c2 51 43 00 01    subl   $0x1,0x4351c2(%rip)        # e7cbe0 <_ZN12_GLOBAL__N_115NumberOfClientsE>
    "subl": {"r_offset": 2, "addend": -5},
    # 7f71a:	0f 11 05 ab eb 0c 00 	movups %xmm0,0xcebab(%rip)        # 14e2cc <sqlite3Prng+0x2c>
    "movups": {"r_offset": 3, "addend": -4},
    # 6330f:	83 05 d2 76 0e 00 01 	addl   $0x1,0xe76d2(%rip)        # 14a9e8 <sqlite3Config+0x168>
    "addl": {"r_offset": 2, "addend": -5},
    #    6332d:	0b 05 a5 76 0e 00    	or     0xe76a5(%rip),%eax        # 14a9d8 <sqlite3Config+0x158>
    "orl": {"r_offset": 2, "addend": -4},
    #   59f5b9:	c5 f9 6f 05 bf 15 41 00	vmovdqa 0x4115bf(%rip),%xmm0        # 9b0b80 <.LC40>
    "vmovdqa":{"r_offset": 4, "addend": -4},
    # 983e57:    c5 fa 10 05 69 c2 01 00   vmovss 0x1c269(%rip),%xmm0        # 9a00c8 <.LC111>
    "vmovss":{"r_offset": 4, "addend": -4},
    # 3d4545:    c5 fb 59 05 6b bb 5c 00   vmulsd 0x5cbb6b(%rip),%xmm0,%xmm0        # 9a00b8 <.LC59
    "vmulsd":{"r_offset": 4, "addend": -4},
    # 3d54a9:    c5 fb 10 0d 0f ac 5c 00   vmovsd 0x5cac0f(%rip),%xmm1        # 9a00c0 <.LC119>
    "vmovsd":{"r_offset": 4, "addend": -4},
    # 54fd63:    c4 e2 e9 99 0d c4 c3 44 00  vfmadd132sd 0x44c3c4(%rip),%xmm2,%xmm1        # 99c130 <.LC0>
    "vfmadd132sd":{"r_offset": 5, "addend": -4},
    # 6cb4d3:    c5 f9 54 05 d5 8e 2f 00   vandpd 0x2f8ed5(%rip),%xmm0,%xmm0        # 9c43b0 <.LC24>
    "vandpd":{"r_offset": 4, "addend": -4},
    # 4153e0:    c5 f9 2f 05 78 77 58 00  vcomisd 0x587778(%rip),%xmm0        # 99cb60 <.LC0>
    "vcomisd":{"r_offset": 4, "addend": -4},
    # 540f43:    c5 fb 5e 05 3d da 46 00   vdivsd 0x46da3d(%rip),%xmm0,%xmm0        # 9ae988 <.LC232>
    "vdivsd":{"r_offset": 4, "addend": -4},
    # 73a9f8:    c5 f9 2f 05 68 23 26 00   vcomisd 0x262368(%rip),%xmm0        # 99cd68 <.LC12>
    "vcomisd":{"r_offset": 4, "addend": -4},
    # 718213:    f0 48 0f c1 05 3c 97 43 00   lock xadd %rax,0x43973c(%rip)        # b51958
    "xaddq":{"r_offset": 4, "addend": -4},
    # 665090:    ff 35 6a 66 4e 00       push   0x4e666a(%rip)        # b4b700 <_ZN7rocksdbL16kRocksDbTFileExtE>
    "pushq":{"r_offset": 2, "addend": -4},
    # 716f70:    48 f7 35 b1 a9 43 00    divq   0x43a9b1(%rip)
    "divq":{"r_offset": 3, "addend": -4},
    # 32410e:    62 e1 fd 08 7f 0d 98 14 8f 00   vmovdqa64 %xmm17,0x8f1498(%rip)        # c155b0 <_ZN3fLSL24d_block_cache_trace_pathE>
    "vmovdqa64":{"r_offset": 6, "addend": -4},
    # 3e016f:    c5 e9 d4 05 a9 ab 69 00   vpaddq 0x69aba9(%rip),%xmm2,%xmm0        # a7ad20 <.LC39>
    "vpaddq":{"r_offset": 4, "addend": -4},
    # 470e54:    c5 fa 7e 05 44 62 60 00   vmovq  0x606244(%rip),%xmm0        # a770a0 <.LC0>
    "vmovq":{"r_offset": 4, "addend": -4},
    # 5fe540:    c4 62 7d 59 05 f7 bf 47 00   vpbroadcastq 0x47bff7(%rip),%ymm8        # a7a540 <.LC106>
    "vpbroadcastq":{"r_offset": 5, "addend": -4},
    # 34d530:    62 f1 7f 28 7f 05 02 0b 93 00   vmovdqu8 %ymm0,0x930b02(%rip)        # c7e03c <_ZN7rocksdbL21global_op_stage_tableE+0x7c>
    "vmovdqu8":{"r_offset": 6, "addend": -4},
    # 61eae1:    c5 fb 58 05 d7 71 4a 00   vaddsd 0x4a71d7(%rip),%xmm0,%xmm0        # ac5cc0 <.LC0>
    "vaddsd":{"r_offset": 4, "addend": -4},
    # 62f37:	66 89 05 46 79 0e 00 	mov    %ax,0xe7946(%rip)        # 14a884 <sqlite3Config+0x4>
    "movw":{"r_offset": 3, "addend": -4},
    # 62e25:	f3 0f 6f 0d 2b 7b 0e 00	movdqu 0xe7b2b(%rip),%xmm1        # 14a958 <sqlite3Config+0xd8>
    "movdqu":{"r_offset": 4, "addend": -4},
    # 73e44:    c5 ed fe 15 b4 75 03 00   vpaddd 0x375b4(%rip),%ymm2,%ymm2        # ab400 <PD_DESCALE_P2>
    "vpaddd":{"r_offset": 4, "addend": -4},
    #73dbc:     c5 cd f5 35 bc 75 03 00    vpmaddwd 0x375bc(%rip),%ymm6,%ymm6        # ab380 <PW_MF078_F117_F078_F117>
    "vpmaddwd":{"r_offset": 4, "addend": -4},
    #70629:     c5 dd e5 25 6f aa 03 00   vpmulhw 0x3aa6f(%rip),%ymm4,%ymm4        # ab0a0 <PW_MF0228>
    "vpmulhw":{"r_offset": 4, "addend": -4},
    #c5 dd fd 25 8f aa 03 00    vpaddw 0x3aa8f(%rip),%ymm4,%ymm4        # ab0e0 <PW_ONE>
    "vpaddw":{"r_offset": 4, "addend": -4},
    # 730dc:   c5 f5 d5 0d 1c 81 03 00    vpmullw 0x3811c(%rip),%ymm1,%ymm1        # ab200 <PW_THREE>
    "vpmullw":{"r_offset": 4, "addend": -4},
    #73ba8:c4 e2 7d 09 05 8f 78 03 00   vpsignw 0x3788f(%rip),%ymm0,%ymm0        # ab440 <PW_1_NEG1>
    "vpsignw":{"r_offset": 5, "addend": -4},
    # c5 fd fc 05 1a 75 03 00   vpaddb 0x3751a(%rip),%ymm0,%ymm0        # ab420 <PB_CENTERJSAMP
    "vpaddb":{"r_offset": 4, "addend": -4},
    # f6 05 b8 09 04 00 80 74 0a   testb  $0x80,0x409b8(%rip) # b52cc <simd_support>
    "testb":{"r_offset": 2, "addend": -7},


}


skip_opcodes = [
    "retq",
    "!CFI",
    "endbr64",
    "cwt",
    "clt",
    "syscall",
    "pause",
    "lock",
    "vzeroupper",
    "sfence",
    "fabs",
    "fxam",
    "leave",
    "ud2",
    "cqto",
    "fldz",
    "fchs",
    "fld1",
]

empty_instruction_prefix = [
    "6601",
    "6603",
    "6609",
    "660b",
    "660d",
    "660f",
    "66a9",
    "6619",
    "6623",
    "662b",
    "662d",
    "6631",
    "6633",
    "6639",
    "663d",
    "663b",
    "6689",
    "6642",
    "6641",
    "6643",
    "6644",
    "6645",
    "6646",
    "6649",
    "664c",
    "66c1",
    "66c7",
    "6690",
    "6625",
    "6605",
    "6681",
    "6683",
    "6685",
    "66bb",
    "66bd",
    "66f7",
    "66d1",
    "660f1f",
    "660f2f",
    "662e0f",
    "664189",
    "66480f",
    "660f6c",
    "66f20f",
    "66c747",
    "66f745",
    "660fef",
    "668365",
    "660f6f",
    "66662e",
    "668378",
    "668148",
    "6641f7c7",
    "662e0f1f",
    "66837c24",
]

leaq_instruction_prefix = [
    "488d05",
    "488d0d",
    "488d15",
    "488d1d",
    "488d2d",
    "488d35",
    "488d3d",
    "4c8d0d",
    "4c8d05",
    "4c8d15",
    "4c8d1d",
    "4c8d2d",
    "4c8d25",
    "4c8d35",
    "4c8d3d",
]
