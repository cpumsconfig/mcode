# -*- coding: utf-8 -*-
import struct

# PE文件结构常量
IMAGE_DOS_SIGNATURE = 0x5A4D      # MZ
IMAGE_NT_SIGNATURE = 0x00004550  # PE00

def create_dos_header():
    """创建DOS头"""
    dos_header = bytearray()
    dos_header.extend(struct.pack('<H', 0x5A4D))  # e_magic (MZ)
    dos_header.extend(struct.pack('<H', 0x0040))  # e_cblp
    dos_header.extend(struct.pack('<H', 0x0001))  # e_cp
    dos_header.extend(struct.pack('<H', 0x0000))  # e_crlc
    dos_header.extend(struct.pack('<H', 0x0040))  # e_cparhdr
    dos_header.extend(struct.pack('<H', 0x0000))  # e_minalloc
    dos_header.extend(struct.pack('<H', 0xFFFF))  # e_maxalloc
    dos_header.extend(struct.pack('<H', 0x0000))  # e_ss
    dos_header.extend(struct.pack('<H', 0x00B8))  # e_sp
    dos_header.extend(struct.pack('<H', 0x0000))  # e_csum
    dos_header.extend(struct.pack('<H', 0x0000))  # e_ip
    dos_header.extend(struct.pack('<H', 0x0000))  # e_cs
    dos_header.extend(struct.pack('<H', 0x0040))  # e_lfarlc
    dos_header.extend(struct.pack('<H', 0x0000))  # e_ovno
    dos_header.extend(b'\x00' * 8)      # e_res
    dos_header.extend(struct.pack('<H', 0x0040))  # e_oemid
    dos_header.extend(struct.pack('<H', 0x0000))  # e_oeminfo
    dos_header.extend(b'\x00' * 20)     # e_res2
    dos_header.extend(struct.pack('<I', 0x00000080))  # e_lfanew (PE头偏移)
    return dos_header

def create_nt_headers(entry_point, code_size, data_size, machine_type=0x8664):
    """创建NT头"""
    nt_headers = bytearray()
    
    # 签名
    nt_headers.extend(struct.pack('<I', 0x00004550))  # PE00
    
    # 文件头
    nt_headers.extend(struct.pack('<H', machine_type))    # Machine (根据架构设置)
    nt_headers.extend(struct.pack('<H', 0x0002))    # NumberOfSections
    nt_headers.extend(struct.pack('<I', 0x00000000))  # TimeDateStamp
    nt_headers.extend(struct.pack('<I', 0x00000000))  # PointerToSymbolTable
    nt_headers.extend(struct.pack('<I', 0x00000000))  # NumberOfSymbols
    nt_headers.extend(struct.pack('<H', 0x00F0))    # SizeOfOptionalHeader
    nt_headers.extend(struct.pack('<H', 0x0022))    # Characteristics
    
    # 可选头
    nt_headers.extend(struct.pack('<H', 0x020B))    # Magic (PE32+)
    nt_headers.extend(struct.pack('<B', 0x06))      # MajorLinkerVersion
    nt_headers.extend(struct.pack('<B', 0x00))      # MinorLinkerVersion
    nt_headers.extend(struct.pack('<I', code_size))  # SizeOfCode
    nt_headers.extend(struct.pack('<I', data_size))  # SizeOfInitializedData

    nt_headers.extend(struct.pack('<I', 0x00000000))  # SizeOfUninitializedData
    nt_headers.extend(struct.pack('<I', entry_point))  # AddressOfEntryPoint
    nt_headers.extend(struct.pack('<I', 0x00001000))  # BaseOfCode
    nt_headers.extend(struct.pack('<I', 0x00002000))  # BaseOfData
    nt_headers.extend(struct.pack('<Q', 0x0000000140000000))  # ImageBase
    nt_headers.extend(struct.pack('<I', 0x00001000))  # SectionAlignment
    nt_headers.extend(struct.pack('<I', 0x00000200))  # FileAlignment
    nt_headers.extend(struct.pack('<H', 0x0006))    # MajorOperatingSystemVersion
    nt_headers.extend(struct.pack('<H', 0x0000))    # MinorOperatingSystemVersion
    nt_headers.extend(struct.pack('<H', 0x0000))    # MajorImageVersion
    nt_headers.extend(struct.pack('<H', 0x0000))    # MinorImageVersion
    nt_headers.extend(struct.pack('<H', 0x0006))    # MajorSubsystemVersion
    nt_headers.extend(struct.pack('<H', 0x0000))    # MinorSubsystemVersion
    nt_headers.extend(struct.pack('<I', 0x00000000))  # Win32VersionValue
    nt_headers.extend(struct.pack('<I', 0x00003000))  # SizeOfImage
    nt_headers.extend(struct.pack('<I', 0x00000200))  # SizeOfHeaders
    nt_headers.extend(struct.pack('<I', 0x00000000))  # CheckSum
    nt_headers.extend(struct.pack('<H', 0x0003))    # Subsystem (Windows Console)
    nt_headers.extend(struct.pack('<H', 0x8160))    # DllCharacteristics
    
    # 64位特定的堆栈和堆设置
    nt_headers.extend(struct.pack('<Q', 0x00100000))  # SizeOfStackReserve
    nt_headers.extend(struct.pack('<Q', 0x00001000))  # SizeOfStackCommit
    nt_headers.extend(struct.pack('<Q', 0x00100000))  # SizeOfHeapReserve
    nt_headers.extend(struct.pack('<Q', 0x00001000))  # SizeOfHeapCommit
    
    nt_headers.extend(struct.pack('<I', 0x00000000))  # LoaderFlags
    nt_headers.extend(struct.pack('<I', 0x00000010))  # NumberOfRvaAndSizes
    
    # 数据目录
    # 导入表
    nt_headers.extend(struct.pack('<I', 0x00000000))  # Export Table RVA
    nt_headers.extend(struct.pack('<I', 0x00000000))  # Export Table Size
    nt_headers.extend(struct.pack('<I', 0x00002000))  # Import Table RVA
    nt_headers.extend(struct.pack('<I', 0x00000064))  # Import Table Size
    nt_headers.extend(struct.pack('<I', 0x00000000))  # Resource Table RVA
    nt_headers.extend(struct.pack('<I', 0x00000000))  # Resource Table Size
    nt_headers.extend(struct.pack('<I', 0x00000000))  # Exception Table RVA
    nt_headers.extend(struct.pack('<I', 0x00000000))  # Exception Table Size
    nt_headers.extend(struct.pack('<I', 0x00000000))  # Certificate Table RVA
    nt_headers.extend(struct.pack('<I', 0x00000000))  # Certificate Table Size
    nt_headers.extend(struct.pack('<I', 0x00000000))  # Base Relocation Table RVA
    nt_headers.extend(struct.pack('<I', 0x00000000))  # Base Relocation Table Size
    
    # 填充剩余的数据目录项
    for _ in range(9):
        nt_headers.extend(struct.pack('<I', 0x00000000))  # RVA
        nt_headers.extend(struct.pack('<I', 0x00000000))  # Size
    
    return nt_headers


def create_section_header(name, vsize, vaddr, size, raw, flags):
    """创建节区头"""
    section_header = bytearray()
    section_header.extend(name.ljust(8, b'\x00')[:8])  # Name
    section_header.extend(struct.pack('<I', vsize))   # VirtualSize
    section_header.extend(struct.pack('<I', vaddr))   # VirtualAddress
    section_header.extend(struct.pack('<I', size))    # SizeOfRawData
    section_header.extend(struct.pack('<I', raw))     # PointerToRawData
    section_header.extend(struct.pack('<I', 0))       # PointerToRelocations
    section_header.extend(struct.pack('<I', 0))       # PointerToLinenumbers
    section_header.extend(struct.pack('<H', 0))       # NumberOfRelocations
    section_header.extend(struct.pack('<H', 0))       # NumberOfLinenumbers
    section_header.extend(struct.pack('<I', flags))   # Characteristics
    return section_header

def align_up(x, align):
    return (x + align - 1) & ~(align - 1)

def make_pe(code, data, machine_type=0x8664):
    """创建PE文件"""
    file_align = 0x200
    section_align = 0x1000

    # 入口点（代码段 RVA）
    entry_point = 0x1000

    # DOS + NT
    dos_header = create_dos_header()
    nt_headers = create_nt_headers(entry_point, len(code), len(data), machine_type)

    # 节表
    section_table = bytearray()

    # headers 大小（对齐到 FileAlignment）
    headers_size = align_up(len(dos_header) + len(nt_headers) + 2*40, file_align)

    # ---- 代码节 ----
    code_rva = 0x1000
    code_raw = headers_size
    code_vsize = len(code)
    code_rawsize = align_up(len(code), file_align)

    code_section = create_section_header(
        b'.text',
        code_vsize,  # 确保这个值正确
        code_rva,
        code_rawsize,
        code_raw,
        0x60000020
    )

    section_table += code_section

    # ---- 数据节 ----
    data_rva = align_up(code_rva + code_rawsize, section_align)
    data_raw = code_raw + code_rawsize
    data_vsize = len(data)
    data_rawsize = align_up(len(data), file_align)

    data_section = create_section_header(
        b'.data',
        data_vsize,
        data_rva,
        data_rawsize,
        data_raw,
        0xC0000040  # 可读 | 可写 | 已初始化数据
    )
    section_table += data_section

    # 更新 SizeOfImage
    size_of_image = align_up(data_rva + data_rawsize, section_align)
    nt_headers[0x50:0x54] = struct.pack('<I', size_of_image)  # 修改 SizeOfImage
    nt_headers[0x54:0x58] = struct.pack('<I', headers_size)   # 修改 SizeOfHeaders

    # ---- 拼接文件 ----
    pe_file = dos_header + nt_headers + section_table
    pe_file = pe_file.ljust(headers_size, b'\x00')

    # 代码
    pe_file[code_raw:code_raw+len(code)] = code
    # 数据
    pe_file[data_raw:data_raw+len(data)] = data

    return pe_file


def gen_windows(stmts):
    """
    生成Windows PE格式的机器代码
    支持: let, print_str, print_var, exit, mov, int, asm, if, elif, else, op (32-bit),
          while, for, import, global, extern, cli, sti, hlt, call, return, entel
    """
    variables = {}
    labels = {}          # name -> code offset
    fixups = []          # list of (pos_in_code, label) for E8/E9 rel32
    code = bytearray()
    data = bytearray()
    unique_id = 0
    
    # 架构设置 - 默认为64位
    architecture = "AMD64"  # 可以是 "86", "64", "AMD64"
    machine_type = 0x8664   # AMD64 的机器类型
    
    # 设置程序入口点
    entry_point = len(code)

    # 模块系统相关
    modules = {}        # 已导入的模块
    global_funcs = {}   # 全局函数：name -> (code_offset, param_count)
    extern_funcs = {}   # 外部函数：name -> (module_name, func_name)
    
    # API地址表 - 使用简化的方式
    # 注意：这些地址是Windows 10/11中的典型地址，但实际地址可能因系统版本和更新而异
    # 在实际应用中，应该使用导入表而不是硬编码地址
    api_addresses = {
        'ExitProcess': 0x76F0DAD0,      # kernel32.dll中的ExitProcess地址 (Windows 10/11)
        'MessageBoxA': 0x756A1A60,      # user32.dll中的MessageBoxA地址 (Windows 10/11)
        'CreateFileA': 0x76EFC4A0,      # kernel32.dll中的CreateFileA地址 (Windows 10/11)
        'ReadFile': 0x76EFB3D0,         # kernel32.dll中的ReadFile地址 (Windows 10/11)
        'CloseHandle': 0x76EFB7B0,      # kernel32.dll中的CloseHandle地址 (Windows 10/11)
        'MessageBeep': 0x756A1B70,      # user32.dll中的MessageBeep地址 (Windows 10/11)
        'caption': 0x00402000,          # 数据段中的偏移量
        'filename': 0x00402010,         # 数据段中的偏移量
        'buffer': 0x00402020            # 数据段中的偏移量
    }
    
    # 字符串地址表
    string_addresses = {}
    
    def new_label(base="L"):
        nonlocal unique_id
        unique_id += 1
        return f"{base}{unique_id}"

    def emit(b):
        """append bytes to code"""
        if isinstance(b, int):
            code.append(b)
        else:
            code.extend(b)

    def emit_data(b):
        """append bytes to data"""
        if isinstance(b, int):
            data.append(b)
        else:
            data.extend(b)

    # helper to allocate a memory variable (32-bit) and return offset
    def alloc_mem_var(name, size=4):
        offset = len(data)
        emit_data(b'\x00' * size)
        variables[name] = ('mem', offset)
        return offset

    # helper to get variable type and value/offset
    def var_get(name):
        if name not in variables:
            # if unknown variable, auto-allocate as mem (4 bytes)
            alloc_mem_var(name, 4)
        return variables[name]

    # emit mov reg, imm (supports 8-bit, 16-bit and 32-bit registers)
    reg8_enc = {"al": 0xb0, "cl": 0xb1, "dl": 0xb2, "bl": 0xb3, "ah": 0xb4, "ch": 0xb5, "dh": 0xb6, "bh": 0xb7}
    reg16_enc = {"ax": 0xb8, "cx": 0xb9, "dx": 0xba, "bx": 0xbb, "sp": 0xbc, "bp": 0xbd, "si": 0xbe, "di": 0xbf}
    reg32_enc = {"eax": 0xb8, "ecx": 0xb9, "edx": 0xba, "ebx": 0xbb, "esp": 0xbc, "ebp": 0xbd, "esi": 0xbe, "edi": 0xbf}

    def emit_mov_reg_imm(reg, val):
        if reg in reg8_enc:
            emit(bytes([reg8_enc[reg]] + [val & 0xff]))
        elif reg in reg16_enc:
            emit(bytes([0x66]) + bytes([reg16_enc[reg]]) + struct.pack("<H", val & 0xffff))
        elif reg in reg32_enc:
            emit(bytes([reg32_enc[reg]]) + struct.pack("<I", val & 0xffffffff))
        else:
            raise ValueError("Unsupported register for mov immediate: " + reg)

    # mov reg, [moffs] for 32-bit: MOV EAX, moffs32 -> A1 moffs32
    def emit_mov_reg_from_moffs8(reg, moffs):
        # only AL supported for 8-bit moffs using A0
        if reg != "al":
            raise ValueError("Only AL supported for moffs8 in this helper")
        emit(b'\xa0' + struct.pack('<I', moffs))

    def emit_mov_reg_from_moffs16(reg, moffs):
        if reg == "ax":
            emit(b'\x66\xa1' + struct.pack('<I', moffs))
        else:
            raise ValueError("Only AX supported for moffs16 in this helper")

    def emit_mov_reg_from_moffs32(reg, moffs):
        if reg == "eax":
            emit(b'\xa1' + struct.pack('<I', moffs))
        else:
            # generic approach: load address into something then use mov
            emit(b'\xb8' + struct.pack('<I', moffs))  # mov eax, moffs
            if reg == "ebx":
                emit(b'\x8b\x18')  # mov ebx, [eax]
            elif reg == "ecx":
                emit(b'\x8b\x08')  # mov ecx, [eax]
            elif reg == "edx":
                emit(b'\x8b\x10')  # mov edx, [eax]
            elif reg == "esi":
                emit(b'\x8b\x30')  # mov esi, [eax]
            elif reg == "edi":
                emit(b'\x8b\x38')  # mov edi, [eax]
            else:
                raise ValueError("Unsupported register for moffs32 in this helper")

    # mov [moffs], eax : opcode A3 moffs32
    def emit_mov_moffs_from_eax(moffs):
        emit(b'\xa3' + struct.pack('<I', moffs))

    # top-level statement processor (handles a single stmt)
    def process_statement(st):
        nonlocal architecture, machine_type
        t = st[0]
        if t == "entel":
            # 设置目标架构
            arch = st[1].upper()
            if arch in ["86", "32", "X86"]:
                architecture = "X86"
                machine_type = 0x014C  # IMAGE_FILE_MACHINE_I386
            elif arch in ["64", "AMD64", "X64"]:
                architecture = "AMD64"
                machine_type = 0x8664  # IMAGE_FILE_MACHINE_AMD64
            else:
                raise ValueError(f"不支持的架构: {arch}，支持的架构有: 86, 64, AMD64")

        elif t == "let":
            # st = ("let", name, value)
            name, val = st[1], st[2]
            # if val is int -> const; else if string "mem" or none -> allocate mem
            try:
                ival = int(val)
                variables[name] = ('const', ival)
            except Exception:
                # allocate as memory variable (4 bytes)
                alloc_mem_var(name, 4)

        elif t == "print_str":
            s = st[1] + "\n"
            # 在Windows中，我们可以使用MessageBoxA来显示字符串
            # 首先在数据段中存储字符串
            str_addr = len(data)
            emit_data(s.encode('ascii') + b'\x00')
            
            # 记录字符串地址，用于后续修复
            string_id = f'string_{len(code)}'
            string_addresses[string_id] = 0x00402000 + str_addr
            
            # 调用MessageBoxA
            # 参数: hWnd=0, lpText=字符串地址, lpCaption="Output", uType=0
            emit(b'\x6a\x00')              # push 0 (uType)
            emit(b'\x68\x00\x00\x00\x00')  # push "Output"
            fixups.append(('fixup', len(code)-4, 'caption'))
            emit(b'\x68\x00\x00\x00\x00')  # push 字符串地址
            fixups.append(('fixup', len(code)-4, string_id))
            emit(b'\x6a\x00')              # push 0 (hWnd)
            
            # 调用MessageBoxA
            emit(b'\xb8\x00\x00\x00\x00')  # mov eax, MessageBoxA
            fixups.append(('fixup', len(code)-4, 'MessageBoxA'))
            emit(b'\xff\xd0')              # call eax

        elif t == "print_var":
            name = st[1]
            typ, val = var_get(name)
            if typ == 'const':
                s = str(val)
            else:
                # 从内存中读取值
                emit(b'\xa1' + struct.pack('<I', val))  # mov eax, [val]
                emit(b'\x50')  # push eax
                emit(b'\x6a\x40')  # push 64 (缓冲区大小)
                emit(b'\x6a\x00')  # push 0 (初始化为0)
                emit(b'\x6a\x00')  # push 0 (堆栈分配)
                emit(b'\xb8\x00\x00\x00\x00')  # mov eax, _alloca
                fixups.append(('fixup', len(code)-4, '_alloca'))
                emit(b'\xff\xd0')  # call eax
                
                # 现在EAX指向缓冲区
                emit(b'\x89\xc1')  # mov ecx, eax
                emit(b'\x58')      # pop eax (值)
                emit(b'\x50')      # push eax
                emit(b'\x51')      # push ecx
                emit(b'\x6a\x0a')  # push 10 (基数10)
                emit(b'\xb8\x00\x00\x00\x00')  # mov eax, _itoa
                fixups.append(('fixup', len(code)-4, '_itoa'))
                emit(b'\xff\xd0')  # call eax
                
                # 现在ECX指向转换后的字符串
                emit(b'\x51')  # push ecx
                
                # 调用MessageBoxA
                emit(b'\x6a\x00')              # push 0 (uType)
                emit(b'\x68\x00\x00\x00\x00')  # push "Output"
                fixups.append(('fixup', len(code)-4, 'caption'))
                emit(b'\x51')                  # push 字符串地址
                emit(b'\x6a\x00')              # push 0 (hWnd)
                
                # 调用MessageBoxA
                emit(b'\xb8\x00\x00\x00\x00')  # mov eax, MessageBoxA
                fixups.append(('fixup', len(code)-4, 'MessageBoxA'))
                emit(b'\xff\xd0')              # call eax

        elif t == "exit":
            # 在Windows中，使用ExitProcess退出程序
            emit(b'\x6a' + bytes([st[1] & 0xff]))  # push exit_code
            emit(b'\xb8\x00\x00\x00\x00')  # mov eax, ExitProcess
            fixups.append(('fixup', len(code)-4, 'ExitProcess'))
            emit(b'\xff\xd0')  # call eax

        elif t == "mov":
            # ("mov", reg, val)
            reg, val = st[1], st[2]
            # if val is int -> immediate; if variable name -> load constant if const else load mem offset as immediate (compile-time)
            try:
                ival = int(val)
                emit_mov_reg_imm(reg, ival)
            except Exception:
                # val is variable
                typ, v = var_get(val)
                if typ == 'const':
                    emit_mov_reg_imm(reg, v)
                else:
                    # memory variable: load from moffs into register depending on reg
                    if reg in ("eax",):
                        emit_mov_reg_from_moffs32("eax", v)
                    elif reg in ("ebx", "ecx", "edx", "esi", "edi"):
                        emit_mov_reg_from_moffs32(reg, v)
                    elif reg in ("ax",):
                        emit_mov_reg_from_moffs16("ax", v)
                    elif reg in ("al",):
                        emit_mov_reg_from_moffs8("al", v)
                    else:
                        raise ValueError("mov from mem unsupported for reg: " + reg)

        elif t == "int":
            # 在Windows中，int指令通常不直接使用，而是通过API调用
            # 这里我们生成对应的机器码，但实际运行可能不会按预期工作
            emit(b"\xcd" + bytes([st[1] & 0xff]))

        elif t == "asm":
            # st[1]: "xx yy zz"
            for byte in st[1].split():
                emit(bytes([int(byte, 16)]))
                
        elif t == "if":
            # 比较变量值是否为真（非零）
            var_name = st[1]
            typ, val = variables[var_name]
            if typ == 'const':
                emit(b'\xb8' + struct.pack('<I', val))  # mov eax, val
            else:
                emit(b'\xa1' + struct.pack('<I', val))  # mov eax, [val]
            emit(b'\x85\xc0')  # test eax, eax
            # 如果条件为假，跳转到标签
            pos = len(code)
            emit(b'\x0f\x84\x00\x00\x00\x00')  # jz rel32 placeholder
            fixups.append(('jz', pos + 2, st[2]))  # 记录需要修复的位置和目标标签

        elif t == "elif":
            # 比较变量值是否为真（非零）
            var_name = st[1]
            typ, val = variables[var_name]
            if typ == 'const':
                emit(b'\xb8' + struct.pack('<I', val))  # mov eax, val
            else:
                emit(b'\xa1' + struct.pack('<I', val))  # mov eax, [val]
            emit(b'\x85\xc0')  # test eax, eax
            # 如果条件为假，跳转到标签
            pos = len(code)
            emit(b'\x0f\x85\x00\x00\x00\x00')  # jnz rel32 placeholder
            fixups.append(('jnz', pos + 2, st[2]))  # 记录需要修复的位置和目标标签

        elif t == "else":
            # 无条件跳转到标签
            pos = len(code)
            emit(b'\xe9\x00\x00\x00\x00')  # jmp rel32 placeholder
            fixups.append(('jmp', pos + 1, st[1]))  # 记录需要修复的位置和目标标签

        elif t == "op":
            # ("op", dest, src1, op, src2)  - use 32-bit arithmetic, result stored into dest (mem var)
            dest, src1, oper, src2 = st[1], st[2], st[3], st[4]
            # ensure dest is memory variable
            if dest not in variables or variables[dest][0] != 'mem':
                alloc_mem_var(dest, 4)
            dest_off = variables[dest][1]

            # load src1 -> EAX
            try:
                v1 = int(src1)
                emit_mov_reg_imm("eax", v1 & 0xffffffff)
            except Exception:
                typ1, v1 = var_get(src1)
                if typ1 == 'const':
                    emit_mov_reg_imm("eax", v1 & 0xffffffff)
                else:
                    emit_mov_reg_from_moffs32("eax", v1)

            # load src2 -> EBX
            try:
                v2 = int(src2)
                emit_mov_reg_imm("ebx", v2 & 0xffffffff)
            except Exception:
                typ2, v2 = var_get(src2)
                if typ2 == 'const':
                    emit_mov_reg_imm("ebx", v2 & 0xffffffff)
                else:
                    emit_mov_reg_from_moffs32("ebx", v2)

            # perform operation on EAX, EBX
            if oper == '+':
                emit(b'\x01\xd8')  # add eax, ebx
            elif oper == '-':
                emit(b'\x29\xd8')  # sub eax, ebx
            elif oper == '*':
                emit(b'\xf7\xe3')  # mul ebx
            elif oper == '/':
                emit(b'\x99')  # cdq
                emit(b'\xf7\xf3')  # idiv ebx
            else:
                raise ValueError("Unsupported op: " + oper)

            # store EAX into dest moffs (mov [moffs], eax) -> opcode A3 moffs32
            emit_mov_moffs_from_eax(dest_off)

            # also update compile-time data so later print_var / op can read it
            # Try constant-folding when possible:
            const_fold = None
            try:
                a1 = int(src1)
            except:
                typ1, v1 = var_get(src1)
                if typ1 == 'const':
                    a1 = v1
                else:
                    a1 = None
            try:
                a2 = int(src2)
            except:
                typ2, v2 = var_get(src2)
                if typ2 == 'const':
                    a2 = v2
                else:
                    a2 = None
            if a1 is not None and a2 is not None:
                if oper == '+': const_fold = (a1 + a2) & 0xffffffff
                elif oper == '-': const_fold = (a1 - a2) & 0xffffffff
                elif oper == '*': const_fold = (a1 * a2) & 0xffffffff
                elif oper == '/':
                    const_fold = (a1 // a2) & 0xffffffff if a2 != 0 else 0
            if const_fold is not None:
                data[dest_off:dest_off+4] = struct.pack("<I", const_fold)

        elif t == "cli":
            # 在Windows用户空间中，CLI指令没有实际效果，但可以生成对应的机器码
            emit(b'\xfa')  # CLI

        elif t == "sti":
            # 在Windows用户空间中，STI指令没有实际效果，但可以生成对应的机器码
            emit(b'\xfb')  # STI

        elif t == "hlt":
            # 在Windows用户空间中，HLT指令会导致程序终止，我们可以用ExitProcess替代
            emit(b'\x6a\x00')  # push 0 (exit code)
            emit(b'\xb8\x00\x00\x00\x00')  # mov eax, ExitProcess
            fixups.append(('fixup', len(code)-4, 'ExitProcess'))
            emit(b'\xff\xd0')  # call eax
            
        elif t == "while":
            # ("while", condition, block_statements)
            condition, block_stmts = st[1], st[2]
            
            # 创建循环开始和结束标签
            loop_start = new_label("while_start")
            loop_end = new_label("while_end")
            
            # 设置循环开始标签
            labels[loop_start] = len(code)
            
            # 生成条件检查代码
            var_name = condition
            typ, val = variables[var_name]
            if typ == 'const':
                emit(b'\xb8' + struct.pack('<I', val))  # mov eax, val
            else:
                emit(b'\xa1' + struct.pack('<I', val))  # mov eax, [val]
            emit(b'\x85\xc0')  # test eax, eax
            
            # 如果条件为假，跳转到循环结束
            pos = len(code)
            emit(b'\x0f\x84\x00\x00\x00\x00')  # jz rel32 placeholder
            fixups.append(('jz', pos + 2, loop_end))
            
            # 处理循环体
            for s in block_stmts:
                process_statement(s)
            
            # 跳回循环开始
            pos_jmp = len(code)
            emit(b'\xe9\x00\x00\x00\x00')  # jmp rel32 placeholder
            fixups.append(('jmp', pos_jmp + 1, loop_start))
            
            # 设置循环结束标签
            labels[loop_end] = len(code)
            
        elif t == "for":
            # ("for", var, start, end, step, block_statements)
            var_name, start_val, end_val, step_val, block_stmts = st[1], st[2], st[3], st[4], st[5]
            
            # 确保循环变量存在
            if var_name not in variables:
                alloc_mem_var(var_name, 4)
            
            # 创建循环开始和结束标签
            loop_start = new_label("for_start")
            loop_end = new_label("for_end")
            
            # 初始化循环变量
            try:
                start = int(start_val)
                emit(b'\xb8' + struct.pack('<I', start))  # mov eax, start
            except ValueError:
                typ, start = variables[start_val]
                if typ == 'const':
                    emit(b'\xb8' + struct.pack('<I', start))  # mov eax, start
                else:
                    emit(b'\xa1' + struct.pack('<I', start))  # mov eax, [start]
            
            # 保存初始值到循环变量
            var_off = variables[var_name][1]
            emit_mov_moffs_from_eax(var_off)
            
            # 设置循环开始标签
            labels[loop_start] = len(code)
            
            # 加载循环变量到EAX
            emit(b'\xa1' + struct.pack('<I', var_off))  # mov eax, [var_off]
            
            # 加载结束值到EBX
            try:
                end = int(end_val)
                emit(b'\xbb' + struct.pack('<I', end))  # mov ebx, end
            except ValueError:
                typ, end = variables[end_val]
                if typ == 'const':
                    emit(b'\xbb' + struct.pack('<I', end))  # mov ebx, end
                else:
                    emit(b'\x8b\x1d' + struct.pack('<I', end))  # mov ebx, [end]
            
            # 比较EAX和EBX
            emit(b'\x39\xc3')  # cmp eax, ebx
            
            # 如果EAX > EBX，跳转到循环结束（假设是递增循环）
            pos = len(code)
            emit(b'\x0f\x8f\x00\x00\x00\x00')  # jg rel32 placeholder
            fixups.append(('jg', pos + 2, loop_end))
            
            # 处理循环体
            for s in block_stmts:
                process_statement(s)
            
            # 更新循环变量
            emit(b'\xa1' + struct.pack('<I', var_off))  # mov eax, [var_off]
            
            try:
                step = int(step_val)
                emit(b'\xbb' + struct.pack('<I', step))  # mov ebx, step
            except ValueError:
                typ, step = variables[step_val]
                if typ == 'const':
                    emit(b'\xbb' + struct.pack('<I', step))  # mov ebx, step
                else:
                    emit(b'\x8b\x1d' + struct.pack('<I', step))  # mov ebx, [step]
            
            # EAX = EAX + EBX
            emit(b'\x01\xd8')  # add eax, ebx
            
            # 保存更新后的值
            emit_mov_moffs_from_eax(var_off)
            
            # 跳回循环开始
            pos_jmp = len(code)
            emit(b'\xe9\x00\x00\x00\x00')  # jmp rel32 placeholder
            fixups.append(('jmp', pos_jmp + 1, loop_start))
            
            # 设置循环结束标签
            labels[loop_end] = len(code)

        elif t == "global":
            # ("global", func_name, param_count, block_statements)
            func_name, param_count, block_stmts = st[1], st[2], st[3]
            
            # 记录全局函数信息
            global_funcs[func_name] = (len(code), param_count)
            
            # 创建函数标签
            labels[func_name] = len(code)
            
            # 处理函数体
            for s in block_stmts:
                process_statement(s)
            
            # 函数返回
            emit(b'\xc3')  # RET
            
        elif t == "extern":
            # ("extern", func_name, module_name)
            func_name, module_name = st[1], st[2]
            
            # 记录外部函数信息
            extern_funcs[func_name] = (module_name, func_name)
        
        elif t == "import":
            # ("import", module_name)
            module_name = st[1]
            
            # 检查模块是否已导入
            if module_name not in modules:
                # 尝试加载模块
                try:
                    # 这里简化处理，实际应该从文件加载模块
                    modules[module_name] = {
                        'functions': {},  # 模块中的函数
                        'variables': {},  # 模块中的变量
                        'code': bytearray(),  # 模块的代码
                        'data': bytearray()   # 模块的数据
                    }
                except Exception as e:
                    raise ValueError(f"Failed to import module {module_name}: {str(e)}")
                    
        elif t == "call":
            # ("call", func_name, args)
            func_name, args = st[1], st[2]
            
            # 检查是否是全局函数
            if func_name in global_funcs:
                func_offset, param_count = global_funcs[func_name]
                
                # 检查参数数量是否匹配
                if len(args) != param_count:
                    raise ValueError(f"Function {func_name} expects {param_count} arguments, got {len(args)}")
                
                # 将参数压栈
                for i, arg in enumerate(args):
                    try:
                        val = int(arg)
                        emit(b'\xb8' + struct.pack('<I', val))  # mov eax, val
                    except ValueError:
                        typ, val = variables[arg]
                        if typ == 'const':
                            emit(b'\xb8' + struct.pack('<I', val))  # mov eax, val
                        else:
                            emit(b'\xa1' + struct.pack('<I', val))  # mov eax, [val]
                    
                    # 压栈
                    emit(b'\x50')  # push eax
                
                # 调用函数
                pos = len(code)
                emit(b'\xe8\x00\x00\x00\x00')  # call rel32 placeholder
                fixups.append(('call', pos + 1, func_name))
                
                # 清理栈
                if param_count > 0:
                    emit(b'\x81\xc4' + struct.pack('<I', param_count * 4))  # add esp, param_count * 4
            
            # 检查是否是外部函数
            elif func_name in extern_funcs:
                module_name, extern_func_name = extern_funcs[func_name]
                
                # 检查模块是否已导入
                if module_name not in modules:
                    raise ValueError(f"Module {module_name} not imported")
                
                # 检查函数是否存在于模块中
                if extern_func_name not in modules[module_name]['functions']:
                    raise ValueError(f"Function {extern_func_name} not found in module {module_name}")
                
                # 获取函数信息
                func_offset, param_count = modules[module_name]['functions'][extern_func_name]
                
                # 检查参数数量是否匹配
                if len(args) != param_count:
                    raise ValueError(f"Function {func_name} expects {param_count} arguments, got {len(args)}")
                
                # 将参数压栈
                for i, arg in enumerate(args):
                    try:
                        val = int(arg)
                        emit(b'\xb8' + struct.pack('<I', val))  # mov eax, val
                    except ValueError:
                        typ, val = variables[arg]
                        if typ == 'const':
                            emit(b'\xb8' + struct.pack('<I', val))  # mov eax, val
                        else:
                            emit(b'\xa1' + struct.pack('<I', val))  # mov eax, [val]
                    
                    # 压栈
                    emit(b'\x50')  # push eax
                
                # 调用函数
                pos = len(code)
                emit(b'\xe8\x00\x00\x00\x00')  # call rel32 placeholder
                fixups.append(('call', pos + 1, f"{module_name}.{extern_func_name}"))
                
                # 清理栈
                if param_count > 0:
                    emit(b'\x81\xc4' + struct.pack('<I', param_count * 4))  # add esp, param_count * 4
            
            else:
                raise ValueError(f"Unknown function: {func_name}")
                
        elif t == "return":
            # st = ("return", ret_val)
            ret_val = st[1]  # 可能为None，表示无返回值
            
            if ret_val is not None:
                # 有返回值，将返回值放入EAX寄存器
                try:
                    # 尝试解析为整数
                    val = int(ret_val, 0)
                    emit(b'\xb8' + struct.pack('<I', val))  # mov eax, val
                except ValueError:
                    # 不是整数，可能是变量
                    typ, val = variables[ret_val]
                    if typ == 'const':
                        emit(b'\xb8' + struct.pack('<I', val))  # mov eax, val
                    else:
                        emit(b'\xa1' + struct.pack('<I', val))  # mov eax, [val]
            
            # 使用RET指令返回
            emit(b'\xc3')  # RET
            
        elif t in ["inb", "inw", "inl", "outb", "outw", "outl"]:
            port = int(st[1].strip(','), 0)
            if t in ["outb", "outw", "outl"]:
                value = int(st[2].strip(','), 0)
            
            # 在Windows用户空间中，直接访问I/O端口需要特殊权限
            # 我们可以使用DeviceIoControl API，但这需要驱动程序支持
            # 这里我们生成对应的机器码，但实际运行可能需要特殊权限
            
            if t == "inb":
                emit(b'\xb0')  # mov al, imm8
                emit(port & 0xff)
                emit(b'\xe4')  # in al, imm8
            elif t == "inw":
                emit(b'\x66')  # operand-size override (16-bit)
                emit(b'\xb8')  # mov ax, imm16
                emit(struct.pack("<H", port & 0xffff))
                emit(b'\xed')  # in ax, dx
            elif t == "inl":
                emit(b'\xb8')  # mov eax, imm32
                emit(struct.pack("<I", port & 0xffffffff))
                emit(b'\xed')  # in eax, dx
            elif t == "outb":
                emit(b'\xb0')  # mov al, imm8
                emit(value & 0xff)
                emit(b'\xe6')  # out imm8, al
                emit(port & 0xff)
            elif t == "outw":
                emit(b'\x66')  # operand-size override (16-bit)
                emit(b'\xb8')  # mov ax, imm16
                emit(struct.pack("<H", value & 0xffff))
                emit(b'\xef')  # out dx, ax
                emit(struct.pack("<H", port & 0xffff))
            elif t == "outl":
                emit(b'\xb8')  # mov eax, imm32
                emit(struct.pack("<I", value & 0xffffffff))
                emit(b'\xef')  # out dx, eax
                emit(struct.pack("<H", port & 0xffff))
                
        elif t == "read_cmos":
            # st = ("read_cmos", addr, var)
            addr = int(st[1], 0)
            var_name = st[2]  # 可能为None，表示使用默认变量
            
            # 确保有一个变量来存储结果
            if var_name is None:
                var_name = "cmos_result"
            
            # 确保变量存在，如果不存在则创建
            if var_name not in variables:
                alloc_mem_var(var_name, 4)  # 分配4字节，确保有足够空间
            
            var_off = variables[var_name][1]
            
            # 在Windows用户空间中，直接访问CMOS需要特殊权限
            # 我们可以使用DeviceIoControl API，但这需要驱动程序支持
            # 这里我们生成对应的机器码，但实际运行可能需要特殊权限
            
            # 禁用中断
            emit(b'\xfa')  # CLI
            
            # 读取CMOS的汇编代码
            # 1. 设置要读取的CMOS地址
            emit(b'\xb0')  # MOV AL, imm8
            emit(addr & 0xFF)
            emit(b'\xe6')  # OUT imm8, AL
            emit(0x70)     # CMOS地址端口
            
            # 2. 从CMOS数据端口读取
            emit(b'\xe4')  # IN AL, imm8
            emit(0x71)     # CMOS数据端口
            
            # 3. 将AL零扩展到EAX（高字节置零）
            emit(b'\x31\xc0')  # XOR EAX, EAX (清零EAX)
            emit(b'\x8a\xc8')  # MOV CL, AL
            emit(b'\x88\xc2')  # MOV DL, AL
            emit(b'\x89\xc0')  # MOV EAX, EAX
            
            # 4. 保存结果到变量
            emit_mov_moffs_from_eax(var_off)
            
            # 恢复中断
            emit(b'\xfb')  # STI
            
        elif t == "read_fat12_hdr" or t == "read_fat16_hdr":
            # st = ("read_fat12_hdr" or "read_fat16_hdr", var_name, offset)
            var_name = st[1]  # 可能为None，表示使用默认变量
            offset = int(st[2], 0)
            
            # 确保有一个变量来存储结果
            if var_name is None:
                var_name = "fat_hdr_value"
            
            # 确保变量存在，如果不存在则创建
            if var_name not in variables:
                alloc_mem_var(var_name, 4)  # 分配4字节，确保有足够空间
            
            var_off = variables[var_name][1]
            
            # 在Windows中，我们不能直接访问磁盘，需要使用文件系统API
            # 这里我们使用CreateFile和ReadFile API
            
            # 1. 打开文件（这里简化处理，实际应该使用适当的API）
            emit(b'\x68\x00\x00\x00\x00')  # push 0 (hTemplateFile)
            emit(b'\x68\x80\x00\x00\x00')  # push FILE_ATTRIBUTE_NORMAL
            emit(b'\x68\x03\x00\x00\x00')  # push OPEN_EXISTING
            emit(b'\x68\x00\x00\x00\x00')  # push 0 (lpSecurityAttributes)
            emit(b'\x68\x01\x00\x00\x00')  # push FILE_SHARE_READ
            emit(b'\x68\xc0\x00\x00\x00')  # push GENERIC_READ
            emit(b'\x68\x00\x00\x00\x00')  # push lpFileName (这里简化处理)
            fixups.append(('fixup', len(code)-4, 'filename'))
            emit(b'\xb8\x00\x00\x00\x00')  # mov eax, CreateFileA
            fixups.append(('fixup', len(code)-4, 'CreateFileA'))
            emit(b'\xff\xd0')  # call eax
            
            # 2. 读取文件
            emit(b'\x8b\xf0')  # mov esi, eax (保存文件句柄)
            emit(b'\x6a\x00')  # push 0 (lpOverlapped)
            emit(b'\x68\x00\x00\x00\x00')  # push pNumberOfBytesRead
            emit(b'\x68\x01\x00\x00\x00')  # push nNumberOfBytesToRead (1)
            emit(b'\x68\x00\x00\x00\x00')  # push lpBuffer (这里简化处理)
            fixups.append(('fixup', len(code)-4, 'buffer'))
            emit(b'\x56')  # push esi (hFile)
            emit(b'\xb8\x00\x00\x00\x00')  # mov eax, ReadFile
            fixups.append(('fixup', len(code)-4, 'ReadFile'))
            emit(b'\xff\xd0')  # call eax
            
            # 3. 关闭文件
            emit(b'\x56')  # push esi (hFile)
            emit(b'\xb8\x00\x00\x00\x00')  # mov eax, CloseHandle
            fixups.append(('fixup', len(code)-4, 'CloseHandle'))
            emit(b'\xff\xd0')  # call eax
            
            # 4. 从缓冲区读取指定偏移的值
            emit(b'\xb8\x00\x00\x00\x00')  # mov eax, buffer
            fixups.append(('fixup', len(code)-4, 'buffer'))
            emit(b'\x8b\x58')              # mov ebx, [eax + offset]
            emit(struct.pack('<I', offset))
            
            # 5. 保存结果到变量
            emit(b'\x89\x1d')              # mov [var_off], ebx
            emit(struct.pack('<I', var_off))
            
        elif t == "beep":
            # 在Windows中，我们可以使用MessageBeep API来发出声音
            emit(b'\x6a\x00')  # push 0 (MB_OK)
            emit(b'\xb8\x00\x00\x00\x00')  # mov eax, MessageBeep
            fixups.append(('fixup', len(code)-4, 'MessageBeep'))
            emit(b'\xff\xd0')  # call eax
            
        else:
            raise ValueError("Unknown statement type: " + str(t))

    # ---- main loop: iterate statements ----
    
    # 添加简单的控制台程序入口点
    emit(b'\x6a\x00')  # push 0 (exit code)
    emit(b'\xb8\x00\x00\x00\x00')  # mov eax, ExitProcess
    fixups.append(('fixup', len(code)-4, 'ExitProcess'))
    emit(b'\xff\xd0')  # call eax
    
    for st in stmts:
        process_statement(st)

    # ---- resolve fixups ----
    # 首先处理API调用和标签跳转
    
    # 在数据段中添加必要的字符串
    # 添加"Output"字符串，用于MessageBoxA的标题
    caption_addr = len(data)
    emit_data(b"Output\0")
    
    # 更新API地址表中的字符串地址
    api_addresses['caption'] = 0x00402000 + caption_addr
    
    # 处理所有fixup
    for item in list(fixups):
        if item[0] == 'fixup':
            pos, name = item[1], item[2]
            if name in api_addresses:
                code[pos:pos+4] = struct.pack('<I', api_addresses[name])
            elif name in string_addresses:
                code[pos:pos+4] = struct.pack('<I', string_addresses[name])
            elif name in labels:
                code[pos:pos+4] = struct.pack('<I', labels[name])
            else:
                raise ValueError(f"Unknown fixup target: {name}")
            fixups.remove(item)
        elif isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], int):
            pos, label = item
            # 处理特殊标签 "$"（表示当前地址）
            if label == "$":
                target = pos  # 跳转到当前指令位置（即无限循环）
            # 处理模块函数调用
            elif "." in label:
                module_name, func_name = label.split(".", 1)
                if module_name not in modules:
                    raise ValueError(f"Unknown module in fixups: {module_name}")
                if func_name not in modules[module_name]['functions']:
                    raise ValueError(f"Unknown function {func_name} in module {module_name}")
                target = modules[module_name]['functions'][func_name][0]
            # 处理普通标签
            elif label not in labels:
                raise ValueError("Unknown label in fixups: " + label)
            else:
                target = labels[label]
            
            # E8 rel32 at pos: code[pos] == 0xE8 ; rel = target - (pos + 5)
            if code[pos] == 0xE8:  # call指令
                rel = target - (pos + 5)
                code[pos+1:pos+5] = struct.pack("<i", rel)
            # E9 rel32 at pos: code[pos] == 0xE9 ; rel = target - (pos + 5)
            elif code[pos] == 0xE9:  # jmp指令
                rel = target - (pos + 5)
                code[pos+1:pos+5] = struct.pack("<i", rel)
            # 0F 84 rel32 at pos: jz指令
            elif code[pos] == 0x0F and code[pos+1] == 0x84:  # jz指令
                rel = target - (pos + 6)
                code[pos+2:pos+6] = struct.pack("<i", rel)
            # 0F 85 rel32 at pos: jnz指令
            elif code[pos] == 0x0F and code[pos+1] == 0x85:  # jnz指令
                rel = target - (pos + 6)
                code[pos+2:pos+6] = struct.pack("<i", rel)
            # 0F 8F rel32 at pos: jg指令
            elif code[pos] == 0x0F and code[pos+1] == 0x8F:  # jg指令
                rel = target - (pos + 6)
                code[pos+2:pos+6] = struct.pack("<i", rel)
            
            fixups.remove(item)
    
    # === 修复 fixups ===
    for kind, pos, target in fixups:
        if kind == "call":
            # 内部函数调用
            if target not in labels:
                raise ValueError(f"Undefined function label: {target}")
            addr = labels[target]
            rel = addr - (pos + 5)  # E8 相对跳转，修正偏移计算
            code[pos:pos+5] = b'\xe8' + struct.pack("<i", rel)
        elif kind == "jmp":
            # 无条件跳转
            if target not in labels:
                raise ValueError(f"Undefined label: {target}")
            addr = labels[target]
            rel = addr - (pos + 5)  # E9 相对跳转，修正偏移计算
            code[pos:pos+5] = b'\xe9' + struct.pack("<i", rel)
        elif kind == "jz":
            # 条件跳转 (等于)
            if target not in labels:
                raise ValueError(f"Undefined label: {target}")
            addr = labels[target]
            rel = addr - (pos + 6)  # 0F 84 相对跳转，修正偏移计算
            code[pos:pos+6] = b'\x0f\x84' + struct.pack("<i", rel)
        elif kind == "jnz":
            # 条件跳转 (不等于)
            if target not in labels:
                raise ValueError(f"Undefined label: {target}")
            addr = labels[target]
            rel = addr - (pos + 6)  # 0F 85 相对跳转，修正偏移计算
            code[pos:pos+6] = b'\x0f\x85' + struct.pack("<i", rel)
        elif kind == "jg":
            # 条件跳转 (大于)
            if target not in labels:
                raise ValueError(f"Undefined label: {target}")
            addr = labels[target]
            rel = addr - (pos + 6)  # 0F 8F 相对跳转，修正偏移计算
            code[pos:pos+6] = b'\x0f\x8f' + struct.pack("<i", rel)
        elif kind == "fixup":
            # 外部函数调用（API）
            if target in api_addresses:
                addr = api_addresses[target]
                code[pos:pos+4] = struct.pack("<I", addr)
            elif target in string_addresses:
                addr = string_addresses[target]
                code[pos:pos+4] = struct.pack("<I", addr)
            else:
                raise ValueError(f"Undefined extern function or string: {target}")
        else:
            raise ValueError(f"Unknown fixup type: {kind}")

    # 返回生成的PE文件，传递机器类型
    return make_pe(code, data, machine_type)