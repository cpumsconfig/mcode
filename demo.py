import struct

# 常量
SECTION_ALIGNMENT = 0x1000
FILE_ALIGNMENT    = 0x200

def align_up(x, align):
    return (x + align - 1) & ~(align - 1)

# ========== 代码生成 ==========
def gen_windows(init_window: bool):
    if not init_window:
        # 简单: xor eax,eax; ret
        return b"\x31\xc0\xc3"
    else:
        # 调用 MessageBoxA + ExitProcess
        #
        # push 0
        # push offset caption
        # push offset text
        # push 0
        # call [MessageBoxA]
        # push 0
        # call [ExitProcess]
        #
        code  = b"\x6A\x00"                  # push 0
        code += b"\x68\x20\x10\x00\x00"      # push offset caption (0x1020)
        code += b"\x68\x30\x10\x00\x00"      # push offset text (0x1030)
        code += b"\x6A\x00"                  # push 0
        code += b"\xFF\x15\x40\x10\x00\x00"  # call [0x1040] = MessageBoxA
        code += b"\x6A\x00"                  # push 0
        code += b"\xFF\x15\x44\x10\x00\x00"  # call [0x1044] = ExitProcess
        return code

# ========== PE Header 生成 ==========
def create_optional_header(entry_point_rva, code_rva, code_size, image_size, import_rva, import_size, subsystem):
    # Standard PE optional header fields
    return struct.pack(
        "<HBBIIIIIIIIHHHHHHIIIIHHIIIII",  # 修改这里，减少一个I
        0x10b,   # Magic PE32
        8,       # MajorLinkerVersion
        0,       # MinorLinkerVersion
        code_size,  # SizeOfCode
        0,       # SizeOfInitializedData
        0,       # SizeOfUninitializedData
        entry_point_rva,  # AddressOfEntryPoint
        code_rva,  # BaseOfCode
        0,       # BaseOfData (not used in PE32+)
        0x400000,  # ImageBase
        SECTION_ALIGNMENT,  # SectionAlignment
        FILE_ALIGNMENT,  # FileAlignment
        4,       # MajorOperatingSystemVersion
        0,       # MinorOperatingSystemVersion
        0,       # MajorImageVersion
        0,       # MinorImageVersion
        4,       # MajorSubsystemVersion
        0,       # MinorSubsystemVersion
        0,       # Win32VersionValue
        image_size,  # SizeOfImage
        FILE_ALIGNMENT,  # SizeOfHeaders
        0,       # CheckSum
        subsystem,  # Subsystem
        0x8140,  # DllCharacteristics
        0x100000,  # SizeOfStackReserve
        0x1000,  # SizeOfStackCommit
        0x100000,  # SizeOfHeapReserve
        0x1000,  # SizeOfHeapCommit
        0,       # LoaderFlags
        16       # NumberOfRvaAndSizes
    ) + struct.pack("<" + "II"*16,
        import_rva, import_size,  # Import Directory
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    )



# ========== 顶层封装 ==========
def make_pe(init_window: bool):
    code = gen_windows(init_window)
    code_rva   = SECTION_ALIGNMENT
    entry_rva  = code_rva
    code_size  = align_up(len(code), FILE_ALIGNMENT)
    image_size = SECTION_ALIGNMENT*2

    # 简化 Import 表 RVA/Size
    import_rva  = SECTION_ALIGNMENT*2
    import_size = 0x40

    subsystem = 2 if init_window else 3

    opt = create_optional_header(entry_rva, code_rva, code_size, image_size, import_rva, import_size, subsystem)
    # TODO: 拼接 DOS Header + NT Header + Section Header + code + import

    return b"MZ..."  # (这里省略完整拼接)

# 调用
with open("m.exe", "wb") as f:
    f.write(make_pe(init_window=True))
