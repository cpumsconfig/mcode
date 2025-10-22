import struct

# 常量定义
IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_32BIT_MACHINE = 0x0100
IMAGE_SUBSYSTEM_WINDOWS_GUI = 0x2

FILE_ALIGNMENT = 0x200        # 标准文件对齐（512字节）
SECTION_ALIGNMENT = 0x1000    # 标准内存对齐（4096字节）

# 修正后的汇编代码（正确调用MessageBoxA和ExitProcess）
# 逻辑：压入MessageBoxA参数（hWnd=0, lpText=0x40200E, lpCaption=0x402000, uType=0）
# 调用MessageBoxA后压入ExitProcess参数（0），调用ExitProcess
code = (b'\x55\x8B\xEC'                                  # 栈帧初始化
        b'\x6A\x00'                                      # push 0 (uType)
        b'\x68\x0E\x20\x40\x00'                          # push 0x40200E (lpText="Hello World")
        b'\x68\x00\x20\x40\x00'                          # push 0x402000 (lpCaption="Message")
        b'\x6A\x00'                                      # push 0 (hWnd)
        b'\xFF\x15\x04\x10\x40\x00'                      # call dword ptr [0x401004] (MessageBoxA的IAT地址)
        b'\x6A\x00'                                      # push 0 (ExitCode)
        b'\xFF\x15\x00\x10\x40\x00'                      # call dword ptr [0x401000] (ExitProcess的IAT地址)
        b'\x33\xC0\x5D\xC3'                              # 清理并返回
        b'Message\x00'                                   # lpCaption (0x402000)
        b'Hello World\x00')                              # lpText (0x40200E)

# ----------------构建PE结构----------------

# 1. DOS头 (IMAGE_DOS_HEADER)
dos_header = struct.pack(
    '=HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHI',  # 30个H + 1个I
    IMAGE_DOS_SIGNATURE,  # e_magic
    0,0,0,0,0,0,0,0,0,0,0,0,0,  # 未使用字段
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,  # 未使用字段
    0x80  # e_lfanew: 调整PE头偏移（确保头部对齐）
)

# DOS stub（长度固定为0x40字节，确保总DOS部分为0x80字节）
dos_stub = b'This program cannot be run in DOS mode.\r\n$' + b'\x00' * (0x40 - 34)  # 总长度0x40

# 2. PE头 (IMAGE_NT_HEADERS)
pe_signature = struct.pack('<I', IMAGE_NT_SIGNATURE)

# 文件头 (IMAGE_FILE_HEADER)
file_header = struct.pack(
    '<HHIIIHH',
    IMAGE_FILE_MACHINE_I386,
    2,  # 节区数量
    0x5F8A5E80,  # 时间戳
    0,0,  # 符号表（未使用）
    0xE0,  # 可选头大小（32位标准）
    IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE
)

# 可选头 (IMAGE_OPTIONAL_HEADER32)
optional_header = struct.pack(
    '<HBBIIIIIIIIHHHHHHIIIIHHIIIIIII',
    0x10b,  # 32位PE
    0x0A, 0x00,  # 链接器版本
    ((len(code) + FILE_ALIGNMENT - 1) // FILE_ALIGNMENT) * FILE_ALIGNMENT,  # SizeOfCode
    0,0,  # 初始化/未初始化数据大小
    0x1000,  # 入口点RVA（.text节）
    0x1000,  # 代码节基址RVA
    0x2000,  # 数据节基址RVA
    0x400000,  # 加载基址
    SECTION_ALIGNMENT,
    FILE_ALIGNMENT,
    5,1,  # 最低系统版本（5.1=XP）
    1,0,  # 镜像版本
    5,1,  # 子系统版本
    0,  # 版本值
    0x3000,  # 镜像总大小
    0x400,  # 头部总大小（对齐后）
    0,  # 校验和
    IMAGE_SUBSYSTEM_WINDOWS_GUI,
    0x8160,  # DLL特性（动态基址+NX兼容）
    0x100000, 0x1000,  # 栈大小
    0x100000, 0x1000,  # 堆大小
    0,  # 加载器标志
    16  # 数据目录数量
)

# 数据目录（仅设置导入表）
import_table_rva = 0x2000  # 导入表在.rdata节的RVA
import_table_size = 0x30   # 导入表大小（3个描述符×20字节）
data_directories = struct.pack('<II', import_table_rva, import_table_size) + b'\x00'*(8*15)
optional_header += data_directories

pe_header = pe_signature + file_header + optional_header  # PE头总长度：4+20+224=248字节

# 3. 节表 (IMAGE_SECTION_HEADER)
# .text节（代码）
text_header = struct.pack(
    '<8sIIIIIIIII',  # 10个字段（8s+9I）
    b'.text\x00\x00',
    len(code),  # VirtualSize
    0x1000,     # VirtualAddress
    ((len(code) + FILE_ALIGNMENT - 1) // FILE_ALIGNMENT) * FILE_ALIGNMENT,  # SizeOfRawData
    0x400,      # PointerToRawData（头部对齐后偏移）
    0,0,0,0,    # 重定位等（未使用）
    0x60000020  # 可执行+可读+代码
)

# .rdata节（导入表+字符串）
rdata_size = 0x100  # 实际数据大小
rdata_raw_size = ((rdata_size + FILE_ALIGNMENT - 1) // FILE_ALIGNMENT) * FILE_ALIGNMENT
rdata_header = struct.pack(
    '<8sIIIIIIIII',
    b'.rdata\x00\x00',
    rdata_size,
    0x2000,     # VirtualAddress
    rdata_raw_size,
    0x600,      # PointerToRawData（.text节之后）
    0,0,0,0,
    0x40000040  # 可读+已初始化数据
)

section_table = text_header + rdata_header  # 节表总长度：2×40=80字节

# 4. 节数据
# .text节数据（代码+对齐填充）
text_data = code.ljust(((len(code) + FILE_ALIGNMENT - 1) // FILE_ALIGNMENT) * FILE_ALIGNMENT, b'\x00')

# .rdata节数据（导入表+IAT+字符串）
# 导入描述符（每个20字节，最后以全0结束）
import_descriptor_kernel32 = struct.pack('<IIIII',
    0x2010,  # OriginalFirstThunk（指向INT）
    0,       # TimeDateStamp
    0,       # ForwarderChain
    0x2020,  # Name（"kernel32.dll"的RVA）
    0x1000   # FirstThunk（指向IAT）
)
import_descriptor_user32 = struct.pack('<IIIII',
    0x2018,  # OriginalFirstThunk
    0,
    0,
    0x202E,  # Name（"user32.dll"的RVA）
    0x1004   # FirstThunk
)
import_descriptor_null = b'\x00'*20  # 结束标志
import_table = import_descriptor_kernel32 + import_descriptor_user32 + import_descriptor_null

# 导入名称表（INT）和导入地址表（IAT）
int_exitprocess = struct.pack('<I', 0x80000000 | 0x2038)  # 函数名偏移（带标志）
int_messagebox = struct.pack('<I', 0x80000000 | 0x2046)
iat_exitprocess = struct.pack('<I', 0)  # 运行时由加载器填充地址
iat_messagebox = struct.pack('<I', 0)
int_data = int_exitprocess + int_messagebox
iat_data = iat_exitprocess + iat_messagebox

# DLL名称和函数名
dll_names = b'kernel32.dll\x00user32.dll\x00'
func_names = b'ExitProcess\x00MessageBoxA\x00'

# 拼接.rdata数据并对齐
rdata_data = import_table + int_data + iat_data + dll_names + func_names
rdata_data = rdata_data.ljust(rdata_raw_size, b'\x00')

# ----------------写入文件----------------
with open('main.exe', 'wb') as f:
    # 写入DOS部分（DOS头+stub，共0x80字节）
    f.write(dos_header)
    f.write(dos_stub)
    
    # 写入PE头和节表（从0x80偏移开始）
    f.seek(0x80)
    f.write(pe_header)
    f.write(section_table)
    
    # 填充头部到0x400（size_of_headers）
    f.seek(0x400)
    
    # 写入.text节（0x400偏移）
    f.write(text_data)
    
    # 写入.rdata节（0x600偏移）
    f.write(rdata_data)

print("修正后PE文件生成成功：main.exe")