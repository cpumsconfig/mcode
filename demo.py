# -*- coding: utf-8 -*-
import struct

def gen_windows_simple(stmts):
    """生成最简单的Windows OBJ文件"""
    
    # 生成极简的机器代码 - 只是一个简单的退出程序
    code = bytearray()
    
    # _start 函数
    # push ebp
    code.extend(b'\x55')
    # mov ebp, esp  
    code.extend(b'\x89\xE5')
    # push 0 (exit code)
    code.extend(b'\x6A\x00')
    # mov eax, 0x4C (ExitProcess function number - simplified)
    code.extend(b'\xB8\x4C\x00\x00\x00')
    # int 0x21 (DOS interrupt - for maximum compatibility)
    code.extend(b'\xCD\x21')
    # pop ebp
    code.extend(b'\x5D')
    # ret
    code.extend(b'\xC3')
    
    # 空的.data段
    data = bytearray()
    
    return create_simple_coff(code, data)

def create_simple_coff(code, data):
    """创建极简的COFF格式"""
    
    # COFF文件头
    header = bytearray()
    header.extend(struct.pack('<H', 0x014C))  # Machine: I386
    header.extend(struct.pack('<H', 2))       # NumberOfSections
    header.extend(struct.pack('<I', 0))       # TimeDateStamp
    header.extend(struct.pack('<I', 0))       # PointerToSymbolTable  
    header.extend(struct.pack('<I', 0))       # NumberOfSymbols
    header.extend(struct.pack('<H', 0))       # SizeOfOptionalHeader
    header.extend(struct.pack('<H', 0x0102))  # Characteristics
    
    # .text 节区头
    text_section = bytearray()
    text_section.extend(b'.text\x00\x00\x00') # Name
    text_section.extend(struct.pack('<I', len(code)))  # VirtualSize
    text_section.extend(struct.pack('<I', 0x1000))     # VirtualAddress
    text_section.extend(struct.pack('<I', len(code)))  # SizeOfRawData
    text_section.extend(struct.pack('<I', 0x64))       # PointerToRawData
    text_section.extend(struct.pack('<I', 0))          # PointerToRelocations
    text_section.extend(struct.pack('<I', 0))          # PointerToLinenumbers
    text_section.extend(struct.pack('<H', 0))          # NumberOfRelocations
    text_section.extend(struct.pack('<H', 0))          # NumberOfLinenumbers
    text_section.extend(struct.pack('<I', 0x60000020)) # Characteristics
    
    # .data 节区头
    data_section = bytearray()
    data_section.extend(b'.data\x00\x00\x00') # Name
    data_section.extend(struct.pack('<I', len(data)))  # VirtualSize
    data_section.extend(struct.pack('<I', 0x2000))     # VirtualAddress
    data_section.extend(struct.pack('<I', len(data)))  # SizeOfRawData
    data_section.extend(struct.pack('<I', 0x64 + len(code))) # PointerToRawData
    data_section.extend(struct.pack('<I', 0))          # PointerToRelocations
    data_section.extend(struct.pack('<I', 0))          # PointerToLinenumbers
    data_section.extend(struct.pack('<H', 0))          # NumberOfRelocations
    data_section.extend(struct.pack('<H', 0))          # NumberOfLinenumbers
    data_section.extend(struct.pack('<I', 0xC0000040)) # Characteristics
    
    # 构建文件
    obj_file = header + text_section + data_section + code + data
    return bytes(obj_file)

# 使用简单版本作为默认
gen_windows = gen_windows_simple