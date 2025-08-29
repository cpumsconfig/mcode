# -*- coding: utf-8 -*-
import struct

BASE_ADDR = 0x08048000
ENTRY_ADDR = BASE_ADDR + 0x54 + 0x20

def make_elf(payload: bytes, data: bytes) -> bytes:
    elf_header = b'\x7fELF' + b'\x01\x01\x01' + b'\x00'*9
    elf_header += struct.pack('<H',2) + struct.pack('<H',3) + struct.pack('<I',1)
    elf_header += struct.pack('<I',ENTRY_ADDR) + struct.pack('<I',52)
    elf_header += struct.pack('<I',0) + struct.pack('<I',0)
    elf_header += struct.pack('<H',52) + struct.pack('<H',32)
    elf_header += struct.pack('<H',1) + struct.pack('<H',0)*3

    total = len(elf_header)+32+len(payload)+len(data)
    ph = struct.pack('<I',1)+struct.pack('<I',0)
    ph+=struct.pack('<I',BASE_ADDR)*2
    ph+=struct.pack('<I',total)+struct.pack('<I',total)
    ph+=struct.pack('<I',5)+struct.pack('<I',0x1000)
    return elf_header+ph+payload+data

def gen_linux(stmts):
    variables, data, code, labels = {}, b"", b"", {}
    data_base = 0x08049000
    def add_string(s):
        nonlocal data
        addr = data_base+len(data)
        data += s.encode()+b"\n"
        return addr, len(s)+1
    def emit(b): nonlocal code; code+=b
    for st in stmts:
        if st[0]=="let":
            variables[st[1]]=st[2]
        elif st[0]=="print_str":
            addr,len_=add_string(st[1])
            emit(b"\xb8\x04\x00\x00\x00") # mov eax,4
            emit(b"\xbb\x01\x00\x00\x00") # mov ebx,1
            emit(b"\xb9"+struct.pack("<I",addr))
            emit(b"\xba"+struct.pack("<I",len_))
            emit(b"\xcd\x80")
        elif st[0]=="print_var":
            s=str(variables[st[1]])
            addr,len_=add_string(s)
            emit(b"\xb8\x04\x00\x00\x00")
            emit(b"\xbb\x01\x00\x00\x00")
            emit(b"\xb9"+struct.pack("<I",addr))
            emit(b"\xba"+struct.pack("<I",len_))
            emit(b"\xcd\x80")
        elif st[0]=="exit":
            emit(b"\xb8\x01\x00\x00\x00")
            emit(b"\xbb"+struct.pack("<I",st[1]))
            emit(b"\xcd\x80")
        elif st[0] == "asm":
            # 直接嵌入汇编代码的字节
            for byte in st[1].split():
                emit(bytes([int(byte, 16)]))
        elif st[0] == "if":
            # 比较变量值是否为真（非零）
            emit(b'\x8b\x05' + struct.pack('<I', variables[st[1]]))
            emit(b'\x85\xc0')  # test eax, eax
            emit(b'\x0f\x84' + struct.pack('<i', labels[st[2]] - (len(code) + 6)))  # jz label

        elif st[0] == "elif":
            emit(b'\x8b\x05' + struct.pack('<I', variables[st[1]]))
            emit(b'\x85\xc0')
            emit(b'\x0f\x85' + struct.pack('<i', labels[st[2]] - (len(code) + 6)))  # jnz label

        elif st[0] == "else":
            emit(b'\xe9' + struct.pack('<i', labels[st[1]] - (len(code) + 5)))  # jmp label

        elif st[0] == "op":
            # 为所有变量分配内存（如果尚未分配）
            for var in [st[1], st[2], st[4]]:
                if var not in variables:
                    variables[var] = len(data)
                    data += b'\x00\x00\x00\x00'
            
            # 加载第一个操作数
            emit(b'\x8b\x05' + struct.pack('<I', variables[st[2]]))
            
            # 根据运算符类型执行相应操作
            if st[3] == '+':
                emit(b'\x03\x05' + struct.pack('<I', variables[st[4]]))  # add eax, [var3]
            elif st[3] == '-':
                emit(b'\x2b\x05' + struct.pack('<I', variables[st[4]]))  # sub eax, [var3]
            elif st[3] == '*':
                emit(b'\xf7\x25' + struct.pack('<I', variables[st[4]]))  # imul eax, [var3]
            elif st[3] == '/':
                emit(b'\x99')  # cdq
                emit(b'\xf7\x3d' + struct.pack('<I', variables[st[4]]))  # idiv [var3]
            
            # 存储结果
            emit(b'\xa3' + struct.pack('<I', variables[st[1]]))

    return make_elf(code,data)
