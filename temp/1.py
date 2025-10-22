# -*- coding: utf-8 -*-
import sys, struct, re
import os

# -----------------------
# Lexer
# -----------------------
def tokenize(src: str):
    # 支持行末 \ 续行
    src = src.replace("\\\n", " ")
    # 先处理注释：移除#号到行尾的内容
    lines = src.split('\n')
    processed_lines = []
    for line in lines:
        if '#' in line:
            line = line[:line.index('#')]
        processed_lines.append(line)
    src = '\n'.join(processed_lines)
    
    tokens, cur, s = [], "", False
    for c in src:
        if c == '"':
            s = not s
            cur += c
            if not s:
                tokens.append(cur)
                cur = ""
        elif c.isspace() and not s:
            if cur: tokens.append(cur); cur = ""
        else:
            cur += c
    if cur: tokens.append(cur)
    return tokens

# -----------------------
# Parser
# -----------------------
def parse(tokens):
    stmts, i, variables = [], 0, {}  # 添加variables字典初始化
    while i < len(tokens):
        t = tokens[i]

        if t == "int":  # 变量声明
            name = tokens[i+1]
            if tokens[i+2] != '=':
                raise SyntaxError("缺少等号")
            
            # 支持表达式（最多3个token: A op B）
            expr_tokens = []
            j = i+3
            while j < len(tokens) and tokens[j] not in ["int", "print", "exit", "execute", "sa", "tm", "org", "def", "jmp", "bpb", "asm", "if", "elif", "else"]:
                expr_tokens.append(tokens[j])
                j += 1
            
            if len(expr_tokens) == 1:  # 单个值
                try:
                    value = int(expr_tokens[0], 0)
                except ValueError:
                    if expr_tokens[0] in variables:
                        value = variables[expr_tokens[0]]
                    else:
                        raise NameError(f"未定义的变量: {expr_tokens[0]}")
            elif len(expr_tokens) == 3:  # A op B
                op = expr_tokens[1]
                try:
                    left = int(expr_tokens[0], 0)
                except:
                    if expr_tokens[0] in variables:
                        left = variables[expr_tokens[0]]
                    else:
                        raise NameError(f"未定义的变量: {expr_tokens[0]}")
                
                try:
                    right = int(expr_tokens[2], 0)
                except:
                    if expr_tokens[2] in variables:
                        right = variables[expr_tokens[2]]
                    else:
                        raise NameError(f"未定义的变量: {expr_tokens[2]}")
                
                if op == "+": value = left + right
                elif op == "-": value = left - right
                elif op == "*": value = left * right
                elif op == "/": 
                    if right == 0:
                        raise ValueError("除零错误")
                    value = left // right
                else: raise SyntaxError(f"不支持的运算符: {op}")
            else:
                raise SyntaxError("无效的表达式")
            
            stmts.append(("let", name, value))
            variables[name] = value
            i = j

        elif t == "print":
            arg = tokens[i+1]
            if arg.startswith('"'):
                stmts.append(("print_str", arg.strip('"')))
            else:
                stmts.append(("print_var", arg))
            i += 2

        elif t == "exit":
            stmts.append(("exit", int(tokens[i+1],0)))
            i += 2

        elif t in ["ax","bx","cx","dx","al","bl","cl","dl","ah","bh","ch","dh"]:
            if tokens[i+1] != "=": raise SyntaxError("寄存器赋值必须使用 '='")
            val = int(tokens[i+2],0)
            stmts.append(("mov", t, val))
            i += 3

        elif t == "execute":
            stmts.append(("int", int(tokens[i+1],0)))
            i += 2

        elif t == "sa":
            values = [int(x,0) for x in tokens[i+1].split(",")]
            stmts.append(("sa", values))
            i += 2

        elif t == "tm":
            if tokens[i+1].endswith("-$"):
                target = int(tokens[i+1].split("-")[0],0)
                stmts.append(("tm", target))
            else:
                raise SyntaxError("tm 语法错误，必须 tm N-$")
            i += 2

        elif t == "org":
            stmts.append(("org", int(tokens[i+1],0)))
            i += 2

        elif t == "def":
            stmts.append(("label", tokens[i+1].rstrip(":")))
            i += 2

        elif t == "jmp":
            stmts.append(("jmp", tokens[i+1]))
            i += 2

        elif t == "set_fat12_BPB":
            values = []
            for j in range(1,20):
                values.append(tokens[i+j])
            stmts.append(("bpb", values))
            i += 20
        elif t == "asm":
            # 提取引号内的汇编代码
            asm_code = tokens[i+1].strip('"')
            stmts.append(("asm", asm_code))
            i += 2
        elif t == "if":
            # if condition : label
            condition = tokens[i+1]
            label = tokens[i+3]
            stmts.append(("if", condition, label))
            i += 4

        elif t == "elif":
            # elif condition : label
            condition = tokens[i+1]
            label = tokens[i+3]
            stmts.append(("elif", condition, label))
            i += 4

        elif t == "else":
            # else : label
            label = tokens[i+2]
            stmts.append(("else", label))
            i += 3

        elif t in ["+", "-", "*", "/"]:
            # 运算符处理: var1 = var2 op var3
            var1 = tokens[i-1]
            var2 = tokens[i+1]
            op = t
            var3 = tokens[i+3]
            stmts.append(("op", var1, var2, op, var3))
            i += 4
        elif t == "beep":
            freq = int(tokens[i+1], 0)
            stmts.append(("beep", freq))
            i += 2

        else:
            raise SyntaxError(f"未知语句: {t}")
    return stmts

# -----------------------
# Linux ELF 后端
# -----------------------
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

# -----------------------
# BIOS BIN 后端
# -----------------------
def gen_bios(stmts):
    variables, code, data, labels, fixups = {}, b"", b"", {}, []
    
    def emit(b): nonlocal code; code+=b
    
    for st in stmts:
        if st[0]=="let":
            variables[st[1]]=st[2]
        
        elif st[0]=="print_str":
            for ch in st[1]+"\n":
                emit(b"\xb4\x0e")
                emit(b"\xb0"+bytes([ord(ch)]))
                emit(b"\xcd\x10")
        
        elif st[0]=="print_var":
            value = variables[st[1]]  # 直接获取变量值
            
            # 将数字转换为字符串
            s = str(value)
            for char in s:
                emit(b"\xb4\x0e")        # mov ah, 0x0E
                emit(bytes([0xb0, ord(char)]))  # mov al, 'char'
                emit(b"\xcd\x10")        # int 0x10
        
        elif st[0]=="exit":
            emit(b"\xf4\xeb\xfe")
        elif st[0]=="mov":
            reg,val=st[1],st[2]
            regmap8 = {"al":0xb0,"bl":0xb3,"cl":0xb1,"dl":0xb2}
            regmap16= {"ax":0xb8,"bx":0xbb,"cx":0xb9,"dx":0xba}
            if reg in regmap8:
                emit(bytes([regmap8[reg]])+bytes([val&0xff]))
            elif reg in regmap16:
                emit(bytes([regmap16[reg]])+struct.pack("<H",val))
        elif st[0]=="int":
            emit(b"\xcd"+bytes([st[1]]))
        elif st[0]=="sa":
            for v in st[1]:
                data += bytes([v])
        elif st[0]=="tm":
            target=st[1]
            padlen=target-(len(code)+len(data))
            if padlen>0: data+=b"\x00"*padlen
            data+=b"\x55\xaa"
        elif st[0]=="org":
            pass
        elif st[0]=="label":
            labels[st[1]]=len(code)
        elif st[0]=="jmp":
            fixups.append((len(code),st[1]))
            emit(b"\xe9\x00\x00")
        elif st[0]=="bpb":
            vals=[int(v,0) for v in st[1]]
            # 写入简化BPB
            bpb = struct.pack("<H", vals[0])+struct.pack("<H",vals[1])
            data+=bpb
        elif st[0] == "asm":
            # 直接嵌入汇编代码的字节
            for byte in st[1].split():
                emit(bytes([int(byte, 16)]))
        elif st[0] == "if":
            emit(b'\x8b\x05' + struct.pack('<I', variables[st[1]]))
            emit(b'\x85\xc0')
            emit(b'\x0f\x84' + struct.pack('<i', labels[st[2]] - (len(code) + 6)))

        elif st[0] == "elif":
            emit(b'\x8b\x05' + struct.pack('<I', variables[st[1]]))
            emit(b'\x85\xc0')
            emit(b'\x0f\x85' + struct.pack('<i', labels[st[2]] - (len(code) + 6)))

        elif st[0] == "else":
            emit(b'\xe9' + struct.pack('<i', labels[st[1]] - (len(code) + 5)))

        elif st[0] == "op":
            # 为所有变量分配内存（如果尚未分配）
            for var in [st[1], st[2], st[4]]:
                if var not in variables:
                    variables[var] = len(data)
                    data += b'\x00\x00\x00\x00'
            
            # 处理常量
            try:
                val2 = int(st[2])
                emit(b'\xb8' + struct.pack('<I', val2))  # mov eax, immediate
            except ValueError:
                emit(b'\xb8' + struct.pack('<I', variables[st[2]]))  # mov eax, [var2]
                emit(b'\x8b\x00')  # mov eax, [eax]
            
            try:
                val3 = int(st[4])
                emit(b'\xbb' + struct.pack('<I', val3))  # mov ebx, immediate
            except ValueError:
                emit(b'\xbb' + struct.pack('<I', variables[st[4]]))  # mov ebx, [var3]
                emit(b'\x8b\x1b')  # mov ebx, [ebx]
            
            # 根据运算符类型执行相应操作
            if st[3] == '+':
                emit(b'\x01\xd8')  # add eax, ebx
            elif st[3] == '-':
                emit(b'\x29\xd8')  # sub eax, ebx
            elif st[3] == '*':
                emit(b'\xf7\xe3')  # mul ebx
            elif st[3] == '/':
                emit(b'\x99')     # cdq
                emit(b'\xf7\xf3') # div ebx
            
            # 存储结果
            emit(b'\xa3' + struct.pack('<I', variables[st[1]]))
        elif st[0] == "beep":
            # 设置定时器2来产生声音
            emit(b'\xb0\xb6')          # mov al, 0xB6
            emit(b'\xe6\x43')          # out 43h, al
            # 设置频率
            freq = st[1]
            divisor = 1193180 // freq  # 计算分频值
            emit(b'\xb0' + bytes([divisor & 0xFF]))     # mov al, divisor低字节
            emit(b'\xe6\x42')          # out 42h, al
            emit(b'\xb0' + bytes([(divisor >> 8) & 0xFF]))  # mov al, divisor高字节
            emit(b'\xe6\x42')          # out 42h, al
            # 打开扬声器
            emit(b'\xb0\x03')          # mov al, 3
            emit(b'\xe6\x61')          # out 61h, al
            # 延时
            emit(b'\xb9\x00\x01')      # mov cx, 256
            emit(b'\xb8\x00\x86')      # mov ax, 34304
            emit(b'\x48')              # dec ax
            emit(b'\x85\xc0')          # test ax, ax
            emit(b'\x75\xfb')          # jnz -5
            emit(b'\x49')              # dec cx
            emit(b'\x85\xc9')          # test cx, cx
            emit(b'\x75\xf4')          # jnz -10
            # 关闭扬声器
            emit(b'\xb0\x00')          # mov al, 0
            emit(b'\xe6\x61')          # out 61h, al


    # 回填 jmp
    for pos,label in fixups:
        target=labels[label]
        rel=target-(pos+2)
        code=code[:pos+1]+struct.pack("<h",rel)+code[pos+3:]
    return code+data

# -----------------------
# 主程序
# -----------------------
if __name__=="__main__":
    if len(sys.argv)<3:
        print("用法: mcd.exe source.m --target=linux|bios")
        sys.exit(1)
    if not os.path.exists(sys.argv[1]):
        print(f"错误: 源文件 '{sys.argv[1]}' 不存在")
        sys.exit(1)
    with open(sys.argv[1], encoding="utf-8") as f:
        src=f.read()
    tokens=tokenize(src)
    stmts=parse(tokens)
    if sys.argv[2]=="--target=linux":
        out=gen_linux(stmts)
        fname="out"
    elif sys.argv[2]=="--target=bios":
        out=gen_bios(stmts)
        fname="out.bin"
    else:
        raise ValueError("目标必须是 linux 或 bios")
    with open(fname,"wb") as f: f.write(out)
    print("编译完成:",fname)