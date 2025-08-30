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
    
    # 添加模块系统相关数据结构
    modules = {}        # 已导入的模块
    global_funcs = {}   # 全局函数：name -> (code_offset, param_count)
    extern_funcs = {}   # 外部函数：name -> (module_name, func_name)
    fixups = []         # 用于修复跳转和调用
    
    def add_string(s):
        nonlocal data
        addr = data_base+len(data)
        data += s.encode()+b"\n"
        return addr, len(s)+1
        
    def emit(b): 
        nonlocal code
        code+=b
        
    def emit_data(b):
        nonlocal data
        data += b
        
    def new_label(base="L"):
        nonlocal labels
        label_id = len(labels)
        return f"{base}{label_id}"
        
    # 添加process_statement函数定义
    def process_statement(st):
        t = st[0]  # 获取语句类型
        
        if t == "let":
            # st = ("let", name, value)
            name, val = st[1], st[2]
            try:
                ival = int(val)
                variables[name] = ('const', ival)
            except Exception:
                # 分配内存变量
                variables[name] = ('mem', len(data))
                data += b'\x00\x00\x00\x00'
                
        elif t == "print_str":
            s = st[1] + "\n"
            addr, len_ = add_string(s)
            emit(b"\xb8\x04\x00\x00\x00") # mov eax,4
            emit(b"\xbb\x01\x00\x00\x00") # mov ebx,1
            emit(b"\xb9"+struct.pack("<I",addr))
            emit(b"\xba"+struct.pack("<I",len_))
            emit(b"\xcd\x80")
            
        elif t == "print_var":
            var_name = st[1]
            typ, val = variables[var_name]
            if typ == 'const':
                s = str(val)
            else:
                # 从内存中读取值
                s = str(struct.unpack('<I', data[val:val+4])[0])
            addr, len_ = add_string(s)
            emit(b"\xb8\x04\x00\x00\x00")
            emit(b"\xbb\x01\x00\x00\x00")
            emit(b"\xb9"+struct.pack("<I",addr))
            emit(b"\xba"+struct.pack("<I",len_))
            emit(b"\xcd\x80")
            
        elif t == "exit":
            emit(b"\xb8\x01\x00\x00\x00")
            emit(b"\xbb"+struct.pack("<I",st[1]))
            emit(b"\xcd\x80")
            
        elif t == "mov":
            # ("mov", reg, val)
            reg, val = st[1], st[2]
            # 如果val是整数，则直接使用；如果是变量名，则加载其值
            try:
                ival = int(val)
                # 根据寄存器类型生成不同的mov指令
                if reg == "eax":
                    emit(b'\xb8' + struct.pack('<I', ival))
                elif reg == "ebx":
                    emit(b'\xbb' + struct.pack('<I', ival))
                elif reg == "ecx":
                    emit(b'\xb9' + struct.pack('<I', ival))
                elif reg == "edx":
                    emit(b'\xba' + struct.pack('<I', ival))
                elif reg == "esi":
                    emit(b'\xbe' + struct.pack('<I', ival))
                elif reg == "edi":
                    emit(b'\xbf' + struct.pack('<I', ival))
                elif reg == "esp":
                    emit(b'\xbc' + struct.pack('<I', ival))
                elif reg == "ebp":
                    emit(b'\xbd' + struct.pack('<I', ival))
                elif reg == "al":
                    emit(b'\xb0' + bytes([ival & 0xff]))
                elif reg == "bl":
                    emit(b'\xb3' + bytes([ival & 0xff]))
                elif reg == "cl":
                    emit(b'\xb1' + bytes([ival & 0xff]))
                elif reg == "dl":
                    emit(b'\xb2' + bytes([ival & 0xff]))
                elif reg == "ah":
                    emit(b'\xb4' + bytes([ival & 0xff]))
                elif reg == "bh":
                    emit(b'\xb7' + bytes([ival & 0xff]))
                elif reg == "ch":
                    emit(b'\xb5' + bytes([ival & 0xff]))
                elif reg == "dh":
                    emit(b'\xb6' + bytes([ival & 0xff]))
                else:
                    raise ValueError(f"Unsupported register: {reg}")
            except Exception:
                # val是变量
                typ, v = variables[val]
                if typ == 'const':
                    # 从常量加载
                    if reg == "eax":
                        emit(b'\xb8' + struct.pack('<I', v))
                    elif reg == "ebx":
                        emit(b'\xbb' + struct.pack('<I', v))
                    elif reg == "ecx":
                        emit(b'\xb9' + struct.pack('<I', v))
                    elif reg == "edx":
                        emit(b'\xba' + struct.pack('<I', v))
                    elif reg == "esi":
                        emit(b'\xbe' + struct.pack('<I', v))
                    elif reg == "edi":
                        emit(b'\xbf' + struct.pack('<I', v))
                    elif reg == "esp":
                        emit(b'\xbc' + struct.pack('<I', v))
                    elif reg == "ebp":
                        emit(b'\xbd' + struct.pack('<I', v))
                    elif reg == "al":
                        emit(b'\xb0' + bytes([v & 0xff]))
                    elif reg == "bl":
                        emit(b'\xb3' + bytes([v & 0xff]))
                    elif reg == "cl":
                        emit(b'\xb1' + bytes([v & 0xff]))
                    elif reg == "dl":
                        emit(b'\xb2' + bytes([v & 0xff]))
                    elif reg == "ah":
                        emit(b'\xb4' + bytes([v & 0xff]))
                    elif reg == "bh":
                        emit(b'\xb7' + bytes([v & 0xff]))
                    elif reg == "ch":
                        emit(b'\xb5' + bytes([v & 0xff]))
                    elif reg == "dh":
                        emit(b'\xb6' + bytes([v & 0xff]))
                    else:
                        raise ValueError(f"Unsupported register: {reg}")
                else:
                    # 从内存加载
                    if reg == "eax":
                        emit(b'\xa1' + struct.pack('<I', v))
                    elif reg == "ebx":
                        emit(b'\x8b\x1d' + struct.pack('<I', v))
                    elif reg == "ecx":
                        emit(b'\x8b\x0d' + struct.pack('<I', v))
                    elif reg == "edx":
                        emit(b'\x8b\x15' + struct.pack('<I', v))
                    elif reg == "esi":
                        emit(b'\x8b\x35' + struct.pack('<I', v))
                    elif reg == "edi":
                        emit(b'\x8b\x3d' + struct.pack('<I', v))
                    elif reg == "al":
                        emit(b'\xa0' + struct.pack('<I', v))
                    elif reg == "bl":
                        emit(b'\x8a\x1d' + struct.pack('<I', v))
                    elif reg == "cl":
                        emit(b'\x8a\x0d' + struct.pack('<I', v))
                    elif reg == "dl":
                        emit(b'\x8a\x15' + struct.pack('<I', v))
                    elif reg == "ah":
                        emit(b'\x8a\x25' + struct.pack('<I', v))
                    elif reg == "bh":
                        emit(b'\x8a\x3d' + struct.pack('<I', v))
                    elif reg == "ch":
                        emit(b'\x8a\x2d' + struct.pack('<I', v))
                    elif reg == "dh":
                        emit(b'\x8a\x35' + struct.pack('<I', v))
                    else:
                        raise ValueError(f"Unsupported register: {reg}")
                        
        elif t == "int":
            # 生成int指令
            emit(b"\xcd" + bytes([st[1] & 0xff]))
            
        elif t == "asm":
            # 直接嵌入汇编代码的字节
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
            # ("op", dest, src1, op, src2)
            dest, src1, oper, src2 = st[1], st[2], st[3], st[4]
            
            # 确保目标变量存在
            if dest not in variables:
                variables[dest] = ('mem', len(data))
                data += b'\x00\x00\x00\x00'
            dest_off = variables[dest][1]
            
            # 加载第一个操作数到EAX
            try:
                v1 = int(src1)
                emit(b'\xb8' + struct.pack('<I', v1))  # mov eax, v1
            except Exception:
                typ1, v1 = variables[src1]
                if typ1 == 'const':
                    emit(b'\xb8' + struct.pack('<I', v1))  # mov eax, v1
                else:
                    emit(b'\xa1' + struct.pack('<I', v1))  # mov eax, [v1]
            
            # 加载第二个操作数到EBX
            try:
                v2 = int(src2)
                emit(b'\xbb' + struct.pack('<I', v2))  # mov ebx, v2
            except Exception:
                typ2, v2 = variables[src2]
                if typ2 == 'const':
                    emit(b'\xbb' + struct.pack('<I', v2))  # mov ebx, v2
                else:
                    emit(b'\x8b\x1d' + struct.pack('<I', v2))  # mov ebx, [v2]
            
            # 执行操作
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
                raise ValueError(f"Unsupported operation: {oper}")
            
            # 存储结果
            emit(b'\xa3' + struct.pack('<I', dest_off))  # mov [dest_off], eax
            
        elif t == "cli":
            # 在Linux用户空间中，CLI指令没有实际效果，但可以生成对应的机器码
            emit(b'\xfa')  # CLI

        elif t == "sti":
            # 在Linux用户空间中，STI指令没有实际效果，但可以生成对应的机器码
            emit(b'\xfb')  # STI

        elif t == "hlt":
            # 在Linux用户空间中，HLT指令会导致程序终止，我们可以用exit系统调用替代
            emit(b"\xb8\x01\x00\x00\x00")  # mov eax, 1 (sys_exit)
            emit(b"\xbb\x00\x00\x00\x00")  # mov ebx, 0 (exit code 0)
            emit(b"\xcd\x80")              # int 0x80
            
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
                variables[var_name] = ('mem', len(data))
                data += b'\x00\x00\x00\x00'
            
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
            emit(b'\xa3' + struct.pack('<I', var_off))  # mov [var_off], eax
            
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
            emit(b'\xa3' + struct.pack('<I', var_off))  # mov [var_off], eax
            
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
            
            # 在Linux用户空间中，直接访问I/O端口需要特殊权限
            # 我们可以使用iopl系统调用提升I/O权限级别，但这需要root权限
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
                variables[var_name] = ('mem', len(data))
                data += b'\x00\x00\x00\x00'  # 分配4字节，确保有足够空间
            
            var_off = variables[var_name][1]
            
            # 在Linux用户空间中，直接访问CMOS需要特殊权限
            # 我们可以使用iopl系统调用提升I/O权限级别，但这需要root权限
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
            emit(b'\xa3')  # MOV [moffs], EAX
            emit(struct.pack('<I', var_off))
            
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
                variables[var_name] = ('mem', len(data))
                data += b'\x00\x00\x00\x00'  # 分配4字节，确保有足够空间
            
            var_off = variables[var_name][1]
            
            # 在Linux中，我们不能直接访问磁盘，需要使用文件系统API
            # 这里我们生成一个简化的版本，实际使用时需要替换为适当的系统调用
            
            # 1. 打开文件（这里简化处理，实际应该使用适当的系统调用）
            emit(b'\xb8\x05\x00\x00\x00')  # mov eax, 5 (sys_open)
            emit(b'\xbe\x00\x00\x00\x00')  # mov esi, filename (这里简化处理)
            emit(b'\xba\x00\x00\x00\x00')  # mov edx, flags (O_RDONLY)
            emit(b'\xb9\x00\x00\x00\x00')  # mov ecx, mode (0)
            emit(b'\xcd\x80')              # int 0x80
            
            # 2. 读取文件
            emit(b'\xb8\x03\x00\x00\x00')  # mov eax, 3 (sys_read)
            emit(b'\xbb\x03\x00\x00\x00')  # mov ebx, fd (从eax返回)
            emit(b'\xb9\x00\x00\x00\x00')  # mov ecx, buffer (这里简化处理)
            emit(b'\xba\x01\x00\x00\x00')  # mov edx, count (1)
            emit(b'\xcd\x80')              # int 0x80
            
            # 3. 关闭文件
            emit(b'\xb8\x06\x00\x00\x00')  # mov eax, 6 (sys_close)
            emit(b'\xbb\x03\x00\x00\x00')  # mov ebx, fd
            emit(b'\xcd\x80')              # int 0x80
            
            # 4. 从缓冲区读取指定偏移的值
            emit(b'\xb8\x00\x00\x00\x00')  # mov eax, buffer
            emit(b'\x8b\x58')              # mov ebx, [eax + offset]
            emit(struct.pack('<I', offset))
            
            # 5. 保存结果到变量
            emit(b'\x89\x1d')              # mov [var_off], ebx
            emit(struct.pack('<I', var_off))
            
        elif t == "beep":
            # 在Linux中，我们可以通过控制台蜂鸣器来发出声音
            # 这里我们使用ioctl系统调用来控制蜂鸣器
            
            # 1. 打开控制台设备
            emit(b'\xb8\x05\x00\x00\x00')  # mov eax, 5 (sys_open)
            emit(b'\xbe\x00\x00\x00\x00')  # mov esi, filename ("/dev/console")
            emit(b'\xba\x02\x00\x00\x00')  # mov edx, flags (O_RDWR)
            emit(b'\xb9\x00\x00\x00\x00')  # mov ecx, mode (0)
            emit(b'\xcd\x80')              # int 0x80
            
            # 2. 准备ioctl参数
            freq = st[1]
            if freq <= 0:
                freq = 440
            emit(b'\xb8' + struct.pack('<I', freq))  # mov eax, freq
            
            # 3. 调用ioctl (KIOCSOUND, 0x4B2F)
            emit(b'\xbb\x2f\x4b\x00\x00')  # mov ebx, 0x4B2F (KIOCSOUND)
            emit(b'\xb9\x00\x00\x00\x00')  # mov ecx, 0 (duration)
            emit(b'\xb8\x36\x00\x00\x00')  # mov eax, 54 (sys_ioctl)
            emit(b'\xcd\x80')              # int 0x80
            
            # 4. 关闭控制台设备
            emit(b'\xb8\x06\x00\x00\x00')  # mov eax, 6 (sys_close)
            emit(b'\xbb\x03\x00\x00\x00')  # mov ebx, fd
            emit(b'\xcd\x80')              # int 0x80
            
        else:
            raise ValueError(f"Unknown statement type: {t}")
    
    # 处理所有语句
    for st in stmts:
        process_statement(st)
    
    # 修复跳转和调用
    for item in fixups:
        if item[0] == 'jz':
            pos, label = item[1], item[2]
            if label not in labels:
                raise ValueError(f"Unknown label: {label}")
            target = labels[label]
            rel = target - (pos + 4)
            code[pos:pos+4] = struct.pack('<i', rel)
        elif item[0] == 'jnz':
            pos, label = item[1], item[2]
            if label not in labels:
                raise ValueError(f"Unknown label: {label}")
            target = labels[label]
            rel = target - (pos + 4)
            code[pos:pos+4] = struct.pack('<i', rel)
        elif item[0] == 'jmp':
            pos, label = item[1], item[2]
            if label not in labels:
                raise ValueError(f"Unknown label: {label}")
            target = labels[label]
            rel = target - (pos + 5)
            code[pos:pos+4] = struct.pack('<i', rel)
        elif item[0] == 'call':
            pos, label = item[1], item[2]
            # 处理模块函数调用
            if "." in label:
                module_name, func_name = label.split(".", 1)
                if module_name not in modules:
                    raise ValueError(f"Unknown module: {module_name}")
                if func_name not in modules[module_name]['functions']:
                    raise ValueError(f"Unknown function {func_name} in module {module_name}")
                target = modules[module_name]['functions'][func_name][0]
            else:
                if label not in labels:
                    raise ValueError(f"Unknown label: {label}")
                target = labels[label]
            rel = target - (pos + 5)
            code[pos:pos+4] = struct.pack('<i', rel)
    
    # 返回生成的ELF文件
    return make_elf(code, data)
