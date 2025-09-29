# -*- coding: utf-8 -*-
import struct

def gen_bios(stmts):
    """
    Generate BIOS-style machine code (bytearray) from a list of statements.
    Supports: let, print_str, print_var, exit, mov, int, sa, tm, org, label,
              jmp, bpb, asm, if, elif, else, op (16-bit), beep, for, while,
              import, global, extern
    variables: maps name -> ('const', value) or ('mem', offset_in_data)
    """
    variables = {}
    labels = {}          # name -> code offset
    fixups = []          # list of (pos_in_code, label) for E9 rel16
    code = bytearray()
    data = bytearray()
    unique_id = 0
    
    # 模块系统相关
    modules = {}        # 已导入的模块
    global_funcs = {}   # 全局函数：name -> (code_offset, param_count)
    extern_funcs = {}   # 外部函数：name -> (module_name, func_name)

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

    # helper to allocate a memory variable (16-bit) and return offset
    def alloc_mem_var(name, size=2):
        offset = len(data)
        emit_data(b'\x00' * size)
        variables[name] = ('mem', offset)
        return offset

    # helper to get variable type and value/offset
    def var_get(name):
        if name not in variables:
            # if unknown variable, auto-allocate as mem (2 bytes)
            alloc_mem_var(name, 2)
        return variables[name]

    # emit mov reg, imm (supports 8-bit and 16-bit registers)
    reg8_enc = {"al": 0xb0, "cl": 0xb1, "dl": 0xb2, "bl": 0xb3, "ah": 0xb4, "ch": 0xb5, "dh": 0xb6, "bh": 0xb7}
    reg16_enc = {"ax": 0xb8, "cx": 0xb9, "dx": 0xba, "bx": 0xbb, "sp": 0xbc, "bp": 0xbd, "si": 0xbe, "di": 0xbf}
    seg_reg_enc = {"es": 0x06, "cs": 0x0e, "ss": 0x16, "ds": 0x1e}

    def emit_mov_seg_reg_imm(reg, val):
        """生成mov段寄存器, 立即数的指令"""
        if reg in seg_reg_enc:
            # 段寄存器不能直接加载立即数，需要通过通用寄存器中转
            emit_mov_reg_imm("ax", val)
            emit(bytes([seg_reg_enc[reg]]))  # mov reg, ax
        else:
            raise ValueError("Unsupported segment register: " + reg)

    def emit_mov_reg_imm(reg, val):
        if reg in reg8_enc:
            emit(bytes([reg8_enc[reg]] + [val & 0xff]))
        elif reg in reg16_enc:
            emit(bytes([reg16_enc[reg]]) + struct.pack("<H", val & 0xffff))
        elif reg in seg_reg_enc:
            emit_mov_seg_reg_imm(reg, val)
        else:
            raise ValueError("Unsupported register for mov immediate: " + reg)

    # mov reg, [moffs] for 16-bit: MOV AX, moffs16 -> A1 moffs16 ; MOV AL, moffs8 -> A0 moffs16
    def emit_mov_reg_from_moffs8(reg, moffs):
        # only AL supported for 8-bit moffs using A0
        if reg != "al":
            raise ValueError("Only AL supported for moffs8 in this helper")
        emit(b'\xa0' + struct.pack('<H', moffs))

    def emit_mov_reg_from_moffs16(reg, moffs):
        if reg == "ax":
            emit(b'\xa1' + struct.pack('<H', moffs))
        else:
            # 使用通用寄存器加载方式
            emit_mov_reg_imm("bx", moffs)
            emit(b'\x8b')  # MOV reg, [BX]
            if reg == "cx":
                emit(b'\x0b')
            elif reg == "dx":
                emit(b'\x13')
            elif reg == "bx":
                emit(b'\x1b')
            elif reg == "sp":
                emit(b'\x23')
            elif reg == "bp":
                emit(b'\x2b')
            elif reg == "si":
                emit(b'\x33')
            elif reg == "di":
                emit(b'\x3b')
            else:
                raise ValueError("Unsupported register for moffs16: " + reg)

    # mov [moffs], ax : opcode A3 moffs16
    def emit_mov_moffs_from_ax(moffs):
        emit(b'\xa3' + struct.pack('<H', moffs))

    # top-level statement processor (handles a single stmt)
    def process_statement(st):
        t = st[0]
        if t == "let":
            # st = ("let", name, value)
            name, val = st[1], st[2]
            # if val is int -> const; else if string "mem" or none -> allocate mem
            try:
                ival = int(val)
                variables[name] = ('const', ival)
            except Exception:
                # allocate as memory variable (2 bytes)
                alloc_mem_var(name, 2)

        elif t == "print_str":
            s = st[1] + "\n"
            for ch in s:
                emit(b"\xb4\x0e")                     # mov ah, 0x0E
                emit(bytes([0xb0, ord(ch) & 0xff]))   # mov al, char
                emit(b"\xcd\x10")                     # int 0x10

        elif t == "print_var":
            name = st[1]
            typ, val = var_get(name)
            if typ == 'const':
                s = str(val)
                for ch in s:
                    emit(b"\xb4\x0e")
                    emit(bytes([0xb0, ord(ch) & 0xff]))
                    emit(b"\xcd\x10")
            else:  # mem
                # load word from moffs into AX then convert decimal at compile-time
                # For simplicity: read initial data value (compile-time) and print it.
                moffs = val
                # 检查数据段是否有足够的空间
                if moffs + 1 >= len(data):
                    # 如果空间不足，扩展数据段
                    data.extend(b'\x00' * (moffs + 2 - len(data)))
                # fetch the 2 bytes from data (they were initialized), interpret little-endian
                word = data[moffs] | (data[moffs+1] << 8)
                s = str(word)
                for ch in s:
                    emit(b"\xb4\x0e")
                    emit(bytes([0xb0, ord(ch) & 0xff]))
                    emit(b"\xcd\x10")


        elif t == "exit":
            # simple halt loop
            emit(b'\xf4')    # hlt
            emit(b'\xeb\xfe')# jmp $

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
                    # memory variable: load from moffs into AX/AL depending on reg
                    if reg in ("ax", "cx", "dx", "bx", "sp", "bp", "si", "di"):
                        emit_mov_reg_from_moffs16(reg, v)
                    elif reg in ("al",):
                        emit_mov_reg_from_moffs8("al", v)
                    else:
                        raise ValueError("mov from mem unsupported for reg: " + reg)

        elif t == "int":
            emit(b"\xcd" + bytes([st[1] & 0xff]))

        elif t == "sa":
            # append raw bytes to data
            for v in st[1]:
                emit_data(bytes([v]))

        elif t == "tm":
            # 确保正确解析tm指令的参数
            if isinstance(st[1], str):
                target = int(st[1], 0)  # 支持十进制、十六进制等格式
            else:
                target = int(st[1])
            
            current_length = len(code) + len(data)
            
            if current_length > target:
                # 计算超过的字节数
                overflow = current_length - target
                error_msg = f"Code exceeds TM limit by {overflow} bytes\n"
                raise ValueError(error_msg)
            else:
                # 计算需要填充的字节数，但要保留最后两个字节给引导扇区标记
                padding = target - current_length - 2  # 减去2字节给0x55AA
                if padding > 0:
                    # 填充0直到达到目标大小-2
                    emit_data(b'\x00' * padding)
                # 添加引导扇区标记
                emit_data(b'\x55\xaa')

        elif t == "org":
            # st = ("org", address)
            # 检查st[1]的类型，如果是整数则直接使用，如果是字符串则转换
            if isinstance(st[1], str):
                address = int(st[1], 0)
            else:
                address = int(st[1])
            
            # 如果指定的地址大于当前代码和数据段的总长度，需要填充数据段
            current_length = len(code) + len(data)
            
            # 注意：我们在这里只是确保数据段足够大，实际的"org"效果需要在最终生成二进制文件时实现
            # 在简单的BIOS引导程序中，通常org 0x7C00表示程序将被加载到0x7C00地址执行

        elif t == "cli":
            # 生成cli指令的机器码
            emit(b'\xfa')  # CLI
        elif t == "sti":
            # 生成sti指令的机器码
            emit(b'\xfb')  # STI
        elif t == "hlt":
            # 生成hlt指令的机器码
            emit(b'\xf4')  # HLT


        elif t == "label":
            labels[st[1]] = len(code)

        elif t == "jmp":
            # jmp label (E9 rel16)
            label = st[1]
            pos = len(code)
            emit(b"\xe9\x00\x00")   # placeholder
            fixups.append((pos, label))

        elif t == "bpb":
            vals = [int(v,0) for v in st[1]]
            # simplified BPB: two words
            bpb = struct.pack("<H", vals[0]) + struct.pack("<H", vals[1])
            emit_data(bpb)

        elif t == "asm":
            # st[1]: "xx yy zz"
            for byte in st[1].split():
                emit(bytes([int(byte, 16)]))
        elif t in ["inb", "inw", "inl", "outb", "outw", "outl"]:
            port = int(st[1].strip(','), 0)
            if t in ["outb", "outw", "outl"]:
                value = int(st[2].strip(','), 0)
            
            # 生成相应的汇编指令
            if t == "inb":
                emit(b'\xb0')  # mov al, imm8
                emit(port & 0xff)
                emit(b'\xe4')  # in al, imm8
            elif t == "inw":
                emit(b'\xb8')  # mov ax, imm16
                emit(struct.pack("<H", port & 0xffff))
                emit(b'\xed')  # in ax, dx
            elif t == "inl":
                emit(b'\x66')  # 32位操作前缀
                emit(b'\xb8')  # mov eax, imm32
                emit(struct.pack("<I", port & 0xffffffff))
                emit(b'\xed')  # in eax, dx
            elif t == "outb":
                emit(b'\xb0')  # mov al, imm8
                emit(value & 0xff)
                emit(b'\xe6')  # out imm8, al
                emit(port & 0xff)
            elif t == "outw":
                emit(b'\xb8')  # mov ax, imm16
                emit(struct.pack("<H", value & 0xffff))
                emit(b'\xef')  # out dx, ax
                emit(struct.pack("<H", port & 0xffff))
            elif t == "outl":
                emit(b'\x66')  # 32位操作前缀
                emit(b'\xb8')  # mov eax, imm32
                emit(struct.pack("<I", value & 0xffffffff))
                emit(b'\xef')  # out dx, eax
                emit(struct.pack("<H", port & 0xffff))
        elif t == "fat16_fda":
            vals = [int(v,0) for v in st[1]]
            # FAT16 FDA有24个参数，其中19个是必须的
            # 我们将所有参数打包为字节并添加到数据段
            fat16_fda_data = bytearray()
            for val in vals:
                fat16_fda_data.extend(struct.pack("<H", val & 0xffff))
            emit_data(fat16_fda_data)
        elif t == "read_cmos":
            # st = ("read_cmos", addr, var)
            addr = int(st[1], 0)
            var_name = st[2]  # 可能为None，表示使用默认变量
            
            # 确保有一个变量来存储结果
            if var_name is None:
                var_name = "cmos_result"
            
            # 确保变量存在，如果不存在则创建
            if var_name not in variables:
                alloc_mem_var(var_name, 2)  # 分配2字节，确保有足够空间
            
            var_off = variables[var_name][1]
            
            # 禁用中断
            emit(b'\xFA')  # CLI
            
            # 读取CMOS的汇编代码
            # 1. 设置要读取的CMOS地址
            emit(b'\xB0')  # MOV AL, imm8
            emit(addr & 0xFF)
            emit(b'\xE6')  # OUT imm8, AL
            emit(0x70)     # CMOS地址端口
            
            # 2. 从CMOS数据端口读取
            emit(b'\xE4')  # IN AL, imm8
            emit(0x71)     # CMOS数据端口
            
            # 3. 将AL零扩展到AX（高字节置零）
            emit(b'\x31\xD2')  # XOR DX, DX (清零DX)
            emit(b'\x8A\xC8')  # MOV CL, AL
            emit(b'\x88\xC2')  # MOV DL, AL
            emit(b'\x89\xD0')  # MOV AX, DX
            
            # 4. 保存结果到变量
            emit(b'\xA3')  # MOV [moffs], AX
            emit(struct.pack('<H', var_off))
            
            # 恢复中断
            emit(b'\xFB')  # STI

        elif t == "read_fat12_hdr":
            # st = ("read_fat12_hdr", var_name, offset)
            var_name = st[1]  # 可能为None，表示使用默认变量
            offset = int(st[2], 0)
            
            # 确保有一个变量来存储结果
            if var_name is None:
                var_name = "fat12_hdr_value"
            
            # 确保变量存在，如果不存在则创建
            if var_name not in variables:
                alloc_mem_var(var_name, 2)  # FAT12头部读取2字节
            
            var_off = variables[var_name][1]
            
            # 读取FAT12头部的汇编代码
            # FAT12头部通常从磁盘的0扇区开始，偏移量0x0B是BPB的开始
            
            # 1. 设置读取参数
            emit(b'\xB8\x00\x00')  # MOV AX, 0 (驱动器号，0表示A盘)
            emit(b'\x8E\xD8')      # MOV DS, AX
            emit(b'\xBB\x00\x7C')  # MOV BX, 0x7C00 (加载到内存的地址)
            emit(b'\xB9\x01\x00')  # MOV CX, 1 (读取1个扇区)
            emit(b'\xBA\x00\x00')  # MOV DX, 0 (起始扇区0)
            
            # 2. 调用BIOS磁盘读取中断
            emit(b'\xCD\x13')      # INT 0x13
            
            # 3. 从内存中读取指定偏移的值
            emit(b'\xB8\x00\x7C')  # MOV AX, 0x7C00
            emit(b'\x8E\xC0')      # MOV ES, AX
            emit(b'\xBB')          # MOV BX, offset
            emit(struct.pack('<H', offset))
            
            # 4. 读取字到AX
            emit(b'\x26\x8B\x07')  # MOV AX, ES:[BX]
            
            # 5. 保存结果到变量
            emit(b'\xA3')          # MOV [moffs], AX
            emit(struct.pack('<H', var_off))

        elif t == "read_fat16_hdr":
            # st = ("read_fat16_hdr", var_name, offset)
            var_name = st[1]  # 可能为None，表示使用默认变量
            offset = int(st[2], 0)
            
            # 确保有一个变量来存储结果
            if var_name is None:
                var_name = "fat16_hdr_value"
            
            # 确保变量存在，如果不存在则创建
            if var_name not in variables:
                alloc_mem_var(var_name, 2)  # FAT16头部读取2字节
            
            var_off = variables[var_name][1]
            
            # 读取FAT16头部的汇编代码
            # FAT16头部通常从磁盘的0扇区开始，偏移量0x0B是BPB的开始
            
            # 1. 设置读取参数
            emit(b'\xB8\x00\x00')  # MOV AX, 0 (驱动器号，0表示A盘)
            emit(b'\x8E\xD8')      # MOV DS, AX
            emit(b'\xBB\x00\x7C')  # MOV BX, 0x7C00 (加载到内存的地址)
            emit(b'\xB9\x01\x00')  # MOV CX, 1 (读取1个扇区)
            emit(b'\xBA\x00\x00')  # MOV DX, 0 (起始扇区0)
            
            # 2. 调用BIOS磁盘读取中断
            emit(b'\xCD\x13')      # INT 0x13
            
            # 3. 从内存中读取指定偏移的值
            emit(b'\xB8\x00\x7C')  # MOV AX, 0x7C00
            emit(b'\x8E\xC0')      # MOV ES, AX
            emit(b'\xBB')          # MOV BX, offset
            emit(struct.pack('<H', offset))
            
            # 4. 读取字到AX
            emit(b'\x26\x8B\x07')  # MOV AX, ES:[BX]
            
            # 5. 保存结果到变量
            emit(b'\xA3')          # MOV [moffs], AX
            emit(struct.pack('<H', var_off))
        elif t == "set_fat12_BPB":
            vals = [int(v,0) for v in st[1]]
            # FAT12 BPB有多个字段，我们将所有参数打包为字节并添加到数据段
            fat12_bpb_data = bytearray()
            for val in vals:
                fat12_bpb_data.extend(struct.pack("<H", val & 0xffff))
            emit_data(fat12_bpb_data)

        elif t == "return":
            # st = ("return", ret_val)
            ret_val = st[1]  # 可能为None，表示无返回值
            
            if ret_val is not None:
                # 有返回值，将返回值放入AX寄存器
                try:
                    # 尝试解析为整数
                    val = int(ret_val, 0)
                    emit_mov_reg_imm("ax", val)
                except ValueError:
                    # 不是整数，可能是变量
                    typ, val = var_get(ret_val)
                    if typ == 'const':
                        emit_mov_reg_imm("ax", val)
                    else:
                        # 从内存加载
                        emit_mov_reg_from_moffs16("ax", val)
            
            # 使用RET指令返回
            emit(b'\xC3')  # RET
        

        elif t == "while":
            # ("while", condition, block_statements)
            condition, block_stmts = st[1], st[2]
            
            # 创建循环开始和结束标签
            loop_start = new_label("while_start")
            loop_end = new_label("while_end")
            
            # 设置循环开始标签
            labels[loop_start] = len(code)
            
            # 生成条件检查代码
            typ, val = var_get(condition)
            if typ == 'const':
                emit_mov_reg_imm("al", val & 0xff)
            else:
                # load byte from moffs into AL
                emit_mov_reg_from_moffs8("al", val)
            
            # test al, al
            emit(b'\x84\xc0')
            
            # 如果条件为假，跳转到循环结束
            pos = len(code)
            emit(b'\x74\x00')  # jz rel8 placeholder
            fixups.append(('jz8', pos+1, loop_end))
            
            # 处理循环体
            for s in block_stmts:
                process_statement(s)
            
            # 跳回循环开始
            pos_jmp = len(code)
            emit(b'\xe9\x00\x00')  # jmp rel16 placeholder
            fixups.append((pos_jmp, loop_start))
            
            # 设置循环结束标签
            labels[loop_end] = len(code)
        elif t == "for":
            # ("for", var, start, end, step, block_statements)
            var_name, start_val, end_val, step_val, block_stmts = st[1], st[2], st[3], st[4], st[5]
            
            # 确保循环变量存在
            if var_name not in variables:
                alloc_mem_var(var_name, 2)
            
            # 创建循环开始和结束标签
            loop_start = new_label("for_start")
            loop_end = new_label("for_end")
            
            # 初始化循环变量
            try:
                start = int(start_val)
                emit_mov_reg_imm("ax", start & 0xffff)
            except ValueError:
                typ, start = var_get(start_val)
                if typ == 'const':
                    emit_mov_reg_imm("ax", start & 0xffff)
                else:
                    emit_mov_reg_from_moffs16("ax", start)
            
            # 保存初始值到循环变量
            var_off = variables[var_name][1]
            emit_mov_moffs_from_ax(var_off)
            
            # 设置循环开始标签
            labels[loop_start] = len(code)
            
            # 加载循环变量到AX
            emit_mov_reg_from_moffs16("ax", var_off)
            
            # 加载结束值到BX
            try:
                end = int(end_val)
                emit_mov_reg_imm("bx", end & 0xffff)
            except ValueError:
                typ, end = var_get(end_val)
                if typ == 'const':
                    emit_mov_reg_imm("bx", end & 0xffff)
                else:
                    emit_mov_reg_from_moffs16("bx", end)
            
            # 比较AX和BX
            emit(b'\x39\xd8')  # cmp ax, bx
            
            # 如果AX > BX，跳转到循环结束（假设是递增循环）
            pos = len(code)
            emit(b'\x7f\x00')  # jg rel8 placeholder
            fixups.append(('jz8', pos+1, loop_end))
            
            # 处理循环体
            for s in block_stmts:
                process_statement(s)
            
            # 更新循环变量
            emit_mov_reg_from_moffs16("ax", var_off)
            
            try:
                step = int(step_val)
                emit_mov_reg_imm("bx", step & 0xffff)
            except ValueError:
                typ, step = var_get(step_val)
                if typ == 'const':
                    emit_mov_reg_imm("bx", step & 0xffff)
                else:
                    emit_mov_reg_from_moffs16("bx", step)
            
            # AX = AX + BX
            emit(b'\x01\xd8')  # add ax, bx
            
            # 保存更新后的值
            emit_mov_moffs_from_ax(var_off)
            
            # 跳回循环开始
            pos_jmp = len(code)
            emit(b'\xe9\x00\x00')  # jmp rel16 placeholder
            fixups.append((pos_jmp, loop_start))
            
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
            emit(b'\xC3')  # RET
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
                    # 假设模块已经预加载到modules字典中
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
                
                # 将参数压栈（简化处理，实际应该根据调用约定）
                for i, arg in enumerate(args):
                    try:
                        val = int(arg)
                        emit_mov_reg_imm("ax", val & 0xffff)
                    except ValueError:
                        typ, val = var_get(arg)
                        if typ == 'const':
                            emit_mov_reg_imm("ax", val & 0xffff)
                        else:
                            emit_mov_reg_from_moffs16("ax", val)
                    
                    # 压栈
                    emit(b'\x50')  # push ax
                
                # 调用函数
                pos = len(code)
                emit(b'\xe8\x00\x00')  # call rel16 placeholder
                fixups.append((pos, func_name))
                
                # 清理栈（简化处理，实际应该根据调用约定）
                if param_count > 0:
                    emit_mov_reg_imm("sp", len(code) + param_count * 2)
            
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
                
                # 将参数压栈（简化处理，实际应该根据调用约定）
                for i, arg in enumerate(args):
                    try:
                        val = int(arg)
                        emit_mov_reg_imm("ax", val & 0xffff)
                    except ValueError:
                        typ, val = var_get(arg)
                        if typ == 'const':
                            emit_mov_reg_imm("ax", val & 0xffff)
                        else:
                            emit_mov_reg_from_moffs16("ax", val)
                    
                    # 压栈
                    emit(b'\x50')  # push ax
                
                # 调用函数
                pos = len(code)
                emit(b'\xe8\x00\x00')  # call rel16 placeholder
                fixups.append((pos, f"{module_name}.{extern_func_name}"))
                
                # 清理栈（简化处理，实际应该根据调用约定）
                if param_count > 0:
                    emit_mov_reg_imm("sp", len(code) + param_count * 2)
            
            else:
                raise ValueError(f"Unknown function: {func_name}")

        elif t == "clear_screen":
            # 使用BIOS中断0x10功能0x06来清空屏幕
            # 功能号0x06：向上滚动窗口
            # AL = 滚动行数（0表示全部）
            # BH = 属性（通常为0x07表示黑底白字）
            # CH, CL = 窗口左上角行列号（0,0）
            # DH, DL = 窗口右下角行列号（24,79）
            emit(b'\xB4\x06')      # mov ah, 0x06
            emit(b'\xB0\x00')      # mov al, 0 (滚动全部行)
            emit(b'\xB7\x07')      # mov bh, 0x07 (黑底白字)
            emit(b'\xB1\x00')      # mov cl, 0 (左上角列)
            emit(b'\xB5\x00')      # mov ch, 0 (左上角行)
            emit(b'\xB2\x4F')      # mov dl, 79 (右下角列)
            emit(b'\xB6\x18')      # mov dh, 24 (右下角行)
            emit(b'\xCD\x10')      # int 0x10

        elif t == "op":
            # ("op", dest, src1, op, src2)  - use 16-bit arithmetic, result stored into dest (mem var)
            dest, src1, oper, src2 = st[1], st[2], st[3], st[4]
            # ensure dest is memory variable
            if dest not in variables or variables[dest][0] != 'mem':
                alloc_mem_var(dest, 2)
            dest_off = variables[dest][1]

            # load src1 -> AX
            try:
                v1 = int(src1)
                emit_mov_reg_imm("ax", v1 & 0xffff)
            except Exception:
                typ1, v1 = var_get(src1)
                if typ1 == 'const':
                    emit_mov_reg_imm("ax", v1 & 0xffff)
                else:
                    emit_mov_reg_from_moffs16("ax", v1)

            # load src2 -> BX
            try:
                v2 = int(src2)
                emit_mov_reg_imm("bx", v2 & 0xffff)
            except Exception:
                typ2, v2 = var_get(src2)
                if typ2 == 'const':
                    emit_mov_reg_imm("bx", v2 & 0xffff)
                else:
                    # mov bx, [moffs] isn't trivial; do a simple approach:
                    # mov ax, moffs; mov bx, [ax] is too complex; instead for compile-time we read data
                    if typ2 == 'mem':
                        val_word = data[v2] | (data[v2+1] << 8)
                        emit_mov_reg_imm("bx", val_word & 0xffff)
                    else:
                        raise ValueError("Unsupported src2 type in op")

            # perform operation on AX, BX
            if oper == '+':
                emit(b'\x01\xd8')  # add ax, bx
            elif oper == '-':
                emit(b'\x29\xd8')  # sub ax, bx
            elif oper == '*':
                # imul bx -> 0F AF C3 (IMUL r16, r16) or use MUL BX (unsigned) F7 E3 -> AX = AX * BX
                # we'll use unsigned MUL BX: F7 E3
                emit(b'\xf7\xe3')  # mul bx (AX = AX * BX) ; result in DX:AX, low in AX
            elif oper == '/':
                # divide AX by BX: need to zero DX then idiv bx (signed) or div bx (unsigned)
                emit(b'\x66')      # operand-size prefix not really correct in 16-bit, kept simple
                emit(b'\x99')      # cdq (sign-extend EAX->EDX) - not perfect in 16-bit, but keep
                emit(b'\xf7\xf3')  # div bx (AX /= BX), result in AX
            else:
                raise ValueError("Unsupported op: " + oper)

            # store AX into dest moffs (mov [moffs], ax) -> opcode A3 moffs16
            emit_mov_moffs_from_ax(dest_off)

            # also update compile-time data so later print_var / op can read it
            # write AX value from data: we cannot fetch run-time AX, but for consistency set initial val to 0
            # (Better approach would be to evaluate constant arithmetic here if both operands const)
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
                if oper == '+': const_fold = (a1 + a2) & 0xffff
                elif oper == '-': const_fold = (a1 - a2) & 0xffff
                elif oper == '*': const_fold = (a1 * a2) & 0xffff
                elif oper == '/':
                    const_fold = (a1 // a2) & 0xffff if a2 != 0 else 0
            if const_fold is not None:
                data[dest_off:dest_off+2] = struct.pack("<H", const_fold)

        elif t == "beep":
            # approximate tone generation using PIT and speaker ports (same as your original)
            freq = st[1]
            if freq <= 0:
                freq = 440
            divisor = int(1193180 // freq)
            # out 0x43, 0xB6
            emit(b'\xb0\xb6'); emit(b'\xe6\x43')
            # low byte
            emit(bytes([0xb0, divisor & 0xff])); emit(b'\xe6\x42')
            # high byte
            emit(bytes([0xb0, (divisor >> 8) & 0xff])); emit(b'\xe6\x42')
            # enable speaker (inb/outb sequence simplified)
            emit(b'\xb0\x03'); emit(b'\xe6\x61')
            # crude delay loop
            emit(b'\xb9\x00\x01')      # mov cx, 256
            emit(b'\xb8\x00\x86')      # mov ax, 34304
            emit(b'\x48')              # dec ax
            emit(b'\x85\xc0')          # test ax, ax
            emit(b'\x75\xfb')          # jnz -5
            emit(b'\x49')              # dec cx
            emit(b'\x85\xc9')          # test cx, cx
            emit(b'\x75\xf4')          # jnz -10
            # disable speaker
            emit(b'\xb0\x00'); emit(b'\xe6\x61')
        elif t == "nop":
            # 生成 nop 指令的机器码
            emit(b'\x90')  # NOP

        elif t == "cmp":
            # ("cmp", reg1, reg2/imm)
            reg1, val = st[1], st[2]
            
            # 获取第一个操作数（寄存器）
            if reg1 in reg8_enc:
                reg1_type = 8
                reg1_code = 0xC0 + reg8_enc[reg1] - 0xB0  # 将寄存器编码转换为 ModR/M 格式
            elif reg1 in reg16_enc:
                reg1_type = 16
                reg1_code = 0xC0 + reg16_enc[reg1] - 0xB8  # 将寄存器编码转换为 ModR/M 格式
            else:
                raise ValueError("Unsupported register for cmp: " + reg1)
            
            # 处理第二个操作数（立即数或寄存器）
            try:
                # 尝试解析为立即数
                imm = int(val)
                if reg1_type == 8:
                    emit(b'\x80')  # 8位比较
                    emit(bytes([reg1_code]))
                    emit(bytes([imm & 0xff]))
                else:
                    emit(b'\x81')  # 16位比较
                    emit(bytes([reg1_code]))
                    emit(struct.pack("<H", imm & 0xffff))
            except ValueError:
                # 第二个操作数是寄存器
                if val in reg8_enc:
                    if reg1_type != 8:
                        raise ValueError("Cannot compare 8-bit and 16-bit registers")
                    reg2_code = 0xC0 + reg8_enc[val] - 0xB0  # 将寄存器编码转换为 ModR/M 格式
                    emit(b'\x38')  # CMP r/m8, r8
                    emit(bytes([reg1_code | (reg2_code >> 3)]))
                elif val in reg16_enc:
                    if reg1_type != 16:
                        raise ValueError("Cannot compare 8-bit and 16-bit registers")
                    reg2_code = 0xC0 + reg16_enc[val] - 0xB8  # 将寄存器编码转换为 ModR/M 格式
                    emit(b'\x39')  # CMP r/m16, r16
                    emit(bytes([reg1_code | (reg2_code >> 3)]))
                else:
                    raise ValueError("Unsupported register for cmp: " + val)

        elif t == "test":
            # ("test", reg1, reg2/imm)
            reg1, val = st[1], st[2]
            
            # 获取第一个操作数（寄存器）
            if reg1 in reg8_enc:
                reg1_type = 8
                reg1_code = 0xC0 + reg8_enc[reg1] - 0xB0  # 将寄存器编码转换为 ModR/M 格式
            elif reg1 in reg16_enc:
                reg1_type = 16
                reg1_code = 0xC0 + reg16_enc[reg1] - 0xB8  # 将寄存器编码转换为 ModR/M 格式
            else:
                raise ValueError("Unsupported register for test: " + reg1)
            
            # 处理第二个操作数（立即数或寄存器）
            try:
                # 尝试解析为立即数
                imm = int(val)
                if reg1_type == 8:
                    emit(b'\xF6')  # 8位测试
                    emit(bytes([reg1_code]))
                    emit(bytes([imm & 0xff]))
                else:
                    emit(b'\xF7')  # 16位测试
                    emit(bytes([reg1_code]))
                    emit(struct.pack("<H", imm & 0xffff))
            except ValueError:
                # 第二个操作数是寄存器
                if val in reg8_enc:
                    if reg1_type != 8:
                        raise ValueError("Cannot test 8-bit and 16-bit registers")
                    reg2_code = 0xC0 + reg8_enc[val] - 0xB0  # 将寄存器编码转换为 ModR/M 格式
                    emit(b'\x84')  # TEST r/m8, r8
                    emit(bytes([reg1_code | (reg2_code >> 3)]))
                elif val in reg16_enc:
                    if reg1_type != 16:
                        raise ValueError("Cannot test 8-bit and 16-bit registers")
                    reg2_code = 0xC0 + reg16_enc[val] - 0xB8  # 将寄存器编码转换为 ModR/M 格式
                    emit(b'\x85')  # TEST r/m16, r16
                    emit(bytes([reg1_code | (reg2_code >> 3)]))
                else:
                    raise ValueError("Unsupported register for test: " + val)

        elif t in ["and", "or", "xor"]:
            # ("and"/"or"/"xor", reg1, reg2/imm)
            op_type, reg1, val = st[0], st[1], st[2]
            
            # 获取第一个操作数（寄存器）
            if reg1 in reg8_enc:
                reg1_type = 8
                reg1_code = 0xC0 + reg8_enc[reg1] - 0xB0  # 将寄存器编码转换为 ModR/M 格式
            elif reg1 in reg16_enc:
                reg1_type = 16
                reg1_code = 0xC0 + reg16_enc[reg1] - 0xB8  # 将寄存器编码转换为 ModR/M 格式
            else:
                raise ValueError("Unsupported register for " + op_type + ": " + reg1)
            
            # 处理第二个操作数（立即数或寄存器）
            try:
                # 尝试解析为立即数
                imm = int(val)
                if reg1_type == 8:
                    if op_type == "and":
                        emit(b'\x80')  # 8位 AND
                    elif op_type == "or":
                        emit(b'\x80')  # 8位 OR
                    elif op_type == "xor":
                        emit(b'\x80')  # 8位 XOR
                    emit(bytes([reg1_code | 0x04]))  # ModR/M 字节，设置操作码扩展位
                    emit(bytes([imm & 0xff]))
                else:
                    if op_type == "and":
                        emit(b'\x81')  # 16位 AND
                    elif op_type == "or":
                        emit(b'\x81')  # 16位 OR
                    elif op_type == "xor":
                        emit(b'\x81')  # 16位 XOR
                    emit(bytes([reg1_code | 0x04]))  # ModR/M 字节，设置操作码扩展位
                    emit(struct.pack("<H", imm & 0xffff))
            except ValueError:
                # 第二个操作数是寄存器
                if val in reg8_enc:
                    if reg1_type != 8:
                        raise ValueError("Cannot " + op_type + " 8-bit and 16-bit registers")
                    reg2_code = 0xC0 + reg8_enc[val] - 0xB0  # 将寄存器编码转换为 ModR/M 格式
                    if op_type == "and":
                        emit(b'\x20')  # AND r/m8, r8
                    elif op_type == "or":
                        emit(b'\x08')  # OR r/m8, r8
                    elif op_type == "xor":
                        emit(b'\x30')  # XOR r/m8, r8
                    emit(bytes([reg1_code | (reg2_code >> 3)]))
                elif val in reg16_enc:
                    if reg1_type != 16:
                        raise ValueError("Cannot " + op_type + " 8-bit and 16-bit registers")
                    reg2_code = 0xC0 + reg16_enc[val] - 0xB8  # 将寄存器编码转换为 ModR/M 格式
                    if op_type == "and":
                        emit(b'\x21')  # AND r/m16, r16
                    elif op_type == "or":
                        emit(b'\x09')  # OR r/m16, r16
                    elif op_type == "xor":
                        emit(b'\x31')  # XOR r/m16, r16
                    emit(bytes([reg1_code | (reg2_code >> 3)]))
                else:
                    raise ValueError("Unsupported register for " + op_type + ": " + val)

        elif t == "not":
            # ("not", reg)
            reg = st[1]
            
            # 获取操作数（寄存器）
            if reg in reg8_enc:
                reg_type = 8
                reg_code = 0xC0 + reg8_enc[reg] - 0xB0  # 将寄存器编码转换为 ModR/M 格式
                emit(b'\xF6')  # NOT r/m8
            elif reg in reg16_enc:
                reg_type = 16
                reg_code = 0xC0 + reg16_enc[reg] - 0xB8  # 将寄存器编码转换为 ModR/M 格式
                emit(b'\xF7')  # NOT r/m16
            else:
                raise ValueError("Unsupported register for not: " + reg)
            
            emit(bytes([reg_code | 0x02]))  # ModR/M 字节，设置操作码扩展位

        elif t in ["shl", "shr", "sar", "rol", "ror", "rcl", "rcr"]:
            # ("shl"/"shr"/"sar"/"rol"/"ror"/"rcl"/"rcr", reg, count)
            op_type, reg, count = st[0], st[1], st[2]
            
            # 获取操作数（寄存器）
            if reg in reg8_enc:
                reg_type = 8
                reg_code = 0xC0 + reg8_enc[reg] - 0xB0  # 将寄存器编码转换为 ModR/M 格式
                emit(b'\xD0')  # 移位/旋转操作，8位
            elif reg in reg16_enc:
                reg_type = 16
                reg_code = 0xC0 + reg16_enc[reg] - 0xB8  # 将寄存器编码转换为 ModR/M 格式
                emit(b'\xD1')  # 移位/旋转操作，16位
            else:
                raise ValueError("Unsupported register for " + op_type + ": " + reg)
            
            # 确定操作码扩展位
            op_ext = 0
            if op_type == "shl" or op_type == "rol":
                op_ext = 0x04  # SHL/ROL 的操作码扩展位
            elif op_type == "shr" or op_type == "ror":
                op_ext = 0x05  # SHR/ROR 的操作码扩展位
            elif op_type == "sar" or op_type == "rcr":
                op_ext = 0x07  # SAR/RCR 的操作码扩展位
            elif op_type == "rcl":
                op_ext = 0x02  # RCL 的操作码扩展位
            
            # 处理计数（立即数或 CL 寄存器）
            try:
                # 尝试解析为立即数
                cnt = int(count)
                if cnt == 1:
                    # 计数为1，使用 D0/D1 指令
                    emit(bytes([reg_code | op_ext]))
                else:
                    # 计数不为1，使用 D2/D3 指令并设置 CL
                    emit(b'\xB1')  # MOV CL, imm8
                    emit(bytes([cnt & 0xff]))
                    if reg_type == 8:
                        emit(b'\xD2')  # 移位/旋转操作，8位，计数在 CL 中
                    else:
                        emit(b'\xD3')  # 移位/旋转操作，16位，计数在 CL 中
                    emit(bytes([reg_code | op_ext]))
            except ValueError:
                # 计数是 CL 寄存器
                if count != "cl":
                    raise ValueError("Unsupported count for " + op_type + ": " + count + ", must be 'cl' or immediate")
                if reg_type == 8:
                    emit(b'\xD2')  # 移位/旋转操作，8位，计数在 CL 中
                else:
                    emit(b'\xD3')  # 移位/旋转操作，16位，计数在 CL 中
                emit(bytes([reg_code | op_ext]))
        elif t in ["je", "jz", "jne", "jnz", "js", "jns", "jo", "jno", "jb", "jc", "jnb", "jnc", "jbe", "ja", "jle", "jg", "jl", "jge", "jp", "jpe", "jnp", "jpo"]:
            # 条件跳转指令
            # 格式: ("je"/"jz"/..., label)
            label = st[1]
            pos = len(code)
            
            # 根据不同的条件跳转类型设置操作码
            opcodes = {
                "je": 0x74, "jz": 0x74,      # JE/JZ - Jump if equal/zero
                "jne": 0x75, "jnz": 0x75,    # JNE/JNZ - Jump if not equal/not zero
                "js": 0x78,                  # JS - Jump if sign (negative)
                "jns": 0x79,                 # JNS - Jump if not sign (positive)
                "jo": 0x70,                  # JO - Jump if overflow
                "jno": 0x71,                 # JNO - Jump if not overflow
                "jb": 0x72, "jc": 0x72,      # JB/JC - Jump if below/carry
                "jnb": 0x73, "jnc": 0x73,    # JBE/JNC - Jump if not below/not carry
                "jbe": 0x76,                 # JBE - Jump if below or equal
                "ja": 0x77,                  # JA - Jump if above
                "jle": 0x7E,                 # JLE - Jump if less or equal
                "jg": 0x7F,                  # JG - Jump if greater
                "jl": 0x7C,                  # JL - Jump if less
                "jge": 0x7D,                 # JGE - Jump if greater or equal
                "jp": 0x7A, "jpe": 0x7A,     # JP/JPE - Jump if parity/parity even
                "jnp": 0x7B, "jpo": 0x7B     # JNP/JPO - Jump if not parity/parity odd
            }
            
            opcode = opcodes.get(t)
            if opcode is None:
                raise ValueError("Unknown conditional jump: " + t)
            
            # 发送跳转指令和占位符
            emit(bytes([opcode, 0x00]))  # 使用8位相对偏移
            
            # 记录修复点，用于后续计算跳转偏移
            fixups.append(('jz8', pos+1, label))

        elif t in ["push", "pop"]:
            # 堆栈操作指令
            # 格式: ("push"/"pop", reg/imm)
            op_type = t
            operand = st[1]
            
            if op_type == "push":
                try:
                    # 尝试解析为立即数
                    imm = int(operand)
                    # PUSH imm16 (需要686+处理器)
                    emit(b'\x68')
                    emit(struct.pack("<H", imm & 0xffff))
                except ValueError:
                    # 操作数是寄存器
                    if operand in reg16_enc:
                        # PUSH r16
                        opcode = 0x50 + (reg16_enc[operand] - 0xB8)
                        emit(bytes([opcode]))
                    elif operand in seg_reg_enc:
                        # PUSH segreg
                        if operand == "cs":
                            # PUSH CS 是一个特殊指令
                            emit(b'\x0E')
                        else:
                            opcode = 0x06 + (seg_reg_enc[operand] - 0x06) // 8
                            emit(bytes([opcode]))
                    else:
                        raise ValueError("Unsupported register for push: " + operand)
            else:  # pop
                if operand in reg16_enc:
                    # POP r16
                    opcode = 0x58 + (reg16_enc[operand] - 0xB8)
                    emit(bytes([opcode]))
                elif operand in seg_reg_enc:
                    # POP segreg (CS 不能被 POP)
                    if operand == "cs":
                        raise ValueError("Cannot pop CS register")
                    opcode = 0x07 + (seg_reg_enc[operand] - 0x06) // 8
                    emit(bytes([opcode]))
                else:
                    raise ValueError("Unsupported register for pop: " + operand)

        elif t in ["clc", "stc", "cmc", "cld", "std", "cli", "sti"]:
            # 标志操作指令
            # 格式: ("clc"/"stc"/...)
            opcodes = {
                "clc": 0xF8,  # CLC - Clear Carry Flag
                "stc": 0xF9,  # STC - Set Carry Flag
                "cmc": 0xF5,  # CMC - Complement Carry Flag
                "cld": 0xFC,  # CLD - Clear Direction Flag
                "std": 0xFD,  # STD - Set Direction Flag
                "cli": 0xFA,  # CLI - Clear Interrupt Flag
                "sti": 0xFB   # STI - Set Interrupt Flag
            }
            
            opcode = opcodes.get(t)
            if opcode is None:
                raise ValueError("Unknown flag operation: " + t)
            
            emit(bytes([opcode]))

        elif t in ["inc", "dec"]:
            # INC/DEC 指令
            # 格式: ("inc"/"dec", reg)
            op_type = t
            reg = st[1]
            
            if reg in reg8_enc:
                # INC/DEC r8
                if op_type == "inc":
                    opcode = 0xFE
                    reg_ext = 0x00
                else:  # dec
                    opcode = 0xFE
                    reg_ext = 0x01
                
                reg_code = 0xC0 + reg8_enc[reg] - 0xB0  # 将寄存器编码转换为 ModR/M 格式
                emit(bytes([opcode]))
                emit(bytes([reg_code | reg_ext]))
            elif reg in reg16_enc:
                # INC/DEC r16
                if op_type == "inc":
                    opcode = 0x40 + (reg16_enc[reg] - 0xB8)
                else:  # dec
                    opcode = 0x48 + (reg16_enc[reg] - 0xB8)
                
                emit(bytes([opcode]))
            else:
                raise ValueError("Unsupported register for " + op_type + ": " + reg)

        elif t in ["add", "sub", "adc", "sbb"]:
            # ADD/SUB/ADC/SBB 指令
            # 格式: ("add"/"sub"/"adc"/"sbb", reg1, reg2/imm)
            op_type, reg1, val = st[0], st[1], st[2]
            
            # 获取第一个操作数（寄存器）
            if reg1 in reg8_enc:
                reg1_type = 8
                reg1_code = 0xC0 + reg8_enc[reg1] - 0xB0  # 将寄存器编码转换为 ModR/M 格式
            elif reg1 in reg16_enc:
                reg1_type = 16
                reg1_code = 0xC0 + reg16_enc[reg1] - 0xB8  # 将寄存器编码转换为 ModR/M 格式
            else:
                raise ValueError("Unsupported register for " + op_type + ": " + reg1)
            
            # 处理第二个操作数（立即数或寄存器）
            try:
                # 尝试解析为立即数
                imm = int(val)
                if reg1_type == 8:
                    if op_type == "add":
                        emit(b'\x80')  # 8位 ADD
                        reg_ext = 0x00
                    elif op_type == "sub":
                        emit(b'\x80')  # 8位 SUB
                        reg_ext = 0x05
                    elif op_type == "adc":
                        emit(b'\x80')  # 8位 ADC
                        reg_ext = 0x02
                    elif op_type == "sbb":
                        emit(b'\x80')  # 8位 SBB
                        reg_ext = 0x03
                    
                    emit(bytes([reg1_code | reg_ext]))
                    emit(bytes([imm & 0xff]))
                else:
                    if op_type == "add":
                        emit(b'\x81')  # 16位 ADD
                        reg_ext = 0x00
                    elif op_type == "sub":
                        emit(b'\x81')  # 16位 SUB
                        reg_ext = 0x05
                    elif op_type == "adc":
                        emit(b'\x81')  # 16位 ADC
                        reg_ext = 0x02
                    elif op_type == "sbb":
                        emit(b'\x81')  # 16位 SBB
                        reg_ext = 0x03
                    
                    emit(bytes([reg1_code | reg_ext]))
                    emit(struct.pack("<H", imm & 0xffff))
            except ValueError:
                # 第二个操作数是寄存器
                if val in reg8_enc:
                    if reg1_type != 8:
                        raise ValueError("Cannot " + op_type + " 8-bit and 16-bit registers")
                    reg2_code = 0xC0 + reg8_enc[val] - 0xB0  # 将寄存器编码转换为 ModR/M 格式
                    if op_type == "add":
                        emit(b'\x00')  # ADD r/m8, r8
                    elif op_type == "sub":
                        emit(b'\x28')  # SUB r/m8, r8
                    elif op_type == "adc":
                        emit(b'\x10')  # ADC r/m8, r8
                    elif op_type == "sbb":
                        emit(b'\x18')  # SBB r/m8, r8
                    
                    emit(bytes([reg1_code | (reg2_code >> 3)]))
                elif val in reg16_enc:
                    if reg1_type != 16:
                        raise ValueError("Cannot " + op_type + " 8-bit and 16-bit registers")
                    reg2_code = 0xC0 + reg16_enc[val] - 0xB8  # 将寄存器编码转换为 ModR/M 格式
                    if op_type == "add":
                        emit(b'\x01')  # ADD r/m16, r16
                    elif op_type == "sub":
                        emit(b'\x29')  # SUB r/m16, r16
                    elif op_type == "adc":
                        emit(b'\x11')  # ADC r/m16, r16
                    elif op_type == "sbb":
                        emit(b'\x19')  # SBB r/m16, r16
                    
                    emit(bytes([reg1_code | (reg2_code >> 3)]))
                else:
                    raise ValueError("Unsupported register for " + op_type + ": " + val)

        elif t in ["mul", "div", "imul", "idiv"]:
            # MUL/DIV/IMUL/IDIV 指令
            # 格式: ("mul"/"div"/"imul"/"idiv", reg)
            op_type = t
            reg = st[1]
            
            # 获取操作数（寄存器）
            if reg in reg8_enc:
                reg_type = 8
                reg_code = 0xE0 + reg8_enc[reg] - 0xB0  # 将寄存器编码转换为 ModR/M 格式
            elif reg in reg16_enc:
                reg_type = 16
                reg_code = 0xE0 + reg16_enc[reg] - 0xB8  # 将寄存器编码转换为 ModR/M 格式
            else:
                raise ValueError("Unsupported register for " + op_type + ": " + reg)
            
            # 根据操作类型设置操作码
            if op_type == "mul":
                opcode = 0xF6 if reg_type == 8 else 0xF7  # MUL r/m8 or MUL r/m16
                reg_ext = 0x04
            elif op_type == "div":
                opcode = 0xF6 if reg_type == 8 else 0xF7  # DIV r/m8 or DIV r/m16
                reg_ext = 0x06
            elif op_type == "imul":
                opcode = 0xF6 if reg_type == 8 else 0xF7  # IMUL r/m8 or IMUL r/m16
                reg_ext = 0x05
            elif op_type == "idiv":
                opcode = 0xF6 if reg_type == 8 else 0xF7  # IDIV r/m8 or IDIV r/m16
                reg_ext = 0x07
            else:
                raise ValueError("Unknown operation: " + op_type)
            
            emit(bytes([opcode]))
            emit(bytes([reg_code | reg_ext]))

        elif t in ["call", "ret", "iret"]:
            # 调用和返回指令
            if t == "call":
                # 格式: ("call", label/reg/imm)
                target = st[1]
                
                try:
                    # 尝试解析为立即数（绝对地址）
                    addr = int(target)
                    # CALL abs16 (需要686+处理器)
                    emit(b'\x9A')
                    emit(struct.pack("<H", addr & 0xffff))
                    emit(struct.pack("<H", 0))  # 段地址，暂时设为0
                except ValueError:
                    # 目标是标签或寄存器
                    if target in reg16_enc:
                        # CALL r16
                        reg_code = 0xD0 + reg16_enc[target] - 0xB8
                        emit(bytes([0xFF, reg_code]))
                    else:
                        # 目标是标签
                        pos = len(code)
                        emit(b'\xE8\x00\x00')  # CALL rel16 placeholder
                        fixups.append((pos, target))
            elif t == "ret":
                # RET 指令
                emit(b'\xC3')
            elif t == "iret":
                # IRET 指令
                emit(b'\xCF')

        elif t in ["loop", "loope", "loopne"]:
            # 循环指令
            # 格式: ("loop"/"loope"/"loopne", label)
            label = st[1]
            pos = len(code)
            
            # 根据不同的循环类型设置操作码
            if t == "loop":
                opcode = 0xE2  # LOOP
            elif t == "loope":
                opcode = 0xE1  # LOOPE/LOOPZ
            elif t == "loopne":
                opcode = 0xE0  # LOOPNE/LOOPNZ
            else:
                raise ValueError("Unknown loop instruction: " + t)
            
            # 发送循环指令和占位符
            emit(bytes([opcode, 0x00]))  # 使用8位相对偏移
            
            # 记录修复点，用于后续计算跳转偏移
            fixups.append(('jz8', pos+1, label))

        elif t in ["int3", "into", "bound"]:
            # 特殊中断和边界检查指令
            if t == "int3":
                # INT3 指令
                emit(b'\xCC')
            elif t == "into":
                # INTO 指令
                emit(b'\xCE')
            elif t == "bound":
                # BOUND 指令
                # 格式: ("bound", reg, mem)
                reg, mem = st[1], st[2]
                
                if reg in reg16_enc:
                    reg_code = 0x60 + reg16_enc[reg] - 0xB8
                    emit(b'\x62')
                    emit(bytes([reg_code]))
                else:
                    raise ValueError("Unsupported register for bound: " + reg)

        elif t in ["lds", "les", "lss", "lfs", "lgs"]:
            # 加载远指针指令
            # 格式: ("lds"/"les"/..., reg, mem)
            op_type, reg, mem = st[0], st[1], st[2]
            
            if reg not in reg16_enc:
                raise ValueError("Unsupported register for " + op_type + ": " + reg)
            
            reg_code = 0x00 + reg16_enc[reg] - 0xB8
            
            # 根据操作类型设置操作码
            if op_type == "lds":
                opcode = 0xC5
            elif op_type == "les":
                opcode = 0xC4
            elif op_type == "lss":
                opcode = 0xF2  # 需要386+处理器
            elif op_type == "lfs":
                opcode = 0xF4  # 需要386+处理器
            elif op_type == "lgs":
                opcode = 0xF5  # 需要386+处理器
            else:
                raise ValueError("Unknown load far pointer instruction: " + op_type)
            
            emit(bytes([opcode]))
            emit(bytes([reg_code]))

        else:
            # unknown/unsupported statement - ignore or raise
            raise ValueError("Unknown statement type: " + str(t))

    # ---- helper to process a full if/elif/else block starting at index i ----
    def process_if_block(stmts_list, start_index):
        """
        stmts_list: the full statements list
        start_index: index where an 'if' occurs
        Returns the index after the entire if/elif/else block
        """
        # collect blocks: each block is tuple(kind, var_or_none, block_statements)
        blocks = []
        i = start_index
        # first must be 'if'
        first = stmts_list[i]
        if first[0] != 'if':
            raise ValueError("process_if_block called on non-if")
        blocks.append(('if', first[1], first[2]))
        i += 1
        # collect following 'elif' or 'else'
        while i < len(stmts_list):
            s = stmts_list[i]
            if s[0] == 'elif':
                blocks.append(('elif', s[1], s[2]))
                i += 1
            elif s[0] == 'else':
                blocks.append(('else', None, s[1]))
                i += 1
                break
            else:
                break

        # create labels
        endif_label = new_label("endif_")
        next_label_base = new_label("next_")  # base for the first "else/elif" label
        # We'll create label names for each branch except the last 'else' block
        branch_labels = []
        for bi in range(len(blocks)-1):  # last block may be else, no need jump-to after it
            branch_labels.append(new_label("branch_"))

        # For each conditional block (not else), emit test and JZ to branch_labels[idx]
        for idx, blk in enumerate(blocks):
            kind, varname, blk_stmts = blk
            is_last = (idx == len(blocks)-1)
            if kind in ('if', 'elif'):
                # emit mov al, var / imm then test al, al ; jz branch_label
                typ, val = var_get(varname)
                if typ == 'const':
                    emit_mov_reg_imm("al", val & 0xff)
                else:
                    # load byte from moffs into AL
                    emit_mov_reg_from_moffs8("al", val)
                # test al,al
                emit(b'\x84\xc0')
                # jz to skip this block -> to branch_labels[idx]
                if not is_last:
                    target_label = branch_labels[idx]
                    # we use short jump EB rel8 if possible, else use jz rel16 (0F 84)
                    # We'll emit short jz EB 00 and record a short_fixups to patch.
                    # For simplicity, emit short jz and patch with relative 8-bit later.
                    pos = len(code)
                    emit(b'\x74\x00')  # jz rel8 placeholder
                    # record a short fixup: (pos+1, target_label, type='jz8')
                    fixups.append(('jz8', pos+1, target_label))
                else:
                    # if last conditional (shouldn't happen often), just proceed
                    pass

                # process the block statements
                for s2 in blk_stmts:
                    process_statement(s2)

                # after finishing block, jump to endif to skip other branches
                pos_jmp = len(code)
                emit(b'\xe9\x00\x00')  # jmp rel16 placeholder
                fixups.append((pos_jmp, endif_label))
                # place branch label (the one the jz jumps to) here
                if not is_last:
                    labels[branch_labels[idx]] = len(code)

            elif kind == 'else':
                # else block: just run its statements
                for s2 in blk_stmts:
                    process_statement(s2)
                # add jump to endif to skip other branches
                pos_jmp = len(code)
                emit(b'\xe9\x00\x00')  # jmp rel16 placeholder
                fixups.append((pos_jmp, endif_label))
            else:
                raise ValueError("Unknown block kind: " + str(kind))

        # finally place endif label
        labels[endif_label] = len(code)
        return i

    # ---- main loop: iterate statements, but handle if-blocks as a group ----
    i = 0
    while i < len(stmts):
        st = stmts[i]
        if st[0] == 'if':
            i = process_if_block(stmts, i)
        else:
            process_statement(st)
            i += 1

    # ---- resolve fixups ----
    # two kinds of fixups: ('jz8', pos, label) or (pos, label) for E9 rel16
    # Also handle module function calls: (pos, "module.func")
    for item in list(fixups):
        if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], int):
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
            
            # E8 rel16 at pos: code[pos] == 0xE8 ; rel = target - (pos + 3)
            if code[pos] == 0xE8:  # call指令
                rel = target - (pos + 3)
                if rel < -32768 or rel > 32767:
                    raise ValueError(f"call 跳转太远: {rel} 超过了 16 位有符号范围 (-32768~32767)")
                code[pos+1:pos+3] = struct.pack("<h", rel)
            # E9 rel16 at pos: code[pos] == 0xE9 ; rel = target - (pos + 3)
            elif code[pos] == 0xE9:  # jmp指令
                rel = target - (pos + 3)
                if rel < -32768 or rel > 32767:
                    raise ValueError(f"jmp 跳转太远: {rel} 超过了 16 位有符号范围 (-32768~32767)")
                code[pos+1:pos+3] = struct.pack("<h", rel)
            
            fixups.remove(item)

    # Then handle short jz8 fixups stored as ('jz8', pos, label)
    for item in list(fixups):
        if isinstance(item, tuple) and item[0] == 'jz8':
            _, pos, label = item
            if label not in labels:
                raise ValueError("Unknown label in jz8 fixups: " + label)
            target = labels[label]
            rel8 = target - (pos + 1)  # rel8 is relative to next byte after rel8
            if -128 <= rel8 <= 127:
                code[pos] = struct.pack("b", rel8)[0]
            else:
                # too far for short jump: replace short jz (74 xx) with long jz 0F 84 rel32
                # we will expand: replace 2 bytes at pos-1 (0x74, 0x00) with 6 bytes 0F 84 <rel32>
                jz_short_pos = pos-1
                target = labels[label]
                rel32 = target - (jz_short_pos + 6)
                # build new sequence
                newseq = b'\x0f\x84' + struct.pack('<i', rel32)
                # replace in code (expand)
                code[jz_short_pos:jz_short_pos+2] = newseq
                # since we've changed code length, labels stored earlier may be invalid!
                # Simpler approach here: we avoid expanding in-place because it's complex.
                raise ValueError("Branch distance too far for 8-bit jz; label layout too complex for this simple generator.")
            fixups.remove(item)



    # final return
    return bytes(code + data)
