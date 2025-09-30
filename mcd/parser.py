# -*- coding: utf-8 -*-
def parse(tokens):
    stmts, i, variables = [], 0, {}  # 添加variables字典初始化
    while i < len(tokens):
        t, line_num = tokens[i]
        
        if t == "entel":
            # entel 语句用于设置目标架构
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: entel语句缺少架构参数")
            arch = tokens[i+1][0]
            if arch not in ["86", "64", "AMD64"]:
                raise SyntaxError(f"第{line_num}行: 不支持的架构 '{arch}'，支持的架构有: 86, 64, AMD64")
            stmts.append(("entel", arch))
            i += 2

        elif t == "int":  # 变量声明
            if i+2 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: 变量声明不完整")
            name = tokens[i+1][0]
            if tokens[i+2][0] != "=":
                raise SyntaxError(f"第{line_num}行: 缺少等号")
            
            # 支持表达式（最多3个token: A op B）
            expr_tokens = []
            j = i+3
            while j < len(tokens) and tokens[j][0] not in ["int", "print", "exit", "execute", "sa", "tm", "org", "def", "jmp", "bpb", "asm", "if", "elif", "else", "beep", "entel"]:
                expr_tokens.append(tokens[j][0])
                j += 1
            
            if len(expr_tokens) == 1:  # 单个值
                try:
                    value = int(expr_tokens[0], 0)
                except ValueError:
                    if expr_tokens[0] in variables:
                        value = variables[expr_tokens[0]]
                    else:
                        raise NameError(f"第{line_num}行: 未定义的变量: {expr_tokens[0]}")
            elif len(expr_tokens) == 3:  # A op B
                op = expr_tokens[1]
                try:
                    left = int(expr_tokens[0], 0)
                except:
                    if expr_tokens[0] in variables:
                        left = variables[expr_tokens[0]]
                    else:
                        raise NameError(f"第{line_num}行: 未定义的变量: {expr_tokens[0]}")
                
                try:
                    right = int(expr_tokens[2], 0)
                except:
                    if expr_tokens[2] in variables:
                        right = variables[expr_tokens[2]]
                    else:
                        raise NameError(f"第{line_num}行: 未定义的变量: {expr_tokens[2]}")
                
                if op == "+": value = left + right
                elif op == "-": value = left - right
                elif op == "*": value = left * right
                elif op == "/": 
                    if right == 0:
                        raise ValueError(f"第{line_num}行: 除零错误")
                    value = left // right
                else: raise SyntaxError(f"第{line_num}行: 不支持的运算符: {op}")
            else:
                raise SyntaxError(f"第{line_num}行: 无效的表达式")
            
            stmts.append(("let", name, value))
            variables[name] = value
            i = j
        elif t.endswith(":"):  # 支持 label: 的写法
            label_name = t[:-1]
            stmts.append(("label", label_name))
            i += 1

        elif t == "print":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: print语句缺少参数")
            arg = tokens[i+1][0]
            if arg.startswith('"'):
                stmts.append(("print_str", arg.strip('"')))
            else:
                stmts.append(("print_var", arg))
            i += 2

        elif t == "exit":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: exit语句缺少参数")
            stmts.append(("exit", int(tokens[i+1][0],0)))
            i += 2

        elif t in ["ax","bx","cx","dx","al","bl","cl","dl","ah","bh","ch","dh","si","di","sp","bp","es","cs","ss","ds"]:
            if i+2 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: 寄存器赋值不完整")
            if tokens[i+1][0] != "=": 
                raise SyntaxError(f"第{line_num}行: 寄存器赋值必须使用 '='")
            val = int(tokens[i+2][0],0)
            stmts.append(("mov", t, val))
            i += 3

        elif t == "execute":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: execute语句缺少参数")
            stmts.append(("int", int(tokens[i+1][0],0)))
            i += 2

        elif t == "sa":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: sa语句缺少参数")
            values = [int(x,0) for x in tokens[i+1][0].split(",")]
            stmts.append(("sa", values))
            i += 2
        elif t in ["je", "jz", "jne", "jnz", "js", "jns", "jo", "jno", "jb", "jc", "jnb", "jnc", "jbe", "ja", "jle", "jg", "jl", "jge", "jp", "jpe", "jnp", "jpo"]:
            # 条件跳转指令
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: {t}语句缺少目标标签")
            target = tokens[i+1][0]
            stmts.append((t, target))
            i += 2

        elif t in ["push", "pop"]:
            # 堆栈操作指令
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: {t}语句缺少操作数")
            operand = tokens[i+1][0]
            
            # 检查操作数是否为寄存器或立即数
            if operand in ["ax", "bx", "cx", "dx", "si", "di", "sp", "bp", "es", "cs", "ss", "ds"]:
                # 寄存器操作数
                stmts.append((t, operand))
            else:
                # 尝试解析为立即数
                try:
                    imm = int(operand, 0)
                    stmts.append((t, imm))
                except ValueError:
                    raise SyntaxError(f"第{line_num}行: {t}语句的操作数必须是寄存器或立即数")
            
            i += 2

        elif t in ["clc", "stc", "cmc", "cld", "std", "cli", "sti"]:
            # 标志操作指令
            stmts.append((t,))
            i += 1

        elif t in ["inc", "dec"]:
            # INC/DEC 指令
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: {t}语句缺少操作数")
            operand = tokens[i+1][0]
            
            # 检查操作数是否为寄存器
            if operand in ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]:
                stmts.append((t, operand))
            else:
                raise SyntaxError(f"第{line_num}行: {t}语句的操作数必须是寄存器")
            
            i += 2

        elif t in ["add", "sub", "adc", "sbb"]:
            # ADD/SUB/ADC/SBB 指令
            if i+3 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: {t}语句不完整")
            
            reg1 = tokens[i+1][0]
            if tokens[i+2][0] != ",":
                raise SyntaxError(f"第{line_num}行: {t}语句语法错误，应为 {t} reg1, reg2/imm")
            
            reg2_or_imm = tokens[i+3][0]
            
            # 检查第一个操作数是否为寄存器
            if reg1 not in ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]:
                raise SyntaxError(f"第{line_num}行: {t}语句的第一个操作数必须是寄存器")
            
            # 检查第二个操作数是否为寄存器或立即数
            if reg2_or_imm in ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]:
                # 寄存器操作数
                stmts.append((t, reg1, reg2_or_imm))
            else:
                # 尝试解析为立即数
                try:
                    imm = int(reg2_or_imm, 0)
                    stmts.append((t, reg1, imm))
                except ValueError:
                    raise SyntaxError(f"第{line_num}行: {t}语句的第二个操作数必须是寄存器或立即数")
            
            i += 4

        elif t in ["mul", "div", "imul", "idiv"]:
            # MUL/DIV/IMUL/IDIV 指令
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: {t}语句缺少操作数")
            operand = tokens[i+1][0]
            
            # 检查操作数是否为寄存器
            if operand in ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]:
                stmts.append((t, operand))
            else:
                raise SyntaxError(f"第{line_num}行: {t}语句的操作数必须是寄存器")
            
            i += 2

        elif t in ["call", "ret", "iret"]:
            # 调用和返回指令
            if t == "call":
                if i+1 >= len(tokens):
                    raise SyntaxError(f"第{line_num}行: call语句缺少目标")
                target = tokens[i+1][0]
                stmts.append(("call", target))
                i += 2
            elif t == "ret":
                stmts.append(("ret",))
                i += 1
            elif t == "iret":
                stmts.append(("iret",))
                i += 1

        elif t in ["loop", "loope", "loopne"]:
            # 循环指令
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: {t}语句缺少目标标签")
            target = tokens[i+1][0]
            stmts.append((t, target))
            i += 2

        elif t in ["int3", "into"]:
            # 特殊中断指令
            stmts.append((t,))
            i += 1

        elif t == "bound":
            # BOUND 指令
            if i+3 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: bound语句不完整")
            
            reg = tokens[i+1][0]
            if tokens[i+2][0] != ",":
                raise SyntaxError(f"第{line_num}行: bound语句语法错误，应为 bound reg, mem")
            
            mem = tokens[i+3][0]
            
            # 检查第一个操作数是否为寄存器
            if reg not in ["ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]:
                raise SyntaxError(f"第{line_num}行: bound语句的第一个操作数必须是16位寄存器")
            
            stmts.append(("bound", reg, mem))
            i += 4

        elif t in ["lds", "les", "lss", "lfs", "lgs"]:
            # 加载远指针指令
            if i+3 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: {t}语句不完整")
            
            reg = tokens[i+1][0]
            if tokens[i+2][0] != ",":
                raise SyntaxError(f"第{line_num}行: {t}语句语法错误，应为 {t} reg, mem")
            
            mem = tokens[i+3][0]
            
            # 检查第一个操作数是否为寄存器
            if reg not in ["ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]:
                raise SyntaxError(f"第{line_num}行: {t}语句的第一个操作数必须是16位寄存器")
            
            stmts.append((t, reg, mem))
            i += 4

        elif t in ["nop", "cmp", "test", "and", "or", "xor", "not", "shl", "shr", "sar", "rol", "ror", "rcl", "rcr"]:
            # 其他指令
            if t == "nop":
                # NOP 指令不需要操作数
                stmts.append(("nop",))
                i += 1
            elif t in ["cmp", "test"]:
                # CMP/TEST 指令
                if i+3 >= len(tokens):
                    raise SyntaxError(f"第{line_num}行: {t}语句不完整")
                
                reg1 = tokens[i+1][0]
                if tokens[i+2][0] != ",":
                    raise SyntaxError(f"第{line_num}行: {t}语句语法错误，应为 {t} reg1, reg2/imm")
                
                reg2_or_imm = tokens[i+3][0]
                
                # 检查第一个操作数是否为寄存器
                if reg1 not in ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]:
                    raise SyntaxError(f"第{line_num}行: {t}语句的第一个操作数必须是寄存器")
                
                # 检查第二个操作数是否为寄存器或立即数
                if reg2_or_imm in ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]:
                    # 寄存器操作数
                    stmts.append((t, reg1, reg2_or_imm))
                else:
                    # 尝试解析为立即数
                    try:
                        imm = int(reg2_or_imm, 0)
                        stmts.append((t, reg1, imm))
                    except ValueError:
                        raise SyntaxError(f"第{line_num}行: {t}语句的第二个操作数必须是寄存器或立即数")
                
                i += 4
            elif t in ["and", "or", "xor"]:
                # AND/OR/XOR 指令
                if i+3 >= len(tokens):
                    raise SyntaxError(f"第{line_num}行: {t}语句不完整")
                
                reg1 = tokens[i+1][0]
                if tokens[i+2][0] != ",":
                    raise SyntaxError(f"第{line_num}行: {t}语句语法错误，应为 {t} reg1, reg2/imm")
                
                reg2_or_imm = tokens[i+3][0]
                
                # 检查第一个操作数是否为寄存器
                if reg1 not in ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]:
                    raise SyntaxError(f"第{line_num}行: {t}语句的第一个操作数必须是寄存器")
                
                # 检查第二个操作数是否为寄存器或立即数
                if reg2_or_imm in ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]:
                    # 寄存器操作数
                    stmts.append((t, reg1, reg2_or_imm))
                else:
                    # 尝试解析为立即数
                    try:
                        imm = int(reg2_or_imm, 0)
                        stmts.append((t, reg1, imm))
                    except ValueError:
                        raise SyntaxError(f"第{line_num}行: {t}语句的第二个操作数必须是寄存器或立即数")
                
                i += 4
            elif t == "not":
                # NOT 指令
                if i+1 >= len(tokens):
                    raise SyntaxError(f"第{line_num}行: {t}语句缺少操作数")
                operand = tokens[i+1][0]
                
                # 检查操作数是否为寄存器
                if operand in ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]:
                    stmts.append((t, operand))
                else:
                    raise SyntaxError(f"第{line_num}行: {t}语句的操作数必须是寄存器")
                
                i += 2
            elif t in ["shl", "shr", "sar", "rol", "ror", "rcl", "rcr"]:
                # 移位/旋转指令
                if i+3 >= len(tokens):
                    raise SyntaxError(f"第{line_num}行: {t}语句不完整")
                
                reg = tokens[i+1][0]
                if tokens[i+2][0] != ",":
                    raise SyntaxError(f"第{line_num}行: {t}语句语法错误，应为 {t} reg, count/cl")
                
                count = tokens[i+3][0]
                
                # 检查第一个操作数是否为寄存器
                if reg not in ["al", "bl", "cl", "dl", "ah", "bh", "ch", "dh", "ax", "bx", "cx", "dx", "si", "di", "sp", "bp"]:
                    raise SyntaxError(f"第{line_num}行: {t}语句的第一个操作数必须是寄存器")
                
                # 检查第二个操作数是否为立即数或CL寄存器
                if count == "cl":
                    stmts.append((t, reg, count))
                else:
                    # 尝试解析为立即数
                    try:
                        imm = int(count, 0)
                        stmts.append((t, reg, imm))
                    except ValueError:
                        raise SyntaxError(f"第{line_num}行: {t}语句的第二个操作数必须是立即数或CL寄存器")
                
                i += 4

        elif t == "tm":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: tm语句缺少参数")
            if not tokens[i+1][0].endswith("-$"):
                raise SyntaxError(f"第{line_num}行: tm 语法错误，必须 tm N-$")
            target = int(tokens[i+1][0].split("-")[0],0)
            stmts.append(("tm", target))
            i += 2

        elif t == "org":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: org语句缺少参数")
            stmts.append(("org", int(tokens[i+1][0],0)))
            i += 2

        elif t == "def":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: def语句缺少标签名")
            # 获取标签名
            label_name = tokens[i+1][0]
            # 检查下一个token是否是冒号
            if i+2 < len(tokens) and tokens[i+2][0] == ":":
                i += 3  # 跳过 def, 标签名, 冒号
            else:
                i += 2  # 跳过 def, 标签名
            stmts.append(("label", label_name))

        elif t == "jmp":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: jmp语句缺少目标标签")
            target = tokens[i+1][0]
            stmts.append(("jmp", target))
            i += 2

        elif t == "set_fat12_BPB":
            if i+19 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: set_fat12_BPB参数不足")
            values = []
            for j in range(1,20):
                values.append(tokens[i+j][0])
            stmts.append(("bpb", values))
            i += 20
        elif t == "asm":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: asm语句缺少汇编代码")
            # 提取引号内的汇编代码
            asm_code = tokens[i+1][0].strip('"')
            stmts.append(("asm", asm_code))
            i += 2
        elif t == "if":
            # 收集条件表达式
            cond_tokens = []
            i += 1
            while i < len(tokens) and tokens[i][0] != ":":
                cond_tokens.append(tokens[i][0])
                i += 1
            condition = " ".join(cond_tokens)

            # 跳过冒号
            if i < len(tokens) and tokens[i][0] == ":":
                i += 1

            # 收集 if 块
            block_tokens = []
            while i < len(tokens) and tokens[i][0] not in ("elif", "else", "endif"):
                block_tokens.append(tokens[i])
                i += 1
            if_block = parse(block_tokens)
            stmts.append(("if", condition, if_block))

        # ---------- elif ----------
        elif t == "elif":
            cond_tokens = []
            i += 1
            while i < len(tokens) and tokens[i][0] != ":":
                cond_tokens.append(tokens[i][0])
                i += 1
            condition = " ".join(cond_tokens)

            if i < len(tokens) and tokens[i][0] == ":":
                i += 1

            block_tokens = []
            while i < len(tokens) and tokens[i][0] not in ("elif", "else", "endif"):
                block_tokens.append(tokens[i])
                i += 1
            elif_block = parse(block_tokens)
            stmts.append(("elif", condition, elif_block))

        # ---------- else ----------
        elif t == "else":
            i += 1
            if i < len(tokens) and tokens[i][0] == ":":
                i += 1
            block_tokens = []
            while i < len(tokens) and tokens[i][0] not in ("endif",):
                block_tokens.append(tokens[i])
                i += 1
            else_block = parse(block_tokens)
            stmts.append(("else", else_block))

        # ---------- endif ----------
        elif t == "endif":
            i += 1
            break
        elif t in ["+", "-", "*", "/"]:
            if i+3 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: 运算表达式不完整")
            # 运算符处理: var1 = var2 op var3
            var1 = tokens[i-1][0]
            var2 = tokens[i+1][0]
            op = t
            var3 = tokens[i+3][0]
            stmts.append(("op", var1, var2, op, var3))
            i += 4
        elif t == "beep":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: beep语句缺少频率参数")
            freq = int(tokens[i+1][0], 0)
            stmts.append(("beep", freq))
            i += 2

        elif t in ["inb", "inw", "inl", "outb", "outw", "outl"]:
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: {t}指令缺少端口参数")
            port = tokens[i+1][0]
            # 对于out指令，还需要第二个参数（值）
            if t in ["outb", "outw", "outl"]:
                if i+2 >= len(tokens):
                    raise SyntaxError(f"第{line_num}行: {t}指令缺少值参数")
                value = tokens[i+2][0]
                stmts.append((t, port, value))
                i += 3
            else:
                stmts.append((t, port))
                i += 2
        elif t == "set_fat16_fda":
            if i+23 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: set_fat16_fda参数不足")
            values = []
            for j in range(1,24):
                values.append(tokens[i+j][0])
            stmts.append(("fat16_fda", values))
            i += 24
        
        elif t == "read_cmos":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: read_cmos语句缺少参数")
            if i+2 >= len(tokens):
                # 只有一个参数，表示CMOS地址，读取到默认变量
                addr = tokens[i+1][0]
                stmts.append(("read_cmos", addr, None))
                i += 2
            else:
                # 两个参数，第一个是CMOS地址，第二个是存储结果的变量名
                addr = tokens[i+1][0]
                var = tokens[i+2][0]
                stmts.append(("read_cmos", addr, var))
                i += 3
        elif t == "read_fat12_hdr":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: read_fat12_hdr语句缺少参数")
            # 参数可以是变量名或默认为None
            if i+2 < len(tokens) and tokens[i+2][0] not in ["int", "print", "exit", "execute", "sa", "tm", "org", "def", "jmp", "bpb", "asm", "if", "elif", "else", "beep", "entel", "read_cmos", "read_fat12_hdr", "read_fat16_hdr"]:
                var_name = tokens[i+1][0]
                offset = tokens[i+2][0]
                stmts.append(("read_fat12_hdr", var_name, offset))
                i += 3
            else:
                # 只有一个参数，表示使用默认变量名
                offset = tokens[i+1][0]
                stmts.append(("read_fat12_hdr", None, offset))
                i += 2
        elif t == "while":
            # 收集条件表达式
            cond_tokens = []
            i += 1
            while i < len(tokens) and tokens[i][0] != ":":
                cond_tokens.append(tokens[i][0])
                i += 1
            condition = " ".join(cond_tokens)
            
            # 跳过冒号
            if i < len(tokens) and tokens[i][0] == ":":
                i += 1
            
            # 收集while块
            block_tokens = []
            while i < len(tokens) and tokens[i][0] not in ("endwhile",):
                block_tokens.append(tokens[i])
                i += 1
            while_block = parse(block_tokens)
            stmts.append(("while", condition, while_block))
            
            # 跳过endwhile
            if i < len(tokens) and tokens[i][0] == "endwhile":
                i += 1

        elif t == "for":
            # for var = start to end step step
            if i+6 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: for语句不完整")
            
            var_name = tokens[i+1][0]
            if tokens[i+2][0] != "=":
                raise SyntaxError(f"第{line_num}行: for语句语法错误，应为 for var = start to end step step")
            
            start_val = tokens[i+3][0]
            if tokens[i+4][0] != "to":
                raise SyntaxError(f"第{line_num}行: for语句语法错误，应为 for var = start to end step step")
            
            end_val = tokens[i+5][0]
            if tokens[i+6][0] != "step":
                raise SyntaxError(f"第{line_num}行: for语句语法错误，应为 for var = start to end step step")
            
            step_val = tokens[i+7][0]
            i += 8
            
            # 跳过冒号
            if i < len(tokens) and tokens[i][0] == ":":
                i += 1
            
            # 收集for块
            block_tokens = []
            while i < len(tokens) and tokens[i][0] not in ("endfor",):
                block_tokens.append(tokens[i])
                i += 1
            for_block = parse(block_tokens)
            stmts.append(("for", var_name, start_val, end_val, step_val, for_block))
            
            # 跳过endfor
            if i < len(tokens) and tokens[i][0] == "endfor":
                i += 1

        elif t == "read_fat16_hdr":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: read_fat16_hdr语句缺少参数")
            # 参数可以是变量名或默认为None
            if i+2 < len(tokens) and tokens[i+2][0] not in ["int", "print", "exit", "execute", "sa", "tm", "org", "def", "jmp", "bpb", "asm", "if", "elif", "else", "beep", "entel", "read_cmos", "read_fat12_hdr", "read_fat16_hdr"]:
                var_name = tokens[i+1][0]
                offset = tokens[i+2][0]
                stmts.append(("read_fat16_hdr", var_name, offset))
                i += 3
            else:
                # 只有一个参数，表示使用默认变量名
                offset = tokens[i+1][0]
                stmts.append(("read_fat16_hdr", None, offset))
                i += 2
        elif t == "import":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: import语句缺少模块名")
            module_name = tokens[i+1][0]
            stmts.append(("import", module_name))
            i += 2

        elif t == "global":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: global语句缺少函数名")
            func_name = tokens[i+1][0]
            
            # 检查是否有参数数量
            param_count = 0
            if i+3 < len(tokens) and tokens[i+2][0] == "(" and tokens[i+3][0] == ")":
                # 无参数函数
                i += 4
            elif i+4 < len(tokens) and tokens[i+2][0] == "(" and tokens[i+4][0] == ")":
                # 有参数函数
                try:
                    param_count = int(tokens[i+3][0])
                except ValueError:
                    raise SyntaxError(f"第{line_num}行: 参数数量必须是整数")
                i += 5
            else:
                raise SyntaxError(f"第{line_num}行: global语句语法错误，应为 global func_name[(param_count)]")
            
            # 跳过冒号
            if i < len(tokens) and tokens[i][0] == ":":
                i += 1
            
            # 收集函数体
            block_tokens = []
            while i < len(tokens) and tokens[i][0] not in ("endglobal",):
                block_tokens.append(tokens[i])
                i += 1
            func_block = parse(block_tokens)
            stmts.append(("global", func_name, param_count, func_block))
            
            # 跳过endglobal
            if i < len(tokens) and tokens[i][0] == "endglobal":
                i += 1

        elif t == "extern":
            if i+3 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: extern语句不完整")
            func_name = tokens[i+1][0]
            if tokens[i+2][0] != "from":
                raise SyntaxError(f"第{line_num}行: extern语句语法错误，应为 extern func_name from module_name")
            module_name = tokens[i+3][0]
            stmts.append(("extern", func_name, module_name))
            i += 4

        elif t == "call":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: call语句缺少函数名")
            func_name = tokens[i+1][0]
            
            # 收集参数
            args = []
            if i+2 < len(tokens) and tokens[i+2][0] == "(":
                i += 3
                while i < len(tokens) and tokens[i][0] != ")":
                    args.append(tokens[i][0])
                    if i+1 < len(tokens) and tokens[i+1][0] == ",":
                        i += 2
                    else:
                        i += 1
                if i < len(tokens) and tokens[i][0] == ")":
                    i += 1
                else:
                    raise SyntaxError(f"第{line_num}行: call语句缺少右括号")
            else:
                i += 2
            
            stmts.append(("call", func_name, args))

        elif t == "return":
            # return可以带一个返回值，也可以不带
            if i+1 < len(tokens) and tokens[i+1][0] not in ["int", "print", "exit", "execute", "sa", "tm", "org", "def", "jmp", "bpb", "asm", "if", "elif", "else", "beep", "entel", "read_cmos", "read_fat12_hdr", "read_fat16_hdr", "return"]:
                # 有返回值
                ret_val = tokens[i+1][0]
                stmts.append(("return", ret_val))
                i += 2
            else:
                # 无返回值
                stmts.append(("return", None))
                i += 1

        elif t == "cli":
            stmts.append(("cli",))
            i += 1

        elif t == "sti":
            stmts.append(("sti",))
            i += 1

        elif t == "hlt":
            stmts.append(("hlt",))
            i += 1
        elif t == "clear_screen":
            # clear_screen语句不需要参数
            stmts.append(("clear_screen",))
            i += 1

        else:
            raise SyntaxError(f"第{line_num}行: 未知语句: {t}")
    return stmts