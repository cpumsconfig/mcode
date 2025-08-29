# -*- coding: utf-8 -*-
def parse(tokens):
    stmts, i, variables = [], 0, {}  # 添加variables字典初始化
    while i < len(tokens):
        t, line_num = tokens[i]
        


        if t == "int":  # 变量声明
            if i+2 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: 变量声明不完整")
            name = tokens[i+1][0]
            if tokens[i+2][0] != "=":
                raise SyntaxError(f"第{line_num}行: 缺少等号")
            
            # 支持表达式（最多3个token: A op B）
            expr_tokens = []
            j = i+3
            while j < len(tokens) and tokens[j][0] not in ["int", "print", "exit", "execute", "sa", "tm", "org", "def", "jmp", "bpb", "asm", "if", "elif", "else", "beep"]:
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

        elif t in ["ax","bx","cx","dx","al","bl","cl","dl"]:
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
            if i+2 < len(tokens) and tokens[i+2][0] not in ["int", "print", "exit", "execute", "sa", "tm", "org", "def", "jmp", "bpb", "asm", "if", "elif", "else", "beep", "read_cmos", "read_fat12_hdr", "read_fat16_hdr"]:
                var_name = tokens[i+1][0]
                offset = tokens[i+2][0]
                stmts.append(("read_fat12_hdr", var_name, offset))
                i += 3
            else:
                # 只有一个参数，表示使用默认变量名
                offset = tokens[i+1][0]
                stmts.append(("read_fat12_hdr", None, offset))
                i += 2

        elif t == "read_fat16_hdr":
            if i+1 >= len(tokens):
                raise SyntaxError(f"第{line_num}行: read_fat16_hdr语句缺少参数")
            # 参数可以是变量名或默认为None
            if i+2 < len(tokens) and tokens[i+2][0] not in ["int", "print", "exit", "execute", "sa", "tm", "org", "def", "jmp", "bpb", "asm", "if", "elif", "else", "beep", "read_cmos", "read_fat12_hdr", "read_fat16_hdr"]:
                var_name = tokens[i+1][0]
                offset = tokens[i+2][0]
                stmts.append(("read_fat16_hdr", var_name, offset))
                i += 3
            else:
                # 只有一个参数，表示使用默认变量名
                offset = tokens[i+1][0]
                stmts.append(("read_fat16_hdr", None, offset))
                i += 2

        elif t == "return":
            # return可以带一个返回值，也可以不带
            if i+1 < len(tokens) and tokens[i+1][0] not in ["int", "print", "exit", "execute", "sa", "tm", "org", "def", "jmp", "bpb", "asm", "if", "elif", "else", "beep", "read_cmos", "read_fat12_hdr", "read_fat16_hdr", "return"]:
                # 有返回值
                ret_val = tokens[i+1][0]
                stmts.append(("return", ret_val))
                i += 2
            else:
                # 无返回值
                stmts.append(("return", None))
                i += 1



        else:
            raise SyntaxError(f"第{line_num}行: 未知语句: {t}")
    return stmts
