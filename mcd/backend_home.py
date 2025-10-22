# -*- coding: utf-8 -*-
class BackendHome:
    def __init__(self):
        self.variables = {}    # name -> ('const', value) or ('mem', value)
        self.labels = {}       # name -> code position
        self.stack = []        # 运行时栈
        self.registers = {     # 模拟寄存器
            'ax': 0, 'bx': 0, 'cx': 0, 'dx': 0,
            'si': 0, 'di': 0, 'sp': 0, 'bp': 0,
            'al': 0, 'ah': 0, 'bl': 0, 'bh': 0,
            'cl': 0, 'ch': 0, 'dl': 0, 'dh': 0
        }
        self.flags = {         # 标志位
            'cf': 0, 'pf': 0, 'af': 0, 'zf': 0,
            'sf': 0, 'tf': 0, 'if': 0, 'df': 0,
            'of': 0
        }
        self.memory = bytearray(65536)  # 模拟内存
        self.output_buffer = []  # 输出缓冲区
        self.functions = {}    # 函数表：name -> (start_pos, param_count)
        self.return_stack = [] # 返回地址栈
        self.call_stack = []    # 调用栈，用于调试
        self.modules = {}      # 已加载的模块
        self.arrays = {}       # 数组：name -> [values]
        self.structs = {}      # 结构体定义：name -> {field: type}
        self.instances = {}    # 结构体实例：name -> {field: value}
        self.loop_stack = []   # 循环栈，用于break/continue
        self.current_scope = None  # 当前作用域
        self.scopes = []       # 作用域栈

    def enter_scope(self, scope_name):
        """进入新作用域"""
        self.scopes.append(self.current_scope)
        self.current_scope = scope_name

    def exit_scope(self):
        """退出当前作用域"""
        if self.scopes:
            self.current_scope = self.scopes.pop()

    def var_get(self, name):
        """获取变量值"""
        if name not in self.variables:
            self.variables[name] = ('mem', 0)
        typ, val = self.variables[name]
        if typ == 'const':
            return val
        else:
            return val

    def var_set(self, name, value):
        """设置变量值"""
        if name not in self.variables:
            self.variables[name] = ('mem', 0)
        typ, _ = self.variables[name]
        if typ == 'const':
            self.variables[name] = ('const', value)
        else:
            self.variables[name] = ('mem', value)

    def push_stack(self, value):
        """压栈"""
        self.stack.append(value)
        self.registers['sp'] += 2

    def pop_stack(self):
        """弹栈"""
        if not self.stack:
            raise ValueError("Stack underflow")
        self.registers['sp'] -= 2
        return self.stack.pop()

    def update_flags(self, result):
        """更新标志位"""
        self.flags['zf'] = 1 if result == 0 else 0
        self.flags['sf'] = 1 if result < 0 else 0
        self.flags['pf'] = 1 if bin(result).count('1') % 2 == 0 else 0
        self.flags['cf'] = 1 if result > 0xFFFF else 0

    def array_get(self, name, index):
        """获取数组元素"""
        if name not in self.arrays:
            raise ValueError(f"Array {name} not found")
        arr = self.arrays[name]
        if index < 0 or index >= len(arr):
            raise ValueError(f"Array index {index} out of bounds")
        return arr[index]

    def array_set(self, name, index, value):
        """设置数组元素"""
        if name not in self.arrays:
            self.arrays[name] = []
        arr = self.arrays[name]
        if index < 0:
            raise ValueError("Array index cannot be negative")
        # 扩展数组如果需要
        while index >= len(arr):
            arr.append(0)
        arr[index] = value

    def struct_get(self, struct_name, field):
        """获取结构体字段值"""
        if struct_name not in self.instances:
            raise ValueError(f"Struct instance {struct_name} not found")
        instance = self.instances[struct_name]
        if field not in instance:
            raise ValueError(f"Field {field} not found in struct {struct_name}")
        return instance[field]

    def struct_set(self, struct_name, field, value):
        """设置结构体字段值"""
        if struct_name not in self.instances:
            self.instances[struct_name] = {}
        instance = self.instances[struct_name]
        instance[field] = value

    def process_statement(self, stmt):
        """处理单个语句"""
        t = stmt[0]
        
        if t == "let":
            # 变量声明
            name, val = stmt[1], stmt[2]
            try:
                ival = int(val)
                self.variables[name] = ('const', ival)
            except:
                self.variables[name] = ('mem', 0)

        elif t == "array":
            # 数组声明
            name, size = stmt[1], int(stmt[2])
            self.arrays[name] = [0] * size

        elif t == "struct":
            # 结构体定义
            name, fields = stmt[1], stmt[2]
            self.structs[name] = fields

        elif t == "new":
            # 创建结构体实例
            struct_name, instance_name = stmt[1], stmt[2]
            if struct_name not in self.structs:
                raise ValueError(f"Struct {struct_name} not defined")
            self.instances[instance_name] = {field: 0 for field in self.structs[struct_name]}

        elif t == "print_str":
            # 打印字符串
            s = stmt[1] + "\n"
            self.output_buffer.append(s)

        elif t == "print_var":
            # 打印变量
            name = stmt[1]
            val = self.var_get(name)
            self.output_buffer.append(str(val) + "\n")

        elif t == "print_array":
            # 打印数组
            name = stmt[1]
            if name not in self.arrays:
                raise ValueError(f"Array {name} not found")
            arr = self.arrays[name]
            self.output_buffer.append(f"[{', '.join(map(str, arr))}]\n")

        elif t == "mov":
            # 移动数据
            reg, val = stmt[1], stmt[2]
            try:
                ival = int(val)
                self.registers[reg] = ival
            except:
                v = self.var_get(val)
                self.registers[reg] = v

        elif t == "op":
            # 算术运算
            dest, src1, oper, src2 = stmt[1], stmt[2], stmt[3], stmt[4]
            try:
                v1 = int(src1)
            except:
                v1 = self.var_get(src1)
            try:
                v2 = int(src2)
            except:
                v2 = self.var_get(src2)
            
            if oper == '+':
                result = v1 + v2
            elif oper == '-':
                result = v1 - v2
            elif oper == '*':
                result = v1 * v2
            elif oper == '/':
                result = v1 // v2 if v2 != 0 else 0
            elif oper == '%':
                result = v1 % v2 if v2 != 0 else 0
            elif oper == '&':
                result = v1 & v2
            elif oper == '|':
                result = v1 | v2
            elif oper == '^':
                result = v1 ^ v2
            elif oper == '<<':
                result = v1 << v2
            elif oper == '>>':
                result = v1 >> v2
            else:
                raise ValueError("Unsupported operation: " + oper)
            
            self.var_set(dest, result)
            self.update_flags(result)

        elif t == "array_op":
            # 数组操作
            array_name, index, oper, val = stmt[1], stmt[2], stmt[3], stmt[4]
            try:
                idx = int(index)
            except:
                idx = self.var_get(index)
            try:
                v = int(val)
            except:
                v = self.var_get(val)
            
            current = self.array_get(array_name, idx)
            if oper == '+':
                result = current + v
            elif oper == '-':
                result = current - v
            elif oper == '*':
                result = current * v
            elif oper == '/':
                result = current // v if v != 0 else 0
            elif oper == '%':
                result = current % v if v != 0 else 0
            elif oper == '=':
                result = v
            else:
                raise ValueError("Unsupported array operation: " + oper)
            
            self.array_set(array_name, idx, result)

        elif t in ["and", "or", "xor", "not"]:
            # 位操作
            if t == "not":
                reg = stmt[1]
                self.registers[reg] = ~self.registers[reg]
                self.update_flags(self.registers[reg])
            else:
                reg1, val = stmt[1], stmt[2]
                try:
                    v2 = int(val)
                except:
                    v2 = self.var_get(val)
                
                if t == "and":
                    self.registers[reg1] &= v2
                elif t == "or":
                    self.registers[reg1] |= v2
                elif t == "xor":
                    self.registers[reg1] ^= v2
                
                self.update_flags(self.registers[reg1])

        elif t in ["shl", "shr", "sar"]:
            # 移位操作
            reg, count = stmt[1], stmt[2]
            try:
                cnt = int(count)
            except:
                cnt = self.var_get(count)
            
            if t == "shl":
                self.registers[reg] <<= cnt
            elif t == "shr":
                self.registers[reg] >>= cnt
            elif t == "sar":
                self.registers[reg] = int(self.registers[reg]) >> cnt
            
            self.update_flags(self.registers[reg])

        elif t == "cmp":
            # 比较操作
            reg1, val = stmt[1], stmt[2]
            try:
                v1 = self.registers[reg1]
                v2 = int(val)
            except:
                v2 = self.var_get(val)
            
            result = v1 - v2
            self.update_flags(result)
            self.flags['cf'] = 1 if v1 < v2 else 0
            self.flags['of'] = 1 if (v1 > 0 and v2 < 0 and result < 0) or (v1 < 0 and v2 > 0 and result > 0) else 0

        elif t in ["jmp", "je", "jz", "jne", "jnz", "js", "jns", "jo", "jno", "jb", "jc", "jnb", "jnc"]:
            # 跳转指令
            label = stmt[1]
            should_jump = False
            
            if t == "jmp":
                should_jump = True
            elif t in ["je", "jz"]:
                should_jump = self.flags['zf'] == 1
            elif t in ["jne", "jnz"]:
                should_jump = self.flags['zf'] == 0
            elif t == "js":
                should_jump = self.flags['sf'] == 1
            elif t == "jns":
                should_jump = self.flags['sf'] == 0
            elif t == "jo":
                should_jump = self.flags['of'] == 1
            elif t == "jno":
                should_jump = self.flags['of'] == 0
            elif t in ["jb", "jc"]:
                should_jump = self.flags['cf'] == 1
            elif t in ["jnb", "jnc"]:
                should_jump = self.flags['cf'] == 0
            
            if should_jump:
                if label not in self.labels:
                    raise ValueError("Unknown label: " + label)
                return self.labels[label]

        elif t == "label":
            # 标签
            self.labels[stmt[1]] = len(self.labels)

        elif t == "call":
            # 函数调用
            func_name = stmt[1]
            args = stmt[2] if len(stmt) > 2 else []
            
            if func_name not in self.functions:
                raise ValueError("Unknown function: " + func_name)
            
            # 保存返回地址
            self.return_stack.append(len(self.labels))
            
            # 压入参数
            for arg in reversed(args):
                try:
                    val = int(arg)
                except:
                    val = self.var_get(arg)
                self.push_stack(val)
            
            # 跳转到函数
            return self.functions[func_name][0]

        elif t == "return":
            # 函数返回
            if not self.return_stack:
                # 如果不在函数调用中，将返回值存储在特殊变量中
                ret_val = None
                if len(stmt) > 1:
                    try:
                        ret_val = int(stmt[1])
                    except:
                        ret_val = self.var_get(stmt[1])
                self.var_set("__return__", ret_val)
                return -1  # 直接退出程序
            
            # 获取返回值
            ret_val = None
            if len(stmt) > 1:
                try:
                    ret_val = int(stmt[1])
                except:
                    ret_val = self.var_get(stmt[1])
            
            # 弹出参数
            param_count = len(self.call_stack[-1][2]) if self.call_stack else 0
            for _ in range(param_count):
                self.pop_stack()
            
            # 返回到调用点
            return self.return_stack.pop()


        elif t == "global":
            # 全局函数声明
            func_name, param_count, body = stmt[1], stmt[2], stmt[3]
            self.functions[func_name] = (len(self.labels), param_count)

        elif t in ["push", "pop"]:
            # 堆栈操作
            if t == "push":
                operand = stmt[1]
                try:
                    val = int(operand)
                except:
                    val = self.var_get(operand)
                self.push_stack(val)
            else:  # pop
                reg = stmt[1]
                self.registers[reg] = self.pop_stack()

        elif t in ["inc", "dec"]:
            # 增减操作
            reg = stmt[1]
            if t == "inc":
                self.registers[reg] += 1
            else:
                self.registers[reg] -= 1
            self.update_flags(self.registers[reg])

        elif t == "for":
            # for循环
            var_name, start, end, step, body = stmt[1], stmt[2], stmt[3], stmt[4], stmt[5]
            try:
                start_val = int(start)
            except:
                start_val = self.var_get(start)
            try:
                end_val = int(end)
            except:
                end_val = self.var_get(end)
            try:
                step_val = int(step)
            except:
                step_val = self.var_get(step)
            
            # 设置循环变量
            self.var_set(var_name, start_val)
            
            # 创建循环标签
            loop_start = f"for_{var_name}_start"
            loop_end = f"for_{var_name}_end"
            self.labels[loop_start] = len(self.labels)
            
            # 检查循环条件
            current = self.var_get(var_name)
            if (step_val > 0 and current <= end_val) or (step_val < 0 and current >= end_val):
                # 执行循环体
                for s in body:
                    ret = self.process_statement(s)
                    if ret == loop_end:  # break
                        break
                    elif ret == loop_start:  # continue
                        continue
                    elif ret is not None and ret != -1:
                        return ret
                
                # 更新循环变量
                new_val = current + step_val
                self.var_set(var_name, new_val)
                
                # 跳回循环开始
                return self.labels[loop_start]
            
            # 设置循环结束标签
            self.labels[loop_end] = len(self.labels)

        elif t == "while":
            # while循环
            condition, body = stmt[1], stmt[2]
            
            # 创建循环标签
            loop_start = f"while_{len(self.loop_stack)}_start"
            loop_end = f"while_{len(self.loop_stack)}_end"
            self.loop_stack.append((loop_start, loop_end))
            self.labels[loop_start] = len(self.labels)
            
            # 检查条件
            cond_val = self.var_get(condition)
            if cond_val != 0:
                # 执行循环体
                for s in body:
                    ret = self.process_statement(s)
                    if ret == loop_end:  # break
                        break
                    elif ret == loop_start:  # continue
                        continue
                    elif ret is not None and ret != -1:
                        self.loop_stack.pop()
                        return ret
                
                # 跳回循环开始
                self.loop_stack.pop()
                return self.labels[loop_start]
            
            # 设置循环结束标签
            self.labels[loop_end] = len(self.labels)
            self.loop_stack.pop()

        elif t == "break":
            # break语句
            if not self.loop_stack:
                raise ValueError("Break outside loop")
            _, loop_end = self.loop_stack[-1]
            return loop_end

        elif t == "continue":
            # continue语句
            if not self.loop_stack:
                raise ValueError("Continue outside loop")
            loop_start, _ = self.loop_stack[-1]
            return loop_start

        elif t == "if":
            # if语句
            condition, then_body = stmt[1], stmt[2]
            else_body = stmt[3] if len(stmt) > 3 else []
            
            # 检查条件
            cond_val = self.var_get(condition)
            if cond_val != 0:
                # 执行then分支
                for s in then_body:
                    ret = self.process_statement(s)
                    if ret is not None and ret != -1:
                        return ret
            elif else_body:
                # 执行else分支
                for s in else_body:
                    ret = self.process_statement(s)
                    if ret is not None and ret != -1:
                        return ret

        elif t == "import":
            # 导入模块
            module_name = stmt[1]
            if module_name not in self.modules:
                # 这里简化处理，实际应该从文件加载模块
                self.modules[module_name] = {
                    'functions': {},
                    'variables': {},
                    'arrays': {},
                    'structs': {}
                }
        elif t == "msgbox":
            # 显示消息框
            msg = stmt[1] if len(stmt) > 1 else "Hello"
            caption = stmt[2] if len(stmt) > 2 else "Message"
            # 处理字符串：修复转义符残留和不对称引号问题
            # 改动1：先替换所有转义引号\"为正常引号"，消除转义符干扰
            msg = msg.replace('\\"', '"')
            caption = caption.replace('\\"', '"')
            # 改动2：用strip('"')去除首尾所有"（无论是否成对），替代原“首尾都为"才处理”的逻辑
            if msg.startswith('"') or msg.endswith('"'):
                msg = msg.strip('"')
            if caption.startswith('"') or caption.endswith('"'):
                caption = caption.strip('"')
            # （可选）改动3：清理首尾意外空白（如输入"  Hello  "）
            msg = msg.strip()
            caption = caption.strip()

            try:
                import ctypes
                # 显式指定参数类型，确保Unicode兼容（沿用之前修复的逻辑）
                ctypes.windll.user32.MessageBoxW.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_wchar_p,
                    ctypes.c_wchar_p,
                    ctypes.c_uint
                ]
                ctypes.windll.user32.MessageBoxW(None, msg, caption, 0)
            except (ImportError, AttributeError, ctypes.ArgumentError):
                self.output_buffer.append(f"[{caption}] {msg}\n")


        elif t == "exit":
            # 退出
            return -1

        elif t == "clear_screen":
            # 清屏
            self.output_buffer.append("\033[2J\033[H")

        elif t == "beep":
            # 发声
            self.output_buffer.append("\a")

        elif t == "nop":
            # 空操作
            pass

        return None

    def execute(self, stmts):
        """执行语句列表"""
        self.output_buffer.clear()
        pc = 0  # 程序计数器
        return_value = 0  # 默认返回值为0
        
        while pc < len(stmts):
            stmt = stmts[pc]
            ret = self.process_statement(stmt)
            
            if ret == -1:  # exit 或 return
                # 检查是否有存储的返回值
                if "__return__" in self.variables:
                    return_value = self.var_get("__return__")
                break
            elif ret is not None:  # 跳转
                pc = ret
            else:
                pc += 1
        
        # 输出程序结果
        output = ''.join(self.output_buffer)
        print(output, end='')
        
        return return_value
# 示例使用
if __name__ == "__main__":
    backend = BackendHome()
    
    # 示例程序
    program = [
        ("array", "numbers", "5"),  # 创建大小为5的数组
        ("for", "i", "0", "4", "1", [  # 循环初始化数组
            ("array_op", "numbers", "i", "=", "i")
        ]),
        ("print_array", "numbers"),  # 打印数组
        
        ("struct", "Point", ["x", "y"]),  # 定义Point结构体
        ("new", "p1", "Point"),  # 创建Point实例
        ("struct_set", "p1", "x", "10"),  # 设置字段值
        ("struct_set", "p1", "y", "20"),
        
        ("global", "distance", 2, [  # 计算距离的函数
            ("pop", "bx"),  # 获取y参数
            ("pop", "ax"),  # 获取x参数
            ("op", "temp", "ax", "*", "ax"),
            ("op", "temp2", "bx", "*", "bx"),
            ("op", "result", "temp", "+", "temp2"),
            ("return", "result")
        ]),
        
        ("call", "distance", [
            ("struct_get", "p1", "x"),
            ("struct_get", "p1", "y")
        ]),
        ("print_var", "result"),
        ("exit",)
    ]
    
    result = backend.execute(program)
    print("Program output:")
    print(result)
