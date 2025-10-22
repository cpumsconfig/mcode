# -*- coding: utf-8 -*-
import os
import subprocess
import logging
import tempfile
import shutil
from typing import List, Union, Optional
import datetime

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('log.txt', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# PE文件结构常量
IMAGE_DOS_SIGNATURE = 0x5A4D      # MZ
IMAGE_NT_SIGNATURE = 0x00004550  # PE00
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

# 错误码定义
class PEBuilderError(Exception):
    """PE构建器基础异常类"""
    def __init__(self, message):
        super().__init__(message)
        logger.error(f"[PE Builder Error] {message}")

class CompilationError(PEBuilderError):
    """编译错误"""
    def __init__(self, message):
        super().__init__(message)
        logger.error(f"[Compilation Error] {message}")

class InvalidStatementError(PEBuilderError):
    """无效语句错误"""
    def __init__(self, message):
        super().__init__(message)
        logger.error(f"[Invalid Statement Error] {message}")

def gen_windows(stmts: List[List[str]]) -> bytes:
    """使用GCC编译Windows程序"""
    try:
        logger.info("开始生成Windows PE文件")
        logger.debug(f"输入语句数量: {len(stmts)}")
        
        if not isinstance(stmts, (list, tuple)):
            raise InvalidStatementError("语句必须是列表")

        # 确定子系统类型
        has_gui = any(st[0] == "msgbox" for st in stmts)
        has_console = any(st[0] in ("print", "print_str") for st in stmts)
        subsystem = "-mwindows" if (has_gui and not has_console) else "-mconsole"
        logger.info(f"子系统类型: {subsystem}")

        # 生成C源码
        logger.info("开始生成C源码")
        c_code = generate_c_source(stmts)
        logger.debug("C源码生成完成")

        
        # 创建临时目录
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_c = os.path.join(temp_dir, "temp_program.c")
            temp_exe = os.path.join(temp_dir, "program.exe")
            
            # 写入C源码
            with open(temp_c, "w", encoding="utf-8") as f:
                f.write(c_code)

            # 构建编译命令
            gcc_cmd = ["gcc"]
            gcc_cmd.extend([
                "-O2",
                "-Wall",
                "-Wno-unused-parameter",
                "-static",
                "-static-libgcc",
                "-static-libstdc++",
                "-Wl,--subsystem,console",
                temp_c,
                "-luser32",
                "-lkernel32",
                "-lshell32",
                "-o", temp_exe
            ])

            # 执行编译
            try:
                result = subprocess.run(
                    gcc_cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                    cwd=temp_dir
                )
                if result.stdout:
                    logger.debug(f"GCC输出: {result.stdout}")
                if result.stderr:
                    logger.warning(f"GCC警告: {result.stderr}")
                
                # 读取编译结果
                with open(temp_exe, "rb") as f:
                    pe_content = f.read()
                
                logger.info(f"编译成功，生成PE文件大小: {len(pe_content)}字节")
                return pe_content
                
            except subprocess.CalledProcessError as e:
                error_msg = f"GCC编译失败: {e.stderr if e.stderr else str(e)}"
                logger.error(error_msg)
                raise CompilationError(error_msg)

    except Exception as e:
        if isinstance(e, (InvalidStatementError, CompilationError)):
            raise
        logger.error(f"程序生成失败: {str(e)}")
        raise PEBuilderError(f"程序生成失败: {str(e)}")

def generate_c_source(stmts: List[List[str]]) -> str:
    """将语句转换为C源码"""
    logger.debug("开始转换语句为C源码")
    c_code = []
    
    # 添加必要的头文件和定义
    headers = [
        "#include <windows.h>",
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#include <locale.h>",
        "#define _CRT_SECURE_NO_WARNINGS"
    ]
    c_code.extend(headers)
    logger.debug("已添加头文件和定义")
    
    # 生成主函数
    c_code.append("int main() {")
    logger.debug("开始处理语句列表")
    # 支持中文输出
    c_code.append("system(\"chcp 65001 >nul\");")
    c_code.append("SetConsoleOutputCP(CP_UTF8);")
    c_code.append("SetConsoleCP(CP_UTF8);")

    
    # 处理每个语句
    for idx, st in enumerate(stmts):
        if not st:
            continue
        logger.debug(f"处理语句 {idx + 1}: {st[0]}")

            
        if st[0] == "msgbox":
            msg = st[1] if len(st) > 1 else "Hello"
            caption = st[2] if len(st) > 2 else "Message"
            # 转义特殊字符并转换为宽字符
            msg = msg.replace('"', '\\"').replace('\n', '\\n')
            caption = caption.replace('"', '\\"').replace('\n', '\\n')
            c_code.append(f'MessageBoxW(NULL, L"{msg}", L"{caption}", MB_OK);')
            
        elif st[0] == "print" or st[0] == "print_str":
            text = st[1] if len(st) > 1 else ""
            # 转义特殊字符
            text = text.replace('"', '\\"').replace('\n', '\\n')
            c_code.append(f'printf("{text}\\n");')
            
        elif st[0] == "exit":
            exit_code = st[1] if len(st) > 1 else 0
            c_code.append(f"return {exit_code};")
            
        elif st[0] == "clear_screen":
            c_code.append('system("cls");')

        elif st[0] == "beep":
            freq = st[1] if len(st) > 1 else 750
            duration = st[2] if len(st) > 2 else 300
            c_code.append(f'Beep({freq}, {duration});')

        elif st[0] == "sleep":
            duration = st[1] if len(st) > 1 else 1000
            c_code.append(f'Sleep({duration});')

        elif st[0] == "openurl":
            url = st[1] if len(st) > 1 else ""
            url = url.replace('"', '\\"')
            c_code.append(f'ShellExecuteA(NULL, "open", "{url}", NULL, NULL, SW_SHOW);')
    
    # 如果没有明确的exit语句，添加默认返回
    if not any(st[0] == "exit" for st in stmts):
        c_code.append("return 0;")
    
    c_code.append("}")
    
    # 记录完整的C代码到日志
    full_code = "\n".join(c_code)
    logger.info("生成的C代码:\n" + full_code)
    
    return full_code


# 示例用法
if __name__ == "__main__":
    # GUI程序示例
    program_gui = [
        ["msgbox", "你好，GUI！", "测试"],
        ["sleep", "2000"],
        ["exit", 0]
    ]
    try:
        pe_gui = gen_windows(program_gui)
        with open("pe_gui.exe", "wb") as f:
            f.write(pe_gui)
        print("GUI程序生成: pe_gui.exe")
    except Exception as e:
        print(f"GUI生成失败: {e}")

    # 控制台程序示例
    program_console = [
        ["print_str", "你好，控制台！"],
        ["sleep", "1000"],
        ["print_str", "这是一个测试程序。"],
        ["exit", 0]
    ]
    try:
        pe_console = gen_windows(program_console)
        with open("pe_console.exe", "wb") as f:
            f.write(pe_console)
        print("控制台程序生成: pe_console.exe")
    except Exception as e:
        print(f"控制台生成失败: {e}")

    # 带URL打开功能的示例
    program_url = [
        ["msgbox", "即将打开浏览器", "提示"],
        ["openurl", "https://www.example.com"],
        ["exit", 0]
    ]
    try:
        pe_url = gen_windows(program_url)
        with open("pe_url.exe", "wb") as f:
            f.write(pe_url)
        print("URL程序生成: pe_url.exe")
    except Exception as e:
        print(f"URL程序生成失败: {e}")
