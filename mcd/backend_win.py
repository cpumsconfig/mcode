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
    """使用GCC编译Windows程序
    
    Args:
        stmts: 语句列表，每个语句是一个字符串列表
        
    Returns:
        bytes: 编译生成的PE文件内容
        
    Raises:
        InvalidStatementError: 当输入语句无效时
        CompilationError: 当编译失败时
    """
    try:
        if not isinstance(stmts, (list, tuple)):
            raise InvalidStatementError("语句必须是列表")
            
        # 确定架构
        machine_type = IMAGE_FILE_MACHINE_AMD64
        for st in stmts:
            if st[0] == "entel":
                arch = st[1].upper() if len(st) > 1 else "64"
                machine_type = IMAGE_FILE_MACHINE_I386 if arch in ["86", "32", "X86"] else IMAGE_FILE_MACHINE_AMD64
                break

        # 确定子系统类型
        has_gui = any(st[0] == "msgbox" for st in stmts)
        has_console = any(st[0] == "print" for st in stmts)
        subsystem = "-mwindows" if (has_gui and not has_console) else "-mconsole"

        # 生成C源码
        c_code = generate_c_source(stmts, machine_type)
        
        # 创建临时目录
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_c = os.path.join(temp_dir, "temp_program.c")
            temp_exe = os.path.join(temp_dir, "program.exe")
            
            # 写入C源码
            with open(temp_c, "w", encoding="utf-8") as f:
                f.write(c_code)

            # 构建编译命令
            gcc_cmd = ["gcc"]
            if machine_type == IMAGE_FILE_MACHINE_I386:
                gcc_cmd.extend(["-m32"])
            else:
                gcc_cmd.extend(["-m64"])
            gcc_cmd.extend([
                "-O2",  # 优化级别
                "-static",  # 静态链接
                "-static-libgcc",  # 静态链接GCC运行时
                "-static-libstdc++",  # 静态链接C++运行时
                "-Wl,--subsystem,console" if subsystem == "-mconsole" else "-Wl,--subsystem,windows",
                "-Wall",  # 开启所有警告
                "-Wextra",  # 额外警告
                "-Werror",  # 将警告视为错误
                "-Wno-unused-parameter",  # 忽略未使用参数警告
                temp_c,
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

def generate_c_source(stmts: List[List[str]], machine_type: int) -> str:
    """将语句转换为C源码
    
    Args:
        stmts: 语句列表
        machine_type: 目标架构类型
        
    Returns:
        str: 生成的C源码
    """
    c_code = []
    
    # 添加必要的头文件和定义
    headers = [
        "#include <windows.h>",
        "#include <stdio.h>",
        "#include <stdlib.h>",
        "#pragma comment(lib, \"user32.lib\")",
        "#pragma comment(lib, \"kernel32.lib\")",
        "#pragma comment(lib, \"shell32.lib\")",
        "#define _CRT_SECURE_NO_WARNINGS"
    ]
    c_code.extend(headers)
    
    # 添加版本信息结构
    version_info = [
        "#ifndef VS_VERSION_INFO",
        "#define VS_VERSION_INFO 1",
        "#endif",
        "",
        "VS_VERSION_INFO VERSIONINFO",
        "FILEVERSION 1,0,0,0",
        "PRODUCTVERSION 1,0,0,0",
        "FILEFLAGSMASK 0x3fL",
        "#ifdef _DEBUG",
        "FILEFLAGS 0x1L",
        "#else",
        "FILEFLAGS 0x0L",
        "#endif",
        "FILEOS 0x40004L",
        "FILETYPE 0x1L",
        "FILESUBTYPE 0x0L",
        "BEGIN",
        "    BLOCK \"StringFileInfo\"",
        "    BEGIN",
        "        BLOCK \"040904b0\"",
        "        BEGIN",
        "            VALUE \"CompanyName\", \"Generated by PE Builder\"",
        "            VALUE \"FileDescription\", \"Generated Windows Program\"",
        "            VALUE \"FileVersion\", \"1.0.0.0\"",
        "            VALUE \"InternalName\", \"program\"",
        "            VALUE \"LegalCopyright\", \"Copyright (C) 2024\"",
        "            VALUE \"OriginalFilename\", \"program.exe\"",
        "            VALUE \"ProductName\", \"Generated by PE Builder\"",
        "            VALUE \"ProductVersion\", \"1.0.0.0\"",
        "        END",
        "    END",
        "    BLOCK \"VarFileInfo\"",
        "    BEGIN",
        "        VALUE \"Translation\", 0x409, 1200",
        "    END",
        "END"
    ]
    c_code.extend(version_info)
    
    # 生成主函数
    c_code.append("int main() {")
    
    # 处理每个语句
    for st in stmts:
        if not st or st[0] == "entel":
            continue
            
        if st[0] == "msgbox":
            msg = st[1] if len(st) > 1 else "Hello"
            caption = st[2] if len(st) > 2 else "Message"
            # 转义特殊字符
            msg = msg.replace('"', '\\"').replace('\n', '\\n')
            caption = caption.replace('"', '\\"').replace('\n', '\\n')
            c_code.append(f'MessageBoxA(NULL, "{msg}", "{caption}", MB_OK);')
            
        elif st[0] == "print":
            text = st[1] if len(st) > 1 else ""
            # 转义特殊字符
            text = text.replace('"', '\\"').replace('\n', '\\n')
            c_code.append(f'printf("{text}\\n");')
            
        elif st[0] == "exit":
            exit_code = st[1] if len(st) > 1 else 0
            c_code.append(f"return {exit_code};")
            
        elif st[0] == "sleep":
            duration = st[1] if len(st) > 1 else 1000
            c_code.append(f'Sleep({duration});')
            
        elif st[0] == "openurl":
            url = st[1] if len(st) > 1 else ""
            url = url.replace('"', '\\"')
            c_code.append(f'ShellExecuteA(NULL, "open", "{url}", NULL, NULL, SW_SHOW);')
    
    c_code.append("}")
    return "\n".join(c_code)

# 示例用法
if __name__ == "__main__":
    # 32位GUI程序示例
    program_gui = [
        ["entel", "32"],
        ["msgbox", "Hello 32-bit GUI!", "Test"],
        ["sleep", "2000"],
        ["exit", 0]
    ]
    try:
        pe_gui = gen_windows(program_gui)
        with open("pe_gui_32.exe", "wb") as f:
            f.write(pe_gui)
        print("32位GUI程序生成: pe_gui_32.exe")
    except Exception as e:
        print(f"32位生成失败: {e}")

    # 64位控制台程序示例
    program_console = [
        ["entel", "64"],
        ["print", "Hello 64-bit Console!"],
        ["sleep", "1000"],
        ["print", "This is a test program."],
        ["exit", 0]
    ]
    try:
        pe_console = gen_windows(program_console)
        with open("pe_console_64.exe", "wb") as f:
            f.write(pe_console)
        print("64位控制台程序生成: pe_console_64.exe")
    except Exception as e:
        print(f"64位生成失败: {e}")

    # 带URL打开功能的示例
    program_url = [
        ["entel", "64"],
        ["msgbox", "即将打开浏览器", "提示"],
        ["openurl", "https://www.example.com"],
        ["exit", 0]
    ]
    try:
        pe_url = gen_windows(program_url)
        with open("pe_url_64.exe", "wb") as f:
            f.write(pe_url)
        print("64位URL程序生成: pe_url_64.exe")
    except Exception as e:
        print(f"URL程序生成失败: {e}")
