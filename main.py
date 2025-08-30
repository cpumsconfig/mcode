# -*- coding: utf-8 -*-
import sys
import os
from mcd.lexer import tokenize
from mcd.parser import parse
from mcd.backend_linux import gen_linux
from mcd.backend_bios import gen_bios
from mcd.backend_win import gen_windows
if __name__=="__main__":
    if len(sys.argv)<3:
        print("用法: mcd.exe source.m --target=linux|bios|windows [-o output]")
        sys.exit(1)

    if not os.path.exists(sys.argv[1]):
        print(f"错误: 源文件 '{sys.argv[1]}' 不存在")
        sys.exit(1)
    
    # 解析命令行参数
    target = None
    output = None
    for i in range(2, len(sys.argv)):
        if sys.argv[i].startswith("--target="):
            target = sys.argv[i][9:]
        elif sys.argv[i] == "-o" and i+1 < len(sys.argv):
            output = sys.argv[i+1]
    
    if target is None:
        print("错误: 必须指定 --target=linux 或 --target=bios")
        sys.exit(1)
    
    with open(sys.argv[1], encoding="utf-8") as f:
        src=f.read()
    tokens=tokenize(src)
    stmts=parse(tokens)
    
    if target=="linux":
        out=gen_linux(stmts)
        if output is None:
            output="out"
    elif target=="bios":
        out=gen_bios(stmts)
        if output is None:
            output="out.bin"
    elif sys.argv[2]=="--target=windows":
        out=gen_windows(stmts)
        if output is None:
            output="out.exe"
    else:
        raise ValueError("目标必须是 linux 或 bios")
    
    with open(output,"wb") as f: f.write(out)
    print("编译完成:",output)
