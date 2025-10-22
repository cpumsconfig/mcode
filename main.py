# -*- coding: utf-8 -*-
import sys
import os
import json
from mcd.lexer import tokenize
from mcd.parser import parse
from mcd.backend_linux import gen_linux
from mcd.backend_bios import gen_bios
from mcd.backend_win import gen_windows
from mcd.backend_home import BackendHome
if __name__=="__main__":
    if len(sys.argv)<2:
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
    elif target=="windows":
        out=gen_windows(stmts)
        if output is None:
            output="out.exe"
    else:
        backend = BackendHome()
        out = backend.execute(stmts)
        sys.exit(out)

    
    with open(output, "wb") as f:
        if isinstance(out, int):
            # 如果 out 是整数，需要先转换为字符串，再编码为字节
            f.write(str(out).encode('utf-8'))
        elif isinstance(out, dict):
            # 如果 out 是字典，将其转换为JSON字符串，再编码为字节
            f.write(json.dumps(out, indent=4, ensure_ascii=False).encode('utf-8'))
        elif isinstance(out, str):
            # 如果 out 是字符串，直接编码为字节
            f.write(out.encode('utf-8'))
        else:
            # 如果 out 已经是字节对象，直接写入
            f.write(out)
    print("编译完成:",output)
