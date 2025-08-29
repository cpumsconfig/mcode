# -*- coding: utf-8 -*-
import sys
import os
from mcd.lexer import tokenize
from mcd.parser import parse
from mcd.backend_linux import gen_linux
from mcd.backend_bios import gen_bios

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
