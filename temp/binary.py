#!/usr/bin/env python3
"""
MBR 二进制文件转 C 头文件工具
用法: 2jz.py -f <输入文件> [-o <输出头文件>]
"""

import argparse
import os

def convert_bin_to_h(input_file, output_file):
    """
    将二进制文件转换为 C 头文件
    """
    try:
        # 读取二进制文件
        with open(input_file, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"错误: 找不到输入文件 '{input_file}'")
        return False
    except Exception as e:
        print(f"读取文件时出错: {e}")
        return False
    
    # 确定数组名称（基于输入文件名）
    array_name = os.path.splitext(os.path.basename(input_file))[0]
    if not array_name.isidentifier():
        array_name = "file_data"
    
    # 写入头文件
    try:
        with open(output_file, 'w') as f:
            # 写入头文件保护符和注释
            guard_name = os.path.splitext(os.path.basename(output_file))[0].upper() + "_H"
            f.write(f"#ifndef {guard_name}\n")
            f.write(f"#define {guard_name}\n\n")
            f.write(f"/* 从 {os.path.basename(input_file)} 生成的十六进制数据 */\n")
            f.write(f"const unsigned char {array_name}[] = {{\n")
            
            # 写入十六进制数据，每行16个字节
            for i in range(0, len(data), 16):
                line = "    "
                for j in range(16):
                    if i + j < len(data):
                        line += f"0x{data[i+j]:02X}, "
                    else:
                        line += "      "
                f.write(line)
                # 添加注释显示偏移量
                f.write(f"/* 0x{i:04X} */\n")
            
            f.write("};\n\n")
            f.write(f"const unsigned int {array_name}_size = sizeof({array_name});\n")
            f.write(f"\n#endif /* {guard_name} */\n")
        
        print(f"成功: 已将 '{input_file}' 转换为 '{output_file}'")
        print(f"数组大小: {len(data)} 字节")
        return True
        
    except Exception as e:
        print(f"写入文件时出错: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="将二进制文件转换为 C 头文件")
    parser.add_argument("-f", "--file", required=True, help="输入文件路径")
    parser.add_argument("-o", "--output", default="a.h", help="输出头文件路径 (默认: a.h)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"错误: 输入文件 '{args.file}' 不存在")
        return
    
    convert_bin_to_h(args.file, args.output)

if __name__ == "__main__":
    main()