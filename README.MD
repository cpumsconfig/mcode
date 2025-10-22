# MCD - 汇编代码生成器

MCD是一个自定义的汇编代码生成器，可以将高级语言风格的代码转换为BIOS兼容的机器码。它支持多种指令和功能，包括变量操作、I/O端口访问、CMOS读取、FAT文件系统头部读取等。

## 功能特性

- **变量操作**：支持整型变量的声明、赋值和运算
- **控制流**：支持if/elif/else条件语句和jmp跳转指令
- **I/O操作**：支持inb/inw/inl和outb/outw/outl指令进行端口I/O
- **CMOS访问**：支持读取CMOS中的数据
- **FAT文件系统**：支持读取FAT12和FAT16文件系统的头部信息
- **函数调用**：支持函数调用和返回机制
- **汇编嵌入**：支持直接嵌入汇编代码
- **BIOS中断**：支持调用BIOS中断

## 安装和使用

### 系统要求

- Python 3.6或更高版本

### 使用方法
```bash
  python main.py <源文件> --target=bios
```
例如：
```bash
  python main.py s.m --target=bios
```
## 语法参考

### 变量声明
```mcd
int a;
```
### 变量赋值
```mcd
int a = 1;
```
### 变量运算
```mcd
int a = 1 + 2;
```
### 条件语句
```mcd
int a = 10;
if a:
  print "a is 10"
elif a == 20:
  print "a is 20"
else:
  print "a is neither 10 nor 20"
```
### 跳转指令
```mcd
def k:
    print "wmk"
jmp k
```
### 端口I/O
```mcd
inb 0x64
outb 0x64, 0x20
```
### CMOS读取
```mcd
# 读取秒
read_cmos 0x00 seconds

# 读取分
read_cmos 0x02 minutes

# 读取小时
read_cmos 0x04 hours

# 读取日
read_cmos 0x07 day

# 读取月
read_cmos 0x08 month

# 读取年
read_cmos 0x09 year

# 打印结果
print hours
print ":"
print minutes
print ":"
print seconds
print " "
print year
print "/"
print month
print "/"
print day
print ""
```
### 寄存器操作
```mcd
# 设置视频模式
ax = 0x0003
execute 0x10
```
### FAT文件系统头部设置(以FAT12为例)
```mcd
set_fat12_BPB 512, 1, 1, 2, 224, 2880, 0xF0, 9, 18, 2, 0, 0, 0, 0
```
### 函数设置
```mcd
def mk:
    print "mk14"
    jmp mk
jmp mk
```
### 汇编嵌入
```mcd
asm("B8 D0 07") # mov ax,bx
```
### 输出
```mcd
print "Hello World!"
```
### 查询文件
```mcd
# 参数顺序：每扇区字节数, 每簇扇区数, 保留扇区数, FAT表数量, 根目录项数, 
#          总扇区数(小容量), 介质描述符, 每FAT扇区数, 每磁道扇区数, 磁头数, 
#          隐藏扇区数, 总扇区数(大容量), 驱动器号, Windows NT标志, 卷标序列号
set_fat12_BPB 512, 1, 1, 2, 224, 2880, 0xF0, 9, 18, 2, 0, 0, 0, 0, 0

# 读取FAT12 BPB中的关键字段
# 读取每扇区字节数 (偏移量0x0B)
read_fat12_hdr bytes_per_sector 0x0B

# 读取每簇扇区数 (偏移量0x0D)
read_fat12_hdr sectors_per_cluster 0x0D

# 读取保留扇区数 (偏移量0x0E)
read_fat12_hdr reserved_sectors 0x0E

# 读取FAT表数量 (偏移量0x10)
read_fat12_hdr fat_count 0x10

# 读取根目录项数 (偏移量0x11)
read_fat12_hdr root_entries 0x11

# 打印结果
print_str "FAT12 BPB 信息:"
print_str "每扇区字节数: "
print_var bytes_per_sector
print_str ""
print_str "每簇扇区数: "
print_var sectors_per_cluster
print_str ""
print_str "保留扇区数: "
print_var reserved_sectors
print_str ""
print_str "FAT表数量: "
print_var fat_count
print_str ""
print_str "根目录项数: "
print_var root_entries
print_str ""

```
### 返回
```mcd
def mk:
    print "mk14"
    return
```
### org
```mcd
org 0x7C00
```
### tm填充字节
```mcd
tm 510-$
```
### sa指定BIOS
```mcd
sa 0x55,0xaa
```
### inb、inw、inl、outb、outw、outl
```mcd

# 测试outb - 向端口0x60输出一个字节
outb 0x60, 0xAA

# 测试outw - 向端口0x60输出一个字
outw 0x60, 0x1234

# 测试outl - 向端口0x60输出一个双字
outl 0x60, 0x12345678

# 测试inb - 从端口0x60读取一个字节
inb 0x60

# 测试inw - 从端口0x60读取一个字
inw 0x60

# 测试inl - 从端口0x60读取一个双字
inl 0x60
```
### beep蜂鸣器
```mcd
beep 1000
```
## 项目结构

项目包含以下脚本：

- `main.py`：主程序，负责解析命令行参数并调用相应的生成器
- `lexer.py`：判断器，将源代码分解为字符
- `parser.py`：判断器，将字符分解为语法树
- `backend_bios.py`：后端，将语法树转换为BIOS兼容的机器码
- `backend_linux.py`：后端，将语法树转换为Linux兼容的机器码
- `backend_win.py`：后端，将语法树转换为Windows兼容的机器码

## 许可证

本项目遵循MPL许可证。

[LICENSE](LICENSE)


## 贡献

如果您有任何建议或想要贡献代码，请随时提交Pull Request或创建Issue。

文件位置：[README.md](README.md)

总行:4265