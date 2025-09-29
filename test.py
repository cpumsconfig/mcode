from mcd.backend_win import gen_windows

# 创建一个极简的测试程序
test_program = [
    ("print_str", "Hello World"),
    ("exit", "0")
]

try:
    # 生成OBJ文件
    obj_data = gen_windows(test_program)
    
    # 保存OBJ文件
    with open("test.obj", "wb") as f:
        f.write(obj_data)
    print("OBJ文件生成成功!")
    
    # 尝试链接
    import subprocess
    result = subprocess.run(["gcc", "main.c", "test.obj", "-o", "test.exe"], 
                          capture_output=True, text=True)
    if result.returncode == 0:
        print("链接成功! 生成 test.exe")
    else:
        print(f"链接失败: {result.stderr}")
        
except Exception as e:
    print(f"错误: {e}")