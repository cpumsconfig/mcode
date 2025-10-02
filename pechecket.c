#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// 检查文件是否为有效的PE文件
int checkPEFile(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("错误：无法打开文件 %s\n", filename);
        return -1;
    }

    // 读取DOS头
    IMAGE_DOS_HEADER dosHeader;
    if (fread(&dosHeader, sizeof(dosHeader), 1, file) != 1) {
        fclose(file);
        printf("错误：文件太小，无法读取DOS头\n");
        return -1;
    }

    // 检查DOS签名 "MZ"
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        fclose(file);
        printf("这不是一个有效的PE文件：缺少MZ签名\n");
        return -1;
    }

    // 跳转到PE头位置
    if (fseek(file, dosHeader.e_lfanew, SEEK_SET) != 0) {
        fclose(file);
        printf("错误：无效的PE头偏移\n");
        return -1;
    }

    // 读取PE签名
    DWORD peSignature;
    if (fread(&peSignature, sizeof(peSignature), 1, file) != 1) {
        fclose(file);
        printf("错误：无法读取PE签名\n");
        return -1;
    }

    // 检查PE签名 "PE\0\0"
    if (peSignature != IMAGE_NT_SIGNATURE) {
        fclose(file);
        printf("这不是一个有效的PE文件：缺少PE签名\n");
        return -1;
    }

    // 读取文件头
    IMAGE_FILE_HEADER fileHeader;
    if (fread(&fileHeader, sizeof(fileHeader), 1, file) != 1) {
        fclose(file);
        printf("错误：无法读取文件头\n");
        return -1;
    }

    // 读取可选头（我们只需要读取大小来确定是32位还是64位）
    WORD optionalHeaderSize;
    if (fread(&optionalHeaderSize, sizeof(optionalHeaderSize), 1, file) != 1) {
        fclose(file);
        printf("错误：无法读取可选头大小\n");
        return -1;
    }

    // 回到PE签名后的位置重新读取
    fseek(file, dosHeader.e_lfanew + 4, SEEK_SET);
    fread(&fileHeader, sizeof(fileHeader), 1, file);

    fclose(file);

    // 输出检测结果
    printf("=== PE文件头检测结果 ===\n");
    printf("文件: %s\n", filename);
    printf("状态: 有效的PE文件\n");
    printf("DOS签名: MZ (0x%04X)\n", dosHeader.e_magic);
    printf("PE签名: PE\\0\\0 (0x%08X)\n", peSignature);
    
    // 输出机器类型
    printf("机器类型: ");
    switch (fileHeader.Machine) {
        case IMAGE_FILE_MACHINE_I386:
            printf("x86 (0x%04X)\n", fileHeader.Machine);
            break;
        case IMAGE_FILE_MACHINE_AMD64:
            printf("x64 (0x%04X)\n", fileHeader.Machine);
            break;
        case IMAGE_FILE_MACHINE_ARM:
            printf("ARM (0x%04X)\n", fileHeader.Machine);
            break;
        case IMAGE_FILE_MACHINE_ARM64:
            printf("ARM64 (0x%04X)\n", fileHeader.Machine);
            break;
        case IMAGE_FILE_MACHINE_IA64:
            printf("IA-64 (0x%04X)\n", fileHeader.Machine);
            break;
        default:
            printf("未知 (0x%04X)\n", fileHeader.Machine);
            break;
    }

    // 输出时间戳
    printf("时间戳: 0x%08X\n", fileHeader.TimeDateStamp);
    
    // 输出特征标志
    printf("特征标志: 0x%04X\n", fileHeader.Characteristics);
    if (fileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
        printf("  - 可执行映像\n");
    if (fileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE)
        printf("  - 32位机器\n");
    if (fileHeader.Characteristics & IMAGE_FILE_DLL)
        printf("  - DLL文件\n");
    if (fileHeader.Characteristics & IMAGE_FILE_SYSTEM)
        printf("  - 系统文件\n");

    printf("节区数量: %d\n", fileHeader.NumberOfSections);
    printf("可选头大小: %d 字节\n", fileHeader.SizeOfOptionalHeader);

    return 0;
}

// 简化版本，不依赖Windows头文件
int checkPEFileSimple(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        printf("错误：无法打开文件 %s\n", filename);
        return -1;
    }

    // 检查DOS头
    unsigned short dosMagic;
    fread(&dosMagic, sizeof(dosMagic), 1, file);
    
    if (dosMagic != 0x5A4D) { // "MZ"
        fclose(file);
        printf("这不是一个有效的PE文件：缺少MZ签名\n");
        return -1;
    }

    // 读取PE头偏移
    fseek(file, 0x3C, SEEK_SET);
    long peOffset;
    fread(&peOffset, sizeof(peOffset), 1, file);

    // 检查PE头
    fseek(file, peOffset, SEEK_SET);
    unsigned int peMagic;
    fread(&peMagic, sizeof(peMagic), 1, file);

    if (peMagic != 0x00004550) { // "PE\0\0"
        fclose(file);
        printf("这不是一个有效的PE文件：缺少PE签名\n");
        return -1;
    }

    fclose(file);
    
    printf("=== PE文件头检测结果 ===\n");
    printf("文件: %s\n", filename);
    printf("状态: 有效的PE文件\n");
    printf("DOS签名: MZ (0x%04X)\n", dosMagic);
    printf("PE签名: PE\\0\\0 (0x%08X)\n", peMagic);
    printf("检测完成：文件具有有效的PE结构\n");
    
    return 0;
}

void printUsage() {
    printf("用法: pechecker.exe <exe文件>\n");
    printf("示例: pechecker.exe test.exe\n");
}

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(65001);
    if (argc != 2) {
        printf("错误：参数数量不正确\n");
        printUsage();
        return 1;
    }

    const char* filename = argv[1];
    
    // 尝试使用完整版本检测
    if (checkPEFile(filename) != 0) {
        // 如果完整版本失败，尝试简化版本
        printf("\n尝试简化检测...\n");
        if (checkPEFileSimple(filename) != 0) {
            return 1;
        }
    }

    return 0;
}