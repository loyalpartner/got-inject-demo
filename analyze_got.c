// analyze_got.c
// 分析进程的GOT表和内存映射，帮助调试hook过程
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <link.h>
#include <dlfcn.h>
#include <elf.h>

// 存储每个共享对象的GOT分析信息的结构体
typedef struct {
    const char *name;
    Elf64_Addr base;
    int found_puts;
    void *puts_got;
    void *puts_addr;
} GotInfo;

// 分析GOT表项的回调函数
static int callback(struct dl_phdr_info *info, size_t size, void *data) {
    if (!info || !data) {
        printf("错误: 回调函数接收到空指针\n");
        return 0;
    }
    
    GotInfo *got_info = (GotInfo*)malloc(sizeof(GotInfo));
    if (!got_info) {
        printf("错误: 无法分配内存给 GotInfo\n");
        return 0;
    }
    
    got_info->name = info->dlpi_name ? strdup(info->dlpi_name) : strdup("[未知]");
    got_info->base = info->dlpi_addr;
    got_info->found_puts = 0;
    got_info->puts_got = NULL;
    got_info->puts_addr = NULL;

    printf("\n=========================================\n");
    printf("模块: %s\n", info->dlpi_name && info->dlpi_name[0] ? info->dlpi_name : "[主程序]");
    printf("基址: 0x%lx\n", (unsigned long)info->dlpi_addr);
    printf("段数量: %d\n", info->dlpi_phnum);

    // 遍历所有段
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const Elf64_Phdr *phdr = &info->dlpi_phdr[i];
        
        // 只关注动态段
        if (phdr->p_type == PT_DYNAMIC) {
            printf("找到动态段 #%d: 地址=0x%lx, 大小=%ld\n", 
                  i, (unsigned long)(info->dlpi_addr + phdr->p_vaddr), 
                  (long)phdr->p_memsz);
            
            // 解析动态段
            Elf64_Dyn *dyn = (Elf64_Dyn *)(info->dlpi_addr + phdr->p_vaddr);
            Elf64_Rela *jmprel = NULL;
            Elf64_Sym *symtab = NULL;
            const char *strtab = NULL;
            size_t relasz = 0;
            
            // 查找重要的动态表项
            for (; dyn->d_tag != DT_NULL; dyn++) {
                switch (dyn->d_tag) {
                    case DT_JMPREL:
                        jmprel = (Elf64_Rela *)(info->dlpi_addr + dyn->d_un.d_ptr);
                        printf("  DT_JMPREL: 0x%lx\n", (unsigned long)jmprel);
                        break;
                    case DT_PLTRELSZ:
                        relasz = dyn->d_un.d_val;
                        printf("  DT_PLTRELSZ: %ld bytes\n", (long)relasz);
                        break;
                    case DT_SYMTAB:
                        symtab = (Elf64_Sym *)(info->dlpi_addr + dyn->d_un.d_ptr);
                        printf("  DT_SYMTAB: 0x%lx\n", (unsigned long)symtab);
                        break;
                    case DT_STRTAB:
                        strtab = (char *)(info->dlpi_addr + dyn->d_un.d_ptr);
                        printf("  DT_STRTAB: 0x%lx\n", (unsigned long)strtab);
                        break;
                }
            }
            
            // 如果所有必要的信息都找到了，解析GOT表
            if (jmprel && symtab && strtab && relasz > 0) {
                printf("\n分析重定位表: %ld 个条目\n", relasz / sizeof(Elf64_Rela));
                
                for (size_t j = 0; j < relasz / sizeof(Elf64_Rela); j++) {
                    Elf64_Rela *rel = &jmprel[j];
                    Elf64_Sym *sym = &symtab[ELF64_R_SYM(rel->r_info)];
                    
                    // 检查符号名称索引是否有效
                    if (sym->st_name >= 1000000) {
                        printf("  警告: 符号名称索引过大: %u, 跳过此条目\n", sym->st_name);
                        continue;
                    }
                    
                    const char *name = &strtab[sym->st_name];
                    // 进行额外的安全检查
                    if (!name || name < (char*)strtab || name > (char*)strtab + 1000000) {
                        printf("  警告: 无效的符号名称指针, 跳过此条目\n");
                        continue;
                    }
                    
                    void **got_entry = (void **)(info->dlpi_addr + rel->r_offset);
                    
                    // 检查GOT地址是否有效
                    if (!got_entry || (unsigned long)got_entry < info->dlpi_addr || 
                        (unsigned long)got_entry > info->dlpi_addr + 0x10000000) {
                        printf("  警告: 无效的GOT条目地址: %p, 跳过此条目\n", got_entry);
                        continue;
                    }
                    
                    // 尝试读取GOT条目的值前检查其可访问性
                    void *func_addr = NULL;
                    if (got_entry) {
                        // 使用安全的访问方式
                        func_addr = *got_entry;
                    }
                    
                    // 只显示puts函数或主要的libc函数
                    if (name && (strcmp(name, "puts") == 0 || 
                        strcmp(name, "printf") == 0 || 
                        strcmp(name, "malloc") == 0 ||
                        strcmp(name, "free") == 0 ||
                        strcmp(name, "open") == 0 || 
                        strcmp(name, "read") == 0)) {
                        
                        printf("  GOT 条目 #%ld: 符号=%s\n", j, name ? name : "未知");
                        printf("    GOT 地址: 0x%lx\n", (unsigned long)got_entry);
                        printf("    函数地址: 0x%lx\n", (unsigned long)func_addr);
                        
                        if (name && strcmp(name, "puts") == 0) {
                            got_info->found_puts = 1;
                            got_info->puts_got = got_entry;
                            got_info->puts_addr = func_addr;
                        }
                    }
                }
            } else {
                printf("缺少解析GOT表所需的信息\n");
            }
        }
    }

    // 将信息添加到结果列表中
    GotInfo **results = (GotInfo**)data;
    int count = 0;
    // 检查结果数组不要越界
    while (results[count] != NULL && count < 99) count++;
    
    if (count < 99) {
        results[count] = got_info;
    } else {
        printf("警告: 结果数组已满, 无法添加更多条目\n");
        free((void*)got_info->name);
        free(got_info);
    }
    
    return 0;
}

// 打印进程内存映射
void print_process_maps() {
    char cmd[256];
    sprintf(cmd, "cat /proc/%d/maps", getpid());
    
    printf("\n\n============= 进程内存映射 =============\n");
    system(cmd);
}

// 直接测试puts函数
void test_puts_function() {
    printf("\n\n============= 测试puts函数 =============\n");
    
    // 获取puts函数地址
    void *puts_addr = dlsym(RTLD_DEFAULT, "puts");
    if (!puts_addr) {
        printf("错误: 无法获取puts函数地址\n");
        return;
    }
    
    printf("puts函数地址: 0x%lx\n", (unsigned long)puts_addr);
    
    // 调用puts函数
    puts("这是通过puts打印的测试消息");
    
    // 使用函数指针调用puts
    int (*puts_ptr)(const char*) = (int(*)(const char*))puts_addr;
    if (puts_ptr) {
        puts_ptr("这是通过函数指针调用puts打印的测试消息");
    }
}

int main() {
    printf("分析进程 %d 的GOT表\n", getpid());
    
    // 为存储结果分配空间并初始化
    GotInfo *results[100];
    memset(results, 0, sizeof(results));
    
    // 遍历所有共享对象
    printf("开始遍历共享对象...\n");
    dl_iterate_phdr(callback, results);
    printf("遍历完成.\n");
    
    // 总结puts函数信息
    printf("\n\n============= puts函数总结 =============\n");
    int i = 0;
    while (i < 100 && results[i] != NULL) {
        if (results[i]->found_puts) {
            printf("在模块 %s 中找到puts:\n", 
                  results[i]->name && results[i]->name[0] ? results[i]->name : "[主程序]");
            printf("  GOT条目地址: 0x%lx\n", (unsigned long)results[i]->puts_got);
            printf("  函数地址: 0x%lx\n", (unsigned long)results[i]->puts_addr);
        }
        i++;
    }
    
    // 打印进程内存映射
    print_process_maps();
    
    // 测试puts函数
    test_puts_function();
    
    // 清理
    i = 0;
    while (i < 100 && results[i] != NULL) {
        if (results[i]->name) {
            free((void*)results[i]->name);
        }
        free(results[i]);
        i++;
    }
    
    return 0;
}