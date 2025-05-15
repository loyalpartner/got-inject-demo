// hook.c - 更稳健的GOT钩子实现
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <link.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <unistd.h>

// 保存原始的 puts 函数指针
static int (*real_puts)(const char *) = NULL;

// 一个标志，指示钩子是否已初始化
static int hook_initialized = 0;

// 我们的钩子函数替换 puts
int my_puts(const char *str) {
    // 确保我们不会递归调用自己 (通过fprintf内部调用puts)
    if (!hook_initialized || !real_puts) {
        write(STDERR_FILENO, "[HOOK ERROR] 未初始化\n", 22);
        return -1;
    }
    
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "[HOOK] 拦截了: %s\n", str);
    write(STDERR_FILENO, buffer, strlen(buffer));
    
    return real_puts("[HOOKED] I've intercepted your puts!");
}

// 直接在目标进程中查找并修改puts的GOT条目
static void find_and_hook_target() {
    void *handle;
    void *puts_addr;
    Dl_info info;
    
    // 先获取目标进程中puts的实际地址
    handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "[ERROR] 无法打开主程序: %s\n", dlerror());
        return;
    }
    
    // 获取puts函数在主程序中的GOT条目
    void **puts_got_ptr = dlsym(handle, "puts");
    if (!puts_got_ptr) {
        fprintf(stderr, "[ERROR] 在主程序中找不到puts: %s\n", dlerror());
        dlclose(handle);
        return;
    }
    
    fprintf(stderr, "[INFO] 主程序中puts的地址: %p\n", puts_got_ptr);
    
    // 获取puts的真实地址
    puts_addr = dlsym(RTLD_NEXT, "puts");
    if (!puts_addr) {
        fprintf(stderr, "[ERROR] 无法获取puts的真实地址: %s\n", dlerror());
        dlclose(handle);
        return;
    }
    
    fprintf(stderr, "[INFO] puts的真实地址: %p\n", puts_addr);
    
    // 在libc中查找puts确认
    handle = dlopen("libc.so.6", RTLD_LAZY);
    if (handle) {
        void *libc_puts = dlsym(handle, "puts");
        if (libc_puts) {
            fprintf(stderr, "[INFO] libc中puts的地址: %p\n", libc_puts);
            
            // 获取libc puts的信息
            if (dladdr(libc_puts, &info) != 0) {
                fprintf(stderr, "[INFO] libc puts所在文件: %s\n", info.dli_fname);
            }
        }
        dlclose(handle);
    }
    
    // 直接在主程序中查找puts的GOT条目
    fprintf(stderr, "[INFO] 尝试在主程序中直接查找puts GOT条目\n");
    
    // 打开主程序，确保我们有一个有效的句柄
    handle = dlopen(NULL, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "[ERROR] 无法打开主程序: %s\n", dlerror());
        return;
    }
    
    // 尝试定位主程序中puts的GOT条目
    void *main_puts = dlsym(handle, "puts");
    if (!main_puts) {
        fprintf(stderr, "[ERROR] 无法获取主程序中puts的地址: %s\n", dlerror());
        dlclose(handle);
        return;
    }
    
    fprintf(stderr, "[INFO] 主程序中puts的引用: %p\n", main_puts);
    fprintf(stderr, "[INFO] 尝试直接修改GOT条目\n");
    
    // 假设main_puts是一个指向puts的GOT条目的指针
    void **got_entry = (void**)main_puts;
    
    // 检查这个地址是否看起来像一个有效的指针
    if (got_entry && *got_entry) {
        fprintf(stderr, "[INFO] 当前GOT条目值: %p\n", *got_entry);
        
        // 保存原始函数指针
        real_puts = *got_entry;
        
        // 修改GOT条目指向我们的钩子
        *got_entry = my_puts;
        
        fprintf(stderr, "[SUCCESS] 成功修改GOT条目从 %p 到 %p\n", 
                real_puts, my_puts);
        
        hook_initialized = 1;
    } else {
        fprintf(stderr, "[ERROR] GOT条目指针无效: %p\n", got_entry);
        // 尝试直接获取puts的真实地址
        real_puts = puts;
        if (real_puts) {
            fprintf(stderr, "[INFO] 从全局符号表获取的puts: %p\n", real_puts);
            hook_initialized = 1;
        }
    }
    
    dlclose(handle);
}

// 使用传统的dl_iterate_phdr方法查找并钩取puts
int phdr_callback(struct dl_phdr_info *info, size_t size, void *data) {
    if (!info) return 0;
    
    fprintf(stderr, "[DEBUG] 检查模块: %s\n", 
            info->dlpi_name && info->dlpi_name[0] ? info->dlpi_name : "[主程序]");
    
    // 优先检查主程序
    if (!info->dlpi_name || !info->dlpi_name[0]) {
        fprintf(stderr, "[INFO] 找到主程序, 基址: %p\n", (void*)info->dlpi_addr);
        
        Elf64_Addr base = info->dlpi_addr;

        for (int i = 0; i < info->dlpi_phnum; ++i) {
            const Elf64_Phdr *phdr = &info->dlpi_phdr[i];
            if (phdr->p_type == PT_DYNAMIC) {
                Elf64_Dyn *dyn = (Elf64_Dyn *)(base + phdr->p_vaddr);
                Elf64_Rela *jmprel = NULL;
                Elf64_Sym *symtab = NULL;
                const char *strtab = NULL;
                size_t relasz = 0;

                fprintf(stderr, "[DEBUG] 找到动态段: 地址=%p, 大小=%lu\n", 
                        (void*)(base + phdr->p_vaddr), (unsigned long)phdr->p_memsz);

                for (; dyn->d_tag != DT_NULL; ++dyn) {
                    if (dyn->d_tag == DT_JMPREL) {
                        jmprel = (Elf64_Rela *)(base + dyn->d_un.d_ptr);
                        fprintf(stderr, "[DEBUG] DT_JMPREL: %p\n", jmprel);
                    }
                    if (dyn->d_tag == DT_PLTRELSZ) {
                        relasz = dyn->d_un.d_val;
                        fprintf(stderr, "[DEBUG] DT_PLTRELSZ: %lu\n", (unsigned long)relasz);
                    }
                    if (dyn->d_tag == DT_SYMTAB) {
                        symtab = (Elf64_Sym *)(base + dyn->d_un.d_ptr);
                        fprintf(stderr, "[DEBUG] DT_SYMTAB: %p\n", symtab);
                    }
                    if (dyn->d_tag == DT_STRTAB) {
                        strtab = (char *)(base + dyn->d_un.d_ptr);
                        fprintf(stderr, "[DEBUG] DT_STRTAB: %p\n", strtab);
                    }
                }

                if (!jmprel || !symtab || !strtab || relasz == 0) {
                    fprintf(stderr, "[DEBUG] 模块缺少必要的动态信息\n");
                    continue;
                }
                
                fprintf(stderr, "[DEBUG] 扫描GOT表, %lu个条目\n", relasz / sizeof(Elf64_Rela));

                for (size_t j = 0; j < relasz / sizeof(Elf64_Rela); ++j) {
                    Elf64_Rela *r = &jmprel[j];
                    
                    // 检查索引是否有效
                    if (ELF64_R_SYM(r->r_info) >= 10000) {
                        fprintf(stderr, "[WARN] 符号索引过大: %lu\n", ELF64_R_SYM(r->r_info));
                        continue;
                    }
                    
                    Elf64_Sym *sym = &symtab[ELF64_R_SYM(r->r_info)];
                    
                    // 检查符号名称索引是否有效
                    if (sym->st_name >= 10000) {
                        fprintf(stderr, "[WARN] 符号名称索引过大: %u\n", sym->st_name);
                        continue;
                    }
                    
                    const char *name = &strtab[sym->st_name];
                    
                    // 安全地检查符号名称
                    if (!name || strnlen(name, 20) >= 20) {
                        fprintf(stderr, "[WARN] 无效的符号名称\n");
                        continue;
                    }
                    
                    fprintf(stderr, "[DEBUG] 检查符号 #%lu: %s\n", j, name);
                    
                    if (strcmp(name, "puts") == 0) {
                        void **got_entry = (void **)(base + r->r_offset);
                        fprintf(stderr, "[INFO] 找到puts GOT条目: %p\n", got_entry);
                        
                        if (!got_entry) {
                            fprintf(stderr, "[ERROR] GOT条目地址无效\n");
                            continue;
                        }
                        
                        // 保存原始函数指针
                        real_puts = *got_entry;
                        
                        if (!real_puts) {
                            fprintf(stderr, "[ERROR] 原始puts函数指针为空\n");
                            continue;
                        }
                        
                        fprintf(stderr, "[INFO] 原始puts地址: %p, 钩子地址: %p\n", 
                                real_puts, my_puts);
                        
                        // 修改GOT条目
                        *got_entry = my_puts;
                        
                        fprintf(stderr, "[SUCCESS] 成功钩取puts函数\n");
                        hook_initialized = 1;
                        return 1;
                    }
                }
            }
        }
    }
    
    return 0;
}

__attribute__((constructor))
void init_hook() {
    fprintf(stderr, "\n[HOOK] 开始初始化 puts 钩子...\n");
    
    // 打印当前进程信息
    fprintf(stderr, "[INFO] 进程ID: %d\n", getpid());
    
    // 先尝试使用传统方法
    int result = dl_iterate_phdr(phdr_callback, NULL);
    if (result && hook_initialized && real_puts) {
        fprintf(stderr, "[INFO] 使用传统方法成功钩取puts\n");
        return;
    }
    
    // 如果传统方法失败，尝试直接查找方法
    if (!hook_initialized || !real_puts) {
        fprintf(stderr, "[INFO] 传统方法失败，尝试直接查找方法\n");
        find_and_hook_target();
    }
    
    // 最后的验证
    if (hook_initialized && real_puts) {
        fprintf(stderr, "[SUCCESS] puts钩子初始化成功\n");
    } else {
        fprintf(stderr, "[ERROR] puts钩子初始化失败\n");
        
        // 最后的后备方案，直接获取puts
        real_puts = puts;
        if (real_puts) {
            fprintf(stderr, "[INFO] 从全局符号表获取puts作为后备\n");
            hook_initialized = 1;
        }
    }
    
    // 确保所有日志都已刷新
    fflush(stderr);
}