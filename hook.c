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
#include <pthread.h>
#include <time.h>
#include <stdbool.h>
#include <stdarg.h>
#include <fcntl.h>

// 保存原始的 puts 函数指针
static int (*real_puts)(const char *) = NULL;

// 一个标志，指示钩子是否已初始化
static int hook_initialized = 0;

// 记录统计信息
static int interception_count = 0;
static time_t first_intercept_time = 0;
static char last_intercepted_string[256] = {0};
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// 调试模式标志
static bool debug_mode = true;

// 钩子日志函数
void hook_log(const char *format, ...) {
    if (!debug_mode) return;
    
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    // 添加时间戳和进程ID
    char final_buffer[1280];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    snprintf(final_buffer, sizeof(final_buffer), 
             "[HOOK %02d:%02d:%02d PID:%d] %s\n",
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec,
             getpid(), buffer);
    
    write(STDERR_FILENO, final_buffer, strlen(final_buffer));
}

// 检查钩子是否成功工作的测试函数
void __attribute__((constructor)) test_hook() {
    hook_log("钩子自测开始");
    const char *test_str = "HOOK_TEST_STRING";
    
    // 保存stdout的原始文件描述符
    int stdout_fd = dup(STDOUT_FILENO);
    
    // 重定向stdout到/dev/null
    int null_fd = open("/dev/null", O_WRONLY);
    if (null_fd != -1) {
        dup2(null_fd, STDOUT_FILENO);
        close(null_fd);
    }
    
    // 调用puts，这应该会被拦截
    puts(test_str);
    
    // 恢复stdout
    dup2(stdout_fd, STDOUT_FILENO);
    close(stdout_fd);
    
    hook_log("钩子自测完成");
}

// 我们的钩子函数替换 puts
int my_puts(const char *str) {
    // 确保我们不会递归调用自己 (通过fprintf内部调用puts)
    if (!hook_initialized || !real_puts) {
        write(STDERR_FILENO, "[HOOK ERROR] 未初始化\n", 22);
        return -1;
    }
    
    // 更新统计信息
    pthread_mutex_lock(&stats_mutex);
    interception_count++;
    if (first_intercept_time == 0) {
        first_intercept_time = time(NULL);
    }
    if (str) {
        strncpy(last_intercepted_string, str, sizeof(last_intercepted_string)-1);
        last_intercepted_string[sizeof(last_intercepted_string)-1] = '\0';
    }
    pthread_mutex_unlock(&stats_mutex);
    
    hook_log("拦截了puts调用: \"%s\"", str ? str : "(null)");
    
    return real_puts("[HOOKED] I've intercepted your puts!");
}

// 检查钩子状态的函数，可以从外部调用
void check_hook_status() {
    pthread_mutex_lock(&stats_mutex);
    hook_log("===== 钩子状态报告 =====");
    hook_log("钩子初始化: %s", hook_initialized ? "成功" : "失败");
    hook_log("拦截次数: %d", interception_count);
    if (first_intercept_time > 0) {
        time_t now = time(NULL);
        hook_log("首次拦截时间: %ld (约 %ld 秒前)", 
                first_intercept_time, now - first_intercept_time);
    } else {
        hook_log("首次拦截时间: 未拦截");
    }
    hook_log("最后拦截的字符串: %s", 
            last_intercepted_string[0] ? last_intercepted_string : "(无)");
    hook_log("原始puts函数地址: %p", real_puts);
    hook_log("钩子函数地址: %p", my_puts);
    void *current_puts = dlsym(RTLD_DEFAULT, "puts");
    hook_log("当前puts符号: %p", current_puts);
    hook_log("=======================");
    pthread_mutex_unlock(&stats_mutex);
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
    hook_log("开始初始化 puts 钩子...");
    
    // 打印当前进程信息
    hook_log("进程ID: %d", getpid());
    hook_log("库加载地址: %p", (void*)&init_hook);
    
    // 尝试立即获取puts符号
    void *puts_symbol = dlsym(RTLD_DEFAULT, "puts");
    hook_log("全局puts符号: %p", puts_symbol);
    
    // 保存原始puts以备后用
    if (!real_puts) {
        real_puts = puts;
        hook_log("预先保存原始puts: %p", real_puts);
    }
    
    // 先尝试使用传统方法
    int result = dl_iterate_phdr(phdr_callback, NULL);
    if (result && hook_initialized && real_puts) {
        hook_log("使用传统方法成功钩取puts");
        check_hook_status();
        return;
    }
    
    // 如果传统方法失败，尝试直接查找方法
    if (!hook_initialized || !real_puts) {
        hook_log("传统方法失败，尝试直接查找方法");
        find_and_hook_target();
    }
    
    // 最后的验证
    if (hook_initialized && real_puts) {
        hook_log("puts钩子初始化成功");
    } else {
        hook_log("puts钩子初始化失败");
        
        // 最后的后备方案，直接获取puts
        real_puts = puts;
        if (real_puts) {
            hook_log("从全局符号表获取puts作为后备");
            hook_initialized = 1;
        }
    }
    
    check_hook_status();
    
    // 确保日志已写入
    fsync(STDERR_FILENO);
}