// injector.c - 改进的注入器实现
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>

// 在远程进程中查找函数地址
void *get_remote_func_addr(pid_t pid, const char *func) {
    char filename[256];
    sprintf(filename, "/proc/%d/maps", pid);

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("无法打开进程内存映射");
        return NULL;
    }

    // 尝试多个库文件
    const char *modules[] = {
        "libc-", "libc.so", "libdl", "ld-linux", NULL
    };
    
    void *result = NULL;
    
    for (int i = 0; modules[i] != NULL && result == NULL; i++) {
        const char *module = modules[i];
        
        // 重置文件位置
        rewind(fp);
        
        char line[512];
        void *base = NULL;
        char module_path[256] = {0};
        
        // 查找模块的基址
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module) && strstr(line, "r-xp")) {
                // 提取基地址
                unsigned long start, end;
                if (sscanf(line, "%lx-%lx", &start, &end) != 2) {
                    continue;
                }
                
                base = (void*)start;
                
                // 提取完整路径
                char *path_start = strchr(line, '/');
                if (path_start) {
                    char *path_end = strchr(path_start, '\n');
                    if (path_end) *path_end = '\0';
                    strncpy(module_path, path_start, sizeof(module_path)-1);
                }
                
                printf("[DEBUG] 找到模块 %s 在 %p, 路径: %s\n", 
                       module, base, module_path);
                break;
            }
        }
        
        if (!base || !module_path[0]) {
            continue;
        }
        
        // 尝试在本地加载同样的库
        void *local_handle = dlopen(module_path, RTLD_LAZY);
        if (!local_handle) {
            printf("[WARN] 无法本地加载 %s: %s\n", module_path, dlerror());
            continue;
        }
        
        // 获取函数地址
        void *local_func = dlsym(local_handle, func);
        if (!local_func) {
            printf("[DEBUG] 在 %s 中未找到 %s: %s\n", 
                   module_path, func, dlerror());
            dlclose(local_handle);
            continue;
        }
        
        // 计算远程函数地址
        Dl_info info;
        if (dladdr(local_func, &info) == 0) {
            printf("[ERROR] 无法获取 %s 的信息\n", func);
            dlclose(local_handle);
            continue;
        }
        
        unsigned long offset = (unsigned long)local_func - (unsigned long)info.dli_fbase;
        void *remote_func = (void*)((unsigned long)base + offset);
        
        printf("[SUCCESS] 在远程进程中找到 %s: %p (偏移: 0x%lx)\n", 
               func, remote_func, offset);
               
        result = remote_func;
        dlclose(local_handle);
    }
    
    fclose(fp);
    return result;
}

// 将数据写入远程进程内存
long remote_write(pid_t pid, void *remote_addr, void *data, size_t len) {
    struct iovec local = { .iov_base = data, .iov_len = len };
    struct iovec remote = { .iov_base = remote_addr, .iov_len = len };
    
    long result = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (result == -1) {
        printf("[ERROR] 无法写入远程内存: %s\n", strerror(errno));
    } else {
        printf("[INFO] 成功写入 %ld 字节到地址 %p\n", result, remote_addr);
    }
    
    return result;
}

// 从远程进程读取内存
long remote_read(pid_t pid, void *remote_addr, void *local_buf, size_t len) {
    struct iovec local = { .iov_base = local_buf, .iov_len = len };
    struct iovec remote = { .iov_base = remote_addr, .iov_len = len };
    
    long result = process_vm_readv(pid, &remote, 1, &local, 1, 0);
    if (result == -1) {
        printf("[ERROR] 无法读取远程内存: %s\n", strerror(errno));
    }
    
    return result;
}

// 在远程进程中分配内存
void* allocate_remote_memory(pid_t pid) {
    // 尝试查找现有可写内存区域
    char maps_path[64];
    sprintf(maps_path, "/proc/%d/maps", pid);
    
    FILE *maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        perror("无法打开内存映射文件");
        return NULL;
    }
    
    void *result = NULL;
    char line[512];
    
    while (fgets(line, sizeof(line), maps_file)) {
        // 查找具有读写权限的区域
        if (strstr(line, "rw-p")) {
            unsigned long start, end;
            if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
                size_t size = end - start;
                // 确保区域足够大
                if (size >= 4096) {
                    result = (void*)start;
                    printf("[INFO] 找到可用内存区域: %p, 大小: %lu\n", result, size);
                    break;
                }
            }
        }
    }
    
    fclose(maps_file);
    
    if (result) {
        // 验证内存可写
        char test_buf[16] = {0};
        if (remote_read(pid, result, test_buf, sizeof(test_buf)) > 0) {
            printf("[INFO] 成功验证内存可读\n");
            return result;
        }
    }
    
    // 如果找不到合适的区域，使用mmap系统调用分配
    printf("[INFO] 未找到合适的内存区域，尝试通过mmap分配\n");
    
    // 附加到进程并获取寄存器
    struct user_regs_struct regs, saved_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("无法获取寄存器");
        return NULL;
    }
    memcpy(&saved_regs, &regs, sizeof(regs));
    
    // 设置mmap系统调用参数
    regs.rax = 9; // syscall: mmap
    regs.rdi = 0; // addr
    regs.rsi = 4096; // length
    regs.rdx = PROT_READ | PROT_WRITE; // prot
    regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS; // flags
    regs.r8 = -1; // fd
    regs.r9 = 0; // offset
    
    // 找到syscall指令
    regs.rip -= 2;
    
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        perror("无法设置寄存器");
        return NULL;
    }
    
    // 执行syscall
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("无法继续执行");
        return NULL;
    }
    
    // 等待进程停止
    int status;
    waitpid(pid, &status, 0);
    
    // 获取mmap结果
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("无法获取mmap结果");
        ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
        return NULL;
    }
    
    result = (void*)regs.rax;
    
    // 恢复原始寄存器
    ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
    
    printf("[INFO] 通过mmap分配的内存: %p\n", result);
    return result;
}

int main(int argc, char *argv[]) {
    printf("===== 改进的共享库注入器 =====\n");
    time_t now = time(NULL);
    printf("当前时间: %s\n", ctime(&now));
    
    if (argc != 3) {
        fprintf(stderr, "用法: %s <pid> <共享库路径>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    const char *so_path = argv[2];
    
    printf("[INFO] 目标进程: %d\n", pid);
    printf("[INFO] 共享库路径: %s\n", so_path);

    // 检查目标进程是否存在
    char proc_path[64];
    sprintf(proc_path, "/proc/%d", pid);
    if (access(proc_path, F_OK) == -1) {
        fprintf(stderr, "[ERROR] 进程 %d 不存在\n", pid);
        return 1;
    }

    // 附加到目标进程
    printf("[INFO] 附加到进程 %d\n", pid);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("[ERROR] ptrace附加失败");
        return 1;
    }
    
    // 等待目标进程停止
    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[ERROR] 进程没有停止, 状态: 0x%x\n", status);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    
    printf("[INFO] 成功附加到进程\n");

    // 获取寄存器状态
    struct user_regs_struct saved_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &saved_regs) == -1) {
        perror("[ERROR] 无法获取寄存器");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    
    printf("[INFO] 保存了原始寄存器状态\n");

    // 在远程进程中分配内存
    void *remote_mem = allocate_remote_memory(pid);
    if (!remote_mem) {
        fprintf(stderr, "[ERROR] 无法在目标进程中分配内存\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    // 写入共享库路径
    if (remote_write(pid, remote_mem, (void *)so_path, strlen(so_path) + 1) == -1) {
        fprintf(stderr, "[ERROR] 无法写入共享库路径\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    // 获取远程dlopen函数地址
    printf("[INFO] 查找dlopen函数地址\n");
    void *dlopen_addr = get_remote_func_addr(pid, "dlopen");
    if (!dlopen_addr) {
        fprintf(stderr, "[ERROR] 无法找到dlopen函数\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    // 设置调用dlopen的参数
    printf("[INFO] 准备调用dlopen(%s, RTLD_NOW)\n", so_path);
    struct user_regs_struct regs;
    memcpy(&regs, &saved_regs, sizeof(regs));
    
    regs.rdi = (unsigned long)remote_mem;    // 第1个参数: 共享库路径
    regs.rsi = RTLD_NOW | RTLD_GLOBAL;       // 第2个参数: 标志
    regs.rip = (unsigned long)dlopen_addr;   // 函数地址
    
    // 设置远程进程的寄存器
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        perror("[ERROR] 无法设置寄存器");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    // 继续执行目标进程，让它调用dlopen
    printf("[INFO] 执行dlopen...\n");
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        perror("[ERROR] 无法继续执行");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    
    // 等待目标进程停止
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[ERROR] 进程在执行dlopen时未正常停止\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }

    // 获取dlopen的返回值
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("[ERROR] 无法获取dlopen结果");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    
    void *handle = (void*)regs.rax;
    printf("[INFO] dlopen返回: %p\n", handle);
    
    if (!handle) {
        fprintf(stderr, "[WARN] dlopen可能失败，返回NULL\n");
    } else {
        printf("[SUCCESS] 共享库成功加载\n");
    }

    // 恢复原始寄存器状态
    printf("[INFO] 恢复原始寄存器状态\n");
    if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) == -1) {
        perror("[ERROR] 无法恢复寄存器");
    }

    // 分离目标进程
    printf("[INFO] 分离目标进程\n");
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("[ERROR] 无法分离");
        return 1;
    }

    printf("[SUCCESS] 注入完成，现在观察目标进程的行为\n");
    return 0;
}