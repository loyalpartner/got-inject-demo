// injector.c
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

// 找到远程进程中 libdl.so 中 dlopen 的地址
void *get_remote_func_addr(pid_t pid, const char *module, const char *func) {
    char filename[256];
    sprintf(filename, "/proc/%d/maps", pid);

    FILE *fp = fopen(filename, "r");
    if (!fp) return NULL;

    char line[256];
    void *base = NULL;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, module)) {
            sscanf(line, "%lx-%*lx", (unsigned long *)&base);
            break;
        }
    }
    fclose(fp);

    void *local_handle = dlopen(module, RTLD_LAZY);
    void *local_func = dlsym(local_handle, func);
    void *remote_func = (void *)((unsigned long)local_func - (unsigned long)local_handle + (unsigned long)base);
    dlclose(local_handle);
    return remote_func;
}

// 将 so 路径写入远程进程内存
long remote_write(pid_t pid, void *remote_addr, void *data, size_t len) {
    struct iovec local = { .iov_base = data, .iov_len = len };
    struct iovec remote = { .iov_base = remote_addr, .iov_len = len };
    return process_vm_writev(pid, &local, 1, &remote, 1, 0);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <full_path_to_so>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    const char *so_path = argv[2];

    // attach
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("ptrace attach");
        return 1;
    }
    waitpid(pid, NULL, 0);

    // get regs
    struct user_regs_struct regs, saved_regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    memcpy(&saved_regs, &regs, sizeof(regs));

    // 分配远程内存（mmap）
    regs.rax = 9; // syscall: mmap
    regs.rdi = 0;
    regs.rsi = 4096;
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.r8 = -1;
    regs.r9 = 0;
    regs.rip -= 2;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, NULL, 0);
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    void *remote_mem = (void *)regs.rax;

    // 写入 so 路径
    remote_write(pid, remote_mem, (void *)so_path, strlen(so_path) + 1);

    // 获取远程 dlopen
    void *dlopen_addr = get_remote_func_addr(pid, "libdl", "dlopen");
    if (!dlopen_addr) {
        fprintf(stderr, "Failed to find dlopen\n");
        return 1;
    }

    // 设置参数并调用 dlopen
    regs.rdi = (unsigned long)remote_mem;
    regs.rsi = RTLD_NOW;
    regs.rip = (unsigned long)dlopen_addr;
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, NULL, 0);

    // 恢复寄存器
    ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    printf("Injection done.\n");
    return 0;
}