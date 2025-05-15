// direct_injector.c - 直接从代码修改GOT表的注入工具
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>

// 目标函数名
#define TARGET_FUNC "puts"
// 替换消息
#define HOOK_MESSAGE "[HOOKED] I've intercepted your puts!"

// 用于远程读取和写入内存的函数
ssize_t process_read(pid_t pid, void *addr, void *buf, size_t len) {
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = buf;
    local[0].iov_len = len;
    remote[0].iov_base = addr;
    remote[0].iov_len = len;
    return process_vm_readv(pid, local, 1, remote, 1, 0);
}

ssize_t process_write(pid_t pid, void *addr, const void *buf, size_t len) {
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = (void*)buf;
    local[0].iov_len = len;
    remote[0].iov_base = addr;
    remote[0].iov_len = len;
    return process_vm_writev(pid, local, 1, remote, 1, 0);
}

// 读取进程内存映射
char* read_maps(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    
    FILE *file = fopen(path, "r");
    if (!file) {
        perror("Failed to open memory maps");
        return NULL;
    }
    
    char *maps = malloc(65536);  // 64KB应该足够大多数进程的maps
    if (!maps) {
        fclose(file);
        return NULL;
    }
    
    size_t bytes_read = fread(maps, 1, 65535, file);
    maps[bytes_read] = '\0';
    fclose(file);
    return maps;
}

// 在远程内存中注入我们的hook代码
void* inject_hook_code(pid_t pid) {
    // 我们的hook函数代码
    unsigned char hook_code[] = {
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, addr_of_message
        0x48, 0x89, 0xC7,                                             // mov rdi, rax
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, addr_of_real_puts
        0xFF, 0xD0,                                                   // call rax
        0xC3                                                           // ret
    };
    
    // 首先，找到一个合适的内存区域来注入代码
    char *maps = read_maps(pid);
    if (!maps) {
        return NULL;
    }
    
    // 寻找有执行权限的区域
    void *code_addr = NULL;
    char *line = strtok(maps, "\n");
    while (line) {
        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            // 需要有写和执行权限
            if (strchr(perms, 'w') && strchr(perms, 'x')) {
                // 确保空间足够
                if (end - start >= 4096) {
                    code_addr = (void*)(start + 1024); // 使用区域中间的一部分
                    break;
                }
            }
        }
        line = strtok(NULL, "\n");
    }
    
    if (!code_addr) {
        // 如果找不到合适的区域，使用mmap分配一个
        struct user_regs_struct regs, saved_regs;
        
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            perror("Failed to get registers");
            free(maps);
            return NULL;
        }
        
        memcpy(&saved_regs, &regs, sizeof(regs));
        
        // 设置mmap系统调用
        regs.rax = 9;                                       // sys_mmap
        regs.rdi = 0;                                       // addr
        regs.rsi = 4096;                                    // length
        regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;      // prot
        regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;             // flags
        regs.r8 = -1;                                       // fd
        regs.r9 = 0;                                        // offset
        
        // 执行syscall
        regs.rip -= 2;  // 假设有syscall指令
        
        if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
            perror("Failed to set registers for mmap");
            free(maps);
            return NULL;
        }
        
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
            perror("Failed to continue process for mmap");
            free(maps);
            return NULL;
        }
        
        waitpid(pid, NULL, 0);
        
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            perror("Failed to get registers after mmap");
            free(maps);
            return NULL;
        }
        
        code_addr = (void*)regs.rax;
        
        // 恢复寄存器
        if (ptrace(PTRACE_SETREGS, pid, NULL, &saved_regs) == -1) {
            perror("Failed to restore registers");
            free(maps);
            return NULL;
        }
    }
    
    free(maps);
    
    // 分配内存存储hook消息
    void *msg_addr = (void*)((char*)code_addr + 128);  // 代码之后一段空间
    
    // 将消息写入远程内存
    if (process_write(pid, msg_addr, HOOK_MESSAGE, strlen(HOOK_MESSAGE) + 1) == -1) {
        perror("Failed to write hook message");
        return NULL;
    }
    
    // 获取真实puts函数的地址
    void *real_puts = dlsym(RTLD_NEXT, TARGET_FUNC);
    if (!real_puts) {
        fprintf(stderr, "Failed to get real puts address: %s\n", dlerror());
        return NULL;
    }
    
    printf("Real puts address: %p\n", real_puts);
    
    // 填充hook代码中的地址
    memcpy(hook_code + 2, &msg_addr, sizeof(void*));        // 消息地址
    memcpy(hook_code + 15, &real_puts, sizeof(void*));      // 真实puts地址
    
    // 写入hook代码
    if (process_write(pid, code_addr, hook_code, sizeof(hook_code)) == -1) {
        perror("Failed to write hook code");
        return NULL;
    }
    
    printf("Successfully injected hook code at %p\n", code_addr);
    return code_addr;
}

// 查找目标进程中的GOT表项
void* find_got_entry(pid_t pid, const char *func_name) {
    // 读取目标进程的可执行文件路径
    char exe_path[4096];
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
    
    ssize_t length = readlink(proc_path, exe_path, sizeof(exe_path) - 1);
    if (length == -1) {
        perror("Failed to read executable path");
        return NULL;
    }
    exe_path[length] = '\0';
    printf("Target executable: %s\n", exe_path);
    
    // 打开可执行文件
    int fd = open(exe_path, O_RDONLY);
    if (fd == -1) {
        perror("Failed to open executable");
        return NULL;
    }
    
    // 读取ELF头
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        perror("Failed to read ELF header");
        close(fd);
        return NULL;
    }
    
    // 验证ELF格式
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not an ELF file\n");
        close(fd);
        return NULL;
    }
    
    // 读取段头表
    Elf64_Shdr *shdr = malloc(ehdr.e_shentsize * ehdr.e_shnum);
    if (!shdr) {
        perror("Failed to allocate memory for section headers");
        close(fd);
        return NULL;
    }
    
    if (lseek(fd, ehdr.e_shoff, SEEK_SET) == -1) {
        perror("Failed to seek to section headers");
        free(shdr);
        close(fd);
        return NULL;
    }
    
    if (read(fd, shdr, ehdr.e_shentsize * ehdr.e_shnum) != ehdr.e_shentsize * ehdr.e_shnum) {
        perror("Failed to read section headers");
        free(shdr);
        close(fd);
        return NULL;
    }
    
    // 读取字符串表
    char *strtab = NULL;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdr[i].sh_type == SHT_STRTAB) {
            strtab = malloc(shdr[i].sh_size);
            if (!strtab) {
                perror("Failed to allocate memory for string table");
                free(shdr);
                close(fd);
                return NULL;
            }
            
            if (lseek(fd, shdr[i].sh_offset, SEEK_SET) == -1) {
                perror("Failed to seek to string table");
                free(strtab);
                free(shdr);
                close(fd);
                return NULL;
            }
            
            if (read(fd, strtab, shdr[i].sh_size) != shdr[i].sh_size) {
                perror("Failed to read string table");
                free(strtab);
                free(shdr);
                close(fd);
                return NULL;
            }
            
            break;
        }
    }
    
    // 查找重定位表
    void *got_entry = NULL;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (shdr[i].sh_type == SHT_RELA) {
            // 这是一个重定位段
            Elf64_Rela *relocations = malloc(shdr[i].sh_size);
            if (!relocations) {
                perror("Failed to allocate memory for relocations");
                free(strtab);
                free(shdr);
                close(fd);
                return NULL;
            }
            
            if (lseek(fd, shdr[i].sh_offset, SEEK_SET) == -1) {
                perror("Failed to seek to relocations");
                free(relocations);
                free(strtab);
                free(shdr);
                close(fd);
                return NULL;
            }
            
            if (read(fd, relocations, shdr[i].sh_size) != shdr[i].sh_size) {
                perror("Failed to read relocations");
                free(relocations);
                free(strtab);
                free(shdr);
                close(fd);
                return NULL;
            }
            
            // 查找符号表
            Elf64_Shdr *symtab_hdr = &shdr[shdr[i].sh_link];
            Elf64_Sym *symtab = malloc(symtab_hdr->sh_size);
            if (!symtab) {
                perror("Failed to allocate memory for symbol table");
                free(relocations);
                free(strtab);
                free(shdr);
                close(fd);
                return NULL;
            }
            
            if (lseek(fd, symtab_hdr->sh_offset, SEEK_SET) == -1) {
                perror("Failed to seek to symbol table");
                free(symtab);
                free(relocations);
                free(strtab);
                free(shdr);
                close(fd);
                return NULL;
            }
            
            if (read(fd, symtab, symtab_hdr->sh_size) != symtab_hdr->sh_size) {
                perror("Failed to read symbol table");
                free(symtab);
                free(relocations);
                free(strtab);
                free(shdr);
                close(fd);
                return NULL;
            }
            
            // 查找字符串表
            char *sym_strtab = NULL;
            if (symtab_hdr->sh_link < ehdr.e_shnum) {
                Elf64_Shdr *sym_strtab_hdr = &shdr[symtab_hdr->sh_link];
                sym_strtab = malloc(sym_strtab_hdr->sh_size);
                if (!sym_strtab) {
                    perror("Failed to allocate memory for symbol string table");
                    free(symtab);
                    free(relocations);
                    free(strtab);
                    free(shdr);
                    close(fd);
                    return NULL;
                }
                
                if (lseek(fd, sym_strtab_hdr->sh_offset, SEEK_SET) == -1) {
                    perror("Failed to seek to symbol string table");
                    free(sym_strtab);
                    free(symtab);
                    free(relocations);
                    free(strtab);
                    free(shdr);
                    close(fd);
                    return NULL;
                }
                
                if (read(fd, sym_strtab, sym_strtab_hdr->sh_size) != sym_strtab_hdr->sh_size) {
                    perror("Failed to read symbol string table");
                    free(sym_strtab);
                    free(symtab);
                    free(relocations);
                    free(strtab);
                    free(shdr);
                    close(fd);
                    return NULL;
                }
            }
            
            // 遍历重定位
            for (size_t j = 0; j < shdr[i].sh_size / sizeof(Elf64_Rela); j++) {
                Elf64_Rela *rela = &relocations[j];
                Elf64_Sym *sym = &symtab[ELF64_R_SYM(rela->r_info)];
                
                if (sym->st_name && sym_strtab) {
                    const char *name = &sym_strtab[sym->st_name];
                    if (strcmp(name, func_name) == 0) {
                        // 找到了匹配的符号
                        // 获取GOT条目的地址
                        void *remote_got_entry = (void*)rela->r_offset;
                        printf("Found GOT entry for %s at offset 0x%lx\n", func_name, rela->r_offset);
                        
                        // 需要获取实际的内存地址
                        // 读取目标进程的基址
                        char *maps = read_maps(pid);
                        if (maps) {
                            unsigned long base_addr = 0;
                            char *line = strtok(maps, "\n");
                            if (line) {
                                sscanf(line, "%lx-", &base_addr);
                                printf("Process base address: 0x%lx\n", base_addr);
                                remote_got_entry = (void*)(base_addr + rela->r_offset);
                                printf("Absolute GOT entry address: %p\n", remote_got_entry);
                            }
                            free(maps);
                        }
                        
                        got_entry = remote_got_entry;
                        break;
                    }
                }
            }
            
            free(sym_strtab);
            free(symtab);
            free(relocations);
            
            if (got_entry)
                break;
        }
    }
    
    free(strtab);
    free(shdr);
    close(fd);
    return got_entry;
}

// 直接修改GOT表项
int modify_got_entry(pid_t pid, const char *func_name, void *new_func) {
    // 找到GOT表中目标函数的条目
    void *got_entry = find_got_entry(pid, func_name);
    if (!got_entry) {
        fprintf(stderr, "Failed to find GOT entry for %s\n", func_name);
        return -1;
    }
    
    // 读取原始函数地址
    void *original_func = NULL;
    if (process_read(pid, got_entry, &original_func, sizeof(void*)) == -1) {
        perror("Failed to read original function address");
        return -1;
    }
    
    printf("Original %s address: %p\n", func_name, original_func);
    
    // 写入新的函数地址
    if (process_write(pid, got_entry, &new_func, sizeof(void*)) == -1) {
        perror("Failed to write new function address");
        return -1;
    }
    
    printf("Successfully modified GOT entry for %s from %p to %p\n", 
           func_name, original_func, new_func);
    return 0;
}

// 显示帮助信息
void show_help(const char *prog_name) {
    printf("Usage: %s <pid>\n", prog_name);
    printf("Directly patches the GOT table in a running process to hook functions\n");
    printf("\nOptions:\n");
    printf("  <pid>  Process ID of the target process\n");
}

int main(int argc, char **argv) {
    if (argc != 2) {
        show_help(argv[0]);
        return 1;
    }
    
    pid_t pid = atoi(argv[1]);
    if (pid <= 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }
    
    // 检查目标进程是否存在
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
    if (access(proc_path, F_OK) == -1) {
        fprintf(stderr, "Process %d does not exist\n", pid);
        return 1;
    }
    
    printf("Attaching to process %d...\n", pid);
    
    // 附加到目标进程
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("Failed to attach to process");
        return 1;
    }
    
    // 等待进程停止
    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "Process did not stop after attach\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    
    printf("Process stopped, injecting hook...\n");
    
    // 注入hook代码
    void *hook_func = inject_hook_code(pid);
    if (!hook_func) {
        fprintf(stderr, "Failed to inject hook code\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    
    // 修改GOT表项
    if (modify_got_entry(pid, TARGET_FUNC, hook_func) != 0) {
        fprintf(stderr, "Failed to modify GOT entry\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    
    // 分离并让进程继续运行
    printf("Hook installed successfully, detaching...\n");
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    
    return 0;
}