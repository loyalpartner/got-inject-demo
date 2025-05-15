// target.c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

// 直接使用puts的函数指针
int (*direct_puts)(const char *) = &puts;

int main() {
    printf("Target process started. PID: %d\n", getpid());
    printf("Address of puts function: %p\n", puts);
    printf("Address of direct_puts: %p\n", direct_puts);
    
    int counter = 0;
    while (1) {
        printf("--- Iteration %d ---\n", counter++);
        
        // 直接调用puts
        puts("Regular puts: Hello from target process.");
        
        // 通过函数指针调用puts
        direct_puts("Function pointer puts: Hello from target process.");
        
        // 刷新输出流
        fflush(stdout);
        sleep(2);
    }
    return 0;
}