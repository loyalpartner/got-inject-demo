// target.c
#include <stdio.h>
#include <unistd.h>

int main() {
    while (1) {
        puts("Hello from target process.");
        sleep(2);
    }
    return 0;
}