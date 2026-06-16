#include <stdlib.h>
#include <string.h>

int main() {
    int arr[16];
    for (int i = 0; i < 16; i++) arr[i] = i * i;
    int sum = 0;
    for (int i = 0; i < 16; i++) sum += arr[i];

    char buf[64];
    memcpy(buf, "ELF_DEBUG_TEST_", 15);
    buf[15] = '\0';

    int fib[10];
    fib[0] = 0; fib[1] = 1;
    for (int i = 2; i < 10; i++) fib[i] = fib[i-1] + fib[i-2];

    return sum % 255;
}
