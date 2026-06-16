#include <stdio.h>
#include <string.h>

int add(int a, int b) {
    return a + b;
}

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

int main() {
    char msg[] = "Hello from ELFDebugger!";
    int x = add(21, 21);
    int f = factorial(5);
    printf("%s\n", msg);
    printf("add(21,21) = %d\n", x);
    printf("factorial(5) = %d\n", f);
    return 0;
}
