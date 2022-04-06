#include <stdio.h>
#include <unistd.h>

int x(int a) {
    return a + 1;
}

int main() {
    int i = 0;
    while (1) {
        printf("%d\n", x(i++));
        sleep(1);
    }
}
