#include <stdio.h>
#include <unistd.h>

int x(int a) {
    return a + 1;
}

int y(int a) {
    return a + 1;
}

int z(int a) {
    return a + 1;
}

int main() {
    int i = 0;
    while (1) {
        printf("%d: %d %d %d\n", i, x(i), y(i), z(i));
        i++;
        sleep(1);
    }
}
