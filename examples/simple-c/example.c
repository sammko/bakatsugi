#include <stdio.h>
#include <unistd.h>
#include <time.h>

int main() {
    time_t t;
    while (1) {
        t = time(NULL);
        printf("%s", ctime(&t));
        sleep(1);
    }
}
