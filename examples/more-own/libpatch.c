#include "bakatsugi.h"

int x(int a) {
    return a * 2;
}

int y(int a) {
    return (!!a)^(++a);
}

BAKATSUGI(
    PATCH_OWN(x, x)
    PATCH_OWN(y, y)
    PATCH_OWN(z, x)
)
