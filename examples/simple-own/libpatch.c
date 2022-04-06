#include "bakatsugi.h"

int x(int a) {
    return a * 2;
}

BAKATSUGI(
    PATCH_OWN(x, x)
)
