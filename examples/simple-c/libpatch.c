#include <time.h>
#include "bakatsugi.h"

time_t badtime(time_t *t) {
    if (t) {
        *t = 123;
    }
    return 123;
}

BAKATSUGI(
    PATCH_LIB(time, badtime)
)
