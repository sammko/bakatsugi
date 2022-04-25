#include <sys/time.h>
#include "bakatsugi.h"

int r_gettimeofday(struct timeval *restrict tp, void *restrict tzp) {
    int r = gettimeofday(tp, tzp);
    tp->tv_sec -= 759;
    return r;
}

BAKATSUGI(
    PATCH_LIB(gettimeofday, r_gettimeofday)
)
