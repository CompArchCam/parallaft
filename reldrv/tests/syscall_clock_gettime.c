// this is expected to fail when running under reldrv if vDSO is enabled

#define _GNU_SOURCE

#include "common.h"
#include <time.h>
#include <stdio.h>

int main()
{
    checkpoint_take();
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    printf("tv_sec = %ld\n", t.tv_sec);
    printf("tv_nsec = %ld\n", t.tv_nsec);
    checkpoint_fini();

    return 0;
}