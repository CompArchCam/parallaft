#define _GNU_SOURCE

#include "common.h"

#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>

int main()
{
    checkpoint_take();
    for (int i = 0; i < 100000; i++) {
        pid_t pid = getpid();
    }
    checkpoint_fini();

    return 0;
}