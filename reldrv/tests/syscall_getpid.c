#define _GNU_SOURCE

#include "common.h"

#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>

int main()
{
    checkpoint_take();
    pid_t pid = getpid();
    printf("My pid is %d\n", pid);
    printf("pid_t address is %p\n", &pid);
    checkpoint_fini();

    return 0;
}