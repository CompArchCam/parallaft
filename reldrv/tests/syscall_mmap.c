#define _GNU_SOURCE

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define SIZE 16384


// TODO: test map failed

int main()
{
    checkpoint_take();
    char *buf = mmap((void*)NULL, SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (buf == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    // char *buf = malloc(SIZE);

    printf("mmap address = %p\n", buf);

    memset(buf, 0x7f, SIZE);

    for (int i = 0; i < SIZE; i++)
    {
        if (buf[i] != 0x7f)
        {
            printf("unexpected value in buffer\n");
            return 1;
        }
    }
    checkpoint_fini();

    return 0;
}