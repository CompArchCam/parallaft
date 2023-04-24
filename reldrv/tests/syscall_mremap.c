#define _GNU_SOURCE

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define SIZE 16384

#define NEW_SIZE 32768

// TODO: test map failed

int main()
{
    char *buf = mmap((void *)NULL, SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (buf == MAP_FAILED)
    {
        perror("mmap");
        return 1;
    }

    // char *buf = malloc(SIZE);

    printf("mmap address = %p\n", buf);

    memset(buf, 0x7f, SIZE);

    checkpoint_take();

    char *new_buf = mremap(buf, SIZE, NEW_SIZE, MREMAP_MAYMOVE);

    if (new_buf == MAP_FAILED)
    {
        perror("mremap");
        return 1;
    }

    memset(new_buf, 0x3f, NEW_SIZE);

    for (int i = 0; i < NEW_SIZE; i++)
    {
        if (new_buf[i] != 0x3f)
        {
            printf("unexpected value in buffer\n");
            return 1;
        }
    }
    checkpoint_fini();

    return 0;
}