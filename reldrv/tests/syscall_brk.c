#define _GNU_SOURCE

#include "common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIZE 16384

int main()
{
    int n = 0;
    checkpoint_take();
    char *buf = malloc(SIZE); // calling malloc with a large size will introduce a brk syscall
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