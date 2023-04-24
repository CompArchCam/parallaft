#define _GNU_SOURCE

#include "common.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>


#define SIZE 16 * 1024 * 1024 // 16MB
#define BLOCK 1024

#define min(a, b) (((a) < (b))? (a) : (b))

int main()
{
    int fd = open("/dev/zero", O_RDONLY);
    if (fd < 0) {
        perror("open");
    }

    char *buf = malloc(SIZE);
    char *p = buf;

    checkpoint_take();

    while (p - buf < SIZE) {
        ssize_t sz_read = read(fd, buf, min(BLOCK, SIZE - (p - buf)));

        if (sz_read < 0) {
            perror("read");
        }
        else if (sz_read == 0) {
            break;
        }

        p += sz_read;
    }
    checkpoint_fini();

    return 0;
}