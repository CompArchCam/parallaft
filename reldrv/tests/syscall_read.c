#define _GNU_SOURCE

#include "common.h"
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

char foo_str[] = {'f', 'o', 'o'};
char bar_str[] = {'b', 'a', 'r'};

int main()
{
    int fd = memfd_create("test", 0);

    if (fd == -1)
    {
        perror("memfd_create");
        return 1;
    }

    ssize_t sz = write(fd, foo_str, sizeof(foo_str));

    if (sz == -1)
    {
        perror("write");
        return 1;
    }

    lseek(fd, 0, SEEK_SET);

    // test read
    checkpoint_take();

    char buf[100];
    sz = read(fd, buf, sizeof(foo_str));

    if (sz != sizeof(foo_str))
    {
        return 1;
    }

    checkpoint_fini();

    printf("buf: %.*s\n", (int)sz, buf);
    if (sz != sizeof(foo_str))
    {
        printf("Unexpected string read length back");
        return 1;
    }

    // test write
    checkpoint_take();

    sz = write(fd, bar_str, sizeof(bar_str));

    if (sz != sizeof(bar_str))
    {
        return 1;
    }

    checkpoint_fini();

    lseek(fd, 0, SEEK_SET);

    char buf2[100];
    sz = read(fd, buf2, sizeof(buf2));

    printf("buf2: %.*s\n", (int)sz, buf2);

    if (sz != sizeof(foo_str) + sizeof(bar_str))
    {
        printf("Unexpected string read length back");
        return 1;
    }

    return 0;
}