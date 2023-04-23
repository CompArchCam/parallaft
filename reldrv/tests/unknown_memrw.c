#define _GNU_SOURCE

#include "common.h"
#include <unistd.h>
#include <sys/uio.h>

int main()
{
    checkpoint_take();
    struct iovec iov = {
        .iov_base = "foo\n",
        .iov_len = 4,
    };
    writev(STDOUT_FILENO, &iov, 1);
    checkpoint_fini();

    return 0;
}