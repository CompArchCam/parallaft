#ifndef __COMMON_H__
#define __COMMON_H__

#include <unistd.h>

#define SYS_checkpoint_take 0xff77
#define SYS_checkpoint_fini 0xff78
#define SYS_checkpoint_sync 0xff7a

static inline void checkpoint_take()
{
    syscall(SYS_checkpoint_take);
}

static inline void checkpoint_fini()
{
    syscall(SYS_checkpoint_fini);
}

static inline void checkpoint_sync()
{
    syscall(SYS_checkpoint_sync);
}

#endif