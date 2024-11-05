#ifndef __STD_IO_H
#define __STD_IO_H
#include "syscall.h"
#include "string.h"
#include <stdint.h>

static void print_str(const char *str) {
    syscall(SYS_write, 1, str, strlen(str));
}

static void print_hex(uint64_t n) {
    char buf[19] = "0x";
    buf[18] = '\n';
    for (int i = 0; i < 16; i++) {
        buf[17 - i] = "0123456789abcdef"[n & 0xf];
        n >>= 4;
    }
    syscall(SYS_write, 1, buf, 19);
}

#endif