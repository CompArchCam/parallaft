#include "common.h"

int main() {
    checkpoint_take();
    checkpoint_fini();
    checkpoint_fini();
    return 0;
}
