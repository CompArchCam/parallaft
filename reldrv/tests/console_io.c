#define _GNU_SOURCE

#include "common.h"
#include <stdio.h>

int main()
{
    int n = 0;
    checkpoint_take();
    printf("You should see this only once\n");
    printf("Enter a number: ");
    scanf("%d", &n);
    printf("The number entered is %d\n", n);
    checkpoint_fini();

    return 0;
}