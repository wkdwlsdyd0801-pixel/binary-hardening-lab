/*
 * aslr_probe.c -- harmless helper for the ASLR entropy measurement.
 *
 * Prints one line of addresses (code, global, stack, heap, libc, mmap).
 * Running it N times and counting distinct values per region shows how
 * many bits of randomisation each region really gets with and without PIE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

int global_var;

int main(void)
{
    int stack_var;
    void *heap = malloc(16);
    void *map = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    /* Fixed key order so the measurement script can parse with split(). */
    printf("code=%p data=%p stack=%p heap=%p libc=%p mmap=%p\n",
           (void *)main, (void *)&global_var, (void *)&stack_var,
           heap, (void *)printf, map);
    free(heap);
    return 0;
}
