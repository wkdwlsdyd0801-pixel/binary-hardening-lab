/*
 * heap_overflow.c -- INTENTIONALLY VULNERABLE. Local lab use only.
 *
 * Data-only heap overflow: two adjacent 24-byte chunks, `name` then `role`.
 * memcpy() copies however many bytes arrived on stdin into `name`, so the
 * input spills over the glibc chunk header into `role`. An attacker who
 * rewrites the header with its original value (0x21) and then "admin"
 * escalates privilege without touching any code pointer -- which is why
 * NX, PIE, canaries, RELRO and CET do nothing against this bug.
 *   - FORTIFY_SOURCE=3 knows malloc(24) via __builtin_dynamic_object_size,
 *     turns memcpy into __memcpy_chk and aborts ("buffer overflow detected").
 *   - glibc's free() checks the next chunk's size field, so a *sloppy*
 *     overflow (e.g. all 'A's) is caught after the fact ("free(): invalid
 *     next size", "double free or corruption"); a careful one is not.
 *
 * Payload (careful): 24 x 'A' + 21 00 00 00 00 00 00 00 + "admin\0"
 * Prints "role=<value>"; exit code 3 means the attacker became admin.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHUNK 24 /* 24 user bytes -> 32-byte glibc chunk: role = name + 32 */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    char *name = malloc(CHUNK);
    char *role = malloc(CHUNK);
    if (!name || !role)
        return 1;
    strcpy(role, "user"); /* trusted value the program later relies on */

    unsigned char in[512];
    ssize_t n = read(STDIN_FILENO, in, sizeof in);
    if (n <= 0)
        return 1;

    /* BUG (on purpose): copies n bytes, never checks n <= CHUNK. */
    memcpy(name, in, (size_t)n);
    /* Compiler barrier: without it -O2 may assume `name` and `role` cannot
     * overlap (it is UB) and reuse the cached "user", hiding the bug the
     * demo is about. Real programs get bitten exactly because memory does
     * overlap at runtime. */
    __asm__ volatile("" ::: "memory");

    printf("copied=%zd name=%.8s role=%.16s\n", n, name, role);
    int is_admin = strcmp(role, "admin") == 0;

    /* free() runs glibc's chunk-header sanity checks: a second line of
     * defence that catches some overflows after the fact. */
    free(role);
    free(name);
    return is_admin ? 3 : 0;
}
