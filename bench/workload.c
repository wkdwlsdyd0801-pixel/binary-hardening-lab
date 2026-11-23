/*
 * workload.c -- a small, deterministic CPU benchmark used to measure what each
 * mitigation profile in build.mk COSTS at run time. It is not vulnerable; it
 * deliberately exercises the code paths each mitigation instruments:
 *
 *   - stack canary : many small calls with local char arrays, so
 *                    -fstack-protector-strong inserts a guard load + check
 *                    in each prologue/epilogue.
 *   - FORTIFY      : memcpy/strcpy/snprintf into fixed buffers with sizes only
 *                    known at run time, so the compiler emits __*_chk calls
 *                    instead of inlining or proving them safe.
 *   - PIE          : global data and function addresses become RIP-relative /
 *                    GOT-indirect, which is the classic (small) PIE overhead.
 *   - CET (IBT)    : indirect calls through a function-pointer table, every
 *                    target starts with an endbr64.
 *   - RELRO (now)  : only changes start-up (eager symbol binding); measured by
 *                    the separate "startup" runs with iterations = 0.
 *
 * Usage: workload <iterations>
 * Prints "checksum=<n> ns=<loop nanoseconds>" so the harness can time the hot
 * loop from inside the process, excluding fork/exec/loader noise.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Global table so PIE has to reach it through position-independent addressing. */
static const char *WORDS[] = {"alpha", "bravo", "charlie", "delta",
                              "echo", "foxtrot", "golf", "hotel"};

/* volatile sink: stops the optimiser from deleting the work as dead code. */
static volatile unsigned long sink;

/* noinline keeps each helper a real call, so canary/CET cost per call shows up. */
__attribute__((noinline)) static unsigned long copy_word(const char *src, size_t n) {
    char buf[32];                 /* char array -> instrumented by -fstack-protector-strong */
    memcpy(buf, src, n);          /* n is runtime -> FORTIFY emits __memcpy_chk(buf, src, n, 32) */
    buf[n] = '\0';
    unsigned long h = 5381;
    for (size_t i = 0; i < n; i++)
        h = h * 33 + (unsigned char)buf[i];
    return h;
}

__attribute__((noinline)) static unsigned long format_word(const char *w, unsigned i) {
    char buf[48];
    /* snprintf with a runtime string -> __snprintf_chk under FORTIFY. */
    int len = snprintf(buf, sizeof buf, "%s-%u", w, i);
    return (unsigned long)len + (unsigned char)buf[0];
}

__attribute__((noinline)) static unsigned long concat_word(const char *a, const char *b) {
    char buf[64];
    strcpy(buf, a);               /* -> __strcpy_chk */
    strcat(buf, b);               /* -> __strcat_chk */
    return strlen(buf);
}

/* Function-pointer table: indirect calls are what CET IBT guards with endbr64. */
typedef unsigned long (*op_fn)(unsigned);
__attribute__((noinline)) static unsigned long op_copy(unsigned i) {
    const char *w = WORDS[i & 7];
    return copy_word(w, strlen(w));
}
__attribute__((noinline)) static unsigned long op_fmt(unsigned i) {
    return format_word(WORDS[(i >> 3) & 7], i);
}
__attribute__((noinline)) static unsigned long op_cat(unsigned i) {
    return concat_word(WORDS[i & 7], WORDS[(i >> 2) & 7]);
}
static op_fn OPS[] = {op_copy, op_fmt, op_cat};

int main(int argc, char **argv) {
    unsigned long iters = argc > 1 ? strtoul(argv[1], NULL, 10) : 1000000UL;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    unsigned long acc = 0;
    for (unsigned long i = 0; i < iters; i++)
        acc += OPS[i % 3]((unsigned)i);   /* indirect call every iteration */
    clock_gettime(CLOCK_MONOTONIC, &t1);
    sink = acc;
    long long ns = (long long)(t1.tv_sec - t0.tv_sec) * 1000000000LL
                   + (t1.tv_nsec - t0.tv_nsec);
    /* Checksum must be identical across profiles: mitigations may not change results. */
    printf("checksum=%lu ns=%lld\n", acc, ns);
    return 0;
}
