/*
 * stack_overflow.c -- INTENTIONALLY VULNERABLE. Local lab use only.
 *
 * Classic stack buffer overflow: read() copies up to 256 attacker bytes
 * into a 16-byte stack buffer. The bytes run past `buf` over the saved
 * frame pointer and return address, so how the process dies tells us
 * which mitigation (if any) noticed:
 *   - no canary          -> corrupted return address -> SIGSEGV (or worse: control flow hijack)
 *   - -fstack-protector  -> canary mismatch before `ret` -> "stack smashing detected", SIGABRT
 *   - FORTIFY_SOURCE     -> read() becomes __read_chk(buf, 256, 16); 256 > 16 is
 *                           known at compile time, so it aborts on EVERY run,
 *                           even benign input (a bug found before exploitation)
 *   - NX / PIE / CET     -> do not stop the overwrite itself, they only make
 *                           turning it into code execution harder (measured in scripts/measure.py)
 *
 * Usage: printf 'AAAA...' | ./stack_overflow
 * Exit 0 + "survived" means the function returned normally.
 */
#include <stdio.h>
#include <unistd.h>

/* noinline keeps a real frame (and canary) even at -O2, so every profile in
 * build.mk compiles the same vulnerable shape. */
__attribute__((noinline)) static void vulnerable(void)
{
    char buf[16];
    /* BUG (on purpose): length 256 is not sizeof(buf). This is the overflow. */
    ssize_t n = read(STDIN_FILENO, buf, 256);
    /* Use buf after the read so the compiler cannot drop the copy as dead. */
    printf("read %zd bytes, first byte 0x%02x\n", n, n > 0 ? (unsigned char)buf[0] : 0);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0); /* unbuffered: output survives a crash */
    vulnerable();
    puts("survived");
    return 0;
}
