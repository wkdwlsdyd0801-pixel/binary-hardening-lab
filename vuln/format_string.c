/*
 * format_string.c -- INTENTIONALLY VULNERABLE. Local lab use only.
 *
 * User input is passed as the *format* argument of printf(). That gives an
 * attacker two primitives:
 *   - read:  "%p %p %p" walks the stack/registers and leaks pointers,
 *            which defeats ASLR/PIE by revealing where things are loaded;
 *   - write: "%n" stores the number of bytes printed so far through a
 *            pointer taken from the stack -> arbitrary memory write.
 * FORTIFY_SOURCE>=2 compiles printf to __printf_chk, which refuses "%n"
 * when the format string lives in writable memory ("%n in writable
 * segments detected", SIGABRT). It does NOT stop the %p leak.
 *
 * Usage: echo '%p.%p.%p' | ./format_string
 */
#include <stdio.h>
#include <string.h>

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    char line[256]; /* on the stack => writable, which is what FORTIFY checks */
    if (!fgets(line, sizeof line, stdin))
        return 1;
    line[strcspn(line, "\n")] = '\0';

    /* BUG (on purpose): should be printf("%s", line). */
    printf(line);
    putchar('\n');
    return 0;
}
