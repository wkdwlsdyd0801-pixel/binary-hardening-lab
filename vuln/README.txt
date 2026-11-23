INTENTIONALLY VULNERABLE C programs. Local lab use only -- build and run
them on your own machine or in the project container, never expose them.

  stack_overflow.c  read() 256 bytes into a 16-byte stack buffer
  heap_overflow.c   memcpy() past a 24-byte chunk into the next one (data-only)
  format_string.c   printf(user_input): %p leak, %n write
  aslr_probe.c      harmless: prints code/data/stack/heap/libc/mmap addresses

Build all mitigation profiles with:  make -f build.mk
