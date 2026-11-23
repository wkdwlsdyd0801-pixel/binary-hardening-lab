# build.mk -- compile every vuln/*.c under every mitigation profile.
#   make -f build.mk            -> build/<profile>/<program>
#   make -f build.mk BUILD=/tmp/x  -> same, different output dir (tests use this)
#   make -f build.mk list       -> print profile names (used by scripts/tests)
#   make -f build.mk flags P=nx -> print the exact CFLAGS of one profile
#                                  (scripts/benchmark.py compiles bench/ with them)
#   make -f build.mk clean
# Named build.mk (not Makefile) on purpose; see README.
#
# WHY every profile spells out the "off" flags too: distro compilers
# (Ubuntu, Fedora...) enable PIE, -fstack-protector-strong, FORTIFY,
# BIND_NOW and CET by default, so omitting a flag does not mean "off".
# Each profile differs from `none` in exactly one mitigation, plus `all`.

# Make's built-in default CC is `cc`; prefer gcc unless the user set CC.
ifeq ($(origin CC),default)
CC := gcc
endif
BUILD  ?= build
# Same -O2 everywhere so profiles differ only in mitigations (FORTIFY needs -O);
# -w silences the overflow warnings these files exist to trigger.
OPT    := -O2 -g0 -w
SRCS   := $(wildcard vuln/*.c)
PROGS  := $(notdir $(SRCS:.c=))

OFF_NX     := -z execstack
OFF_CANARY := -fno-stack-protector
OFF_FORT   := -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
OFF_PIE    := -fno-pie -no-pie
OFF_RELRO  := -Wl,-z,norelro -Wl,-z,lazy
OFF_CET    := -fcf-protection=none

ON_NX      := -z noexecstack
ON_CANARY  := -fstack-protector-strong
ON_FORT    := -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3
ON_PIE     := -fPIE -pie
ON_RELRO   := -Wl,-z,relro -Wl,-z,now
# CET is x86-only; other arches simply get no CFI flag.
ON_CET     := $(if $(filter x86_64 i%86,$(shell uname -m)),-fcf-protection=full,)

FLAGS_none    := $(OFF_NX) $(OFF_CANARY) $(OFF_FORT) $(OFF_PIE) $(OFF_RELRO) $(OFF_CET)
FLAGS_nx      := $(ON_NX)  $(OFF_CANARY) $(OFF_FORT) $(OFF_PIE) $(OFF_RELRO) $(OFF_CET)
FLAGS_canary  := $(OFF_NX) $(ON_CANARY)  $(OFF_FORT) $(OFF_PIE) $(OFF_RELRO) $(OFF_CET)
FLAGS_fortify := $(OFF_NX) $(OFF_CANARY) $(ON_FORT)  $(OFF_PIE) $(OFF_RELRO) $(OFF_CET)
FLAGS_pie     := $(OFF_NX) $(OFF_CANARY) $(OFF_FORT) $(ON_PIE)  $(OFF_RELRO) $(OFF_CET)
FLAGS_relro   := $(OFF_NX) $(OFF_CANARY) $(OFF_FORT) $(OFF_PIE) $(ON_RELRO)  $(OFF_CET)
FLAGS_cet     := $(OFF_NX) $(OFF_CANARY) $(OFF_FORT) $(OFF_PIE) $(OFF_RELRO) $(ON_CET)
FLAGS_all     := $(ON_NX)  $(ON_CANARY)  $(ON_FORT)  $(ON_PIE)  $(ON_RELRO)  $(ON_CET)

PROFILES := none nx canary fortify pie relro cet all
TARGETS  := $(foreach p,$(PROFILES),$(addprefix $(BUILD)/$(p)/,$(PROGS)))

.PHONY: all list flags clean
all: $(TARGETS)

list:
	@echo $(PROFILES)

# Single source of truth for flags: the benchmark reuses them instead of
# duplicating the matrix in Python, so the two can never drift apart.
flags:
	@echo $(OPT) $(FLAGS_$(P))

# Second expansion lets the prerequisite drop the profile dir (build/nx/x -> vuln/x.c);
# the recipe then picks FLAGS_<profile> from the target's parent directory name.
.SECONDEXPANSION:
$(BUILD)/%: vuln/$$(notdir $$*).c build.mk
	@mkdir -p $(@D)
	$(CC) $(OPT) $(FLAGS_$(notdir $(patsubst %/,%,$(dir $@)))) $< -o $@

clean:
	rm -rf $(BUILD)
