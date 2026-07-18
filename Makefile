# BrickGuard build

HOST_CC ?= cc
TARGET_COMPILE ?= aarch64-linux-gnu-
CLI_CC ?= $(TARGET_COMPILE)gcc
KPM_CC ?= $(TARGET_COMPILE)gcc
KPM_READELF ?= $(TARGET_COMPILE)readelf
KPM_NM ?= $(TARGET_COMPILE)nm
KDIR ?=
KOUT ?= $(KDIR)
SANITIZERS ?= undefined

VERSION := 0.1.0
BUILD := build
POLICY_TEST := $(BUILD)/policy_test
SHA256_TEST := $(BUILD)/sha256_test
PACK_TEST := $(BUILD)/pack_test
CLI_OUT := $(BUILD)/brickguard-arm64
KPM_OUT := $(BUILD)/BrickGuard-$(VERSION)-arm64.kpm
KPM_VALIDATE := scripts/validate_kpm.sh

HOST_CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -Iinclude
CLI_CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -static \
	-Iinclude -Icli

KPM_INCLUDES := \
	-I$(KDIR)/arch/arm64/include \
	-I$(KOUT)/arch/arm64/include/generated \
	-I$(KDIR)/include \
	-I$(KDIR)/arch/arm64/include/uapi \
	-I$(KOUT)/arch/arm64/include/generated/uapi \
	-I$(KDIR)/include/uapi \
	-I$(KOUT)/include/generated/uapi \
	-Iinclude -Ikpm
KPM_CFLAGS := -std=gnu11 -D__KERNEL__ -DMODULE \
	'-DKBUILD_MODNAME="BrickGuard"' -O2 -ffreestanding \
	-fno-pic -fno-pie -fno-stack-protector -fno-builtin -fno-common \
	-fno-asynchronous-unwind-tables -fno-unwind-tables \
	-mgeneral-regs-only -mno-outline-atomics \
	-Wall -Wextra -Werror -Wno-unused-parameter \
	-Wno-address-of-packed-member -Wno-sign-compare \
	-Wno-type-limits -Wno-pointer-sign $(KPM_INCLUDES) \
	-include $(KDIR)/include/linux/compiler-version.h \
	-include $(KDIR)/include/linux/kconfig.h

KPM_OBJS := \
	$(BUILD)/brickguard_main.o \
	$(BUILD)/brickguard_block.o \
	$(BUILD)/brickguard_blg.o \
	$(BUILD)/policy_kpm.o

.PHONY: all check test sanitize cli kpm check-kdir clean

all: test

$(BUILD):
	mkdir -p $@

$(POLICY_TEST): src/policy.c tests/policy_test.c \
		include/brickguard_policy.h | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) src/policy.c tests/policy_test.c -o $@

$(SHA256_TEST): src/sha256.c tests/sha256_test.c \
		include/brickguard_sha256.h | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) src/sha256.c tests/sha256_test.c -o $@

$(PACK_TEST): cli/brickguard_blg.c src/sha256.c tests/pack_test.c \
		cli/brickguard_cli.h include/brickguard_protocol.h \
		include/brickguard_sha256.h | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) -Icli \
		-DBG_VAULT='"/tmp/brickguard-pack-test"' \
		cli/brickguard_blg.c src/sha256.c tests/pack_test.c -o $@

test: $(POLICY_TEST) $(SHA256_TEST) $(PACK_TEST)
	./$(POLICY_TEST)
	./$(SHA256_TEST)
	./$(PACK_TEST)

sanitize: | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) -O1 -g -fsanitize=$(SANITIZERS) \
		src/policy.c tests/policy_test.c -o $(BUILD)/policy_test_sanitize
	$(HOST_CC) $(HOST_CFLAGS) -O1 -g -fsanitize=$(SANITIZERS) \
		src/sha256.c tests/sha256_test.c -o $(BUILD)/sha256_test_sanitize
	$(HOST_CC) $(HOST_CFLAGS) -Icli -O1 -g -fsanitize=$(SANITIZERS) \
		-DBG_VAULT='"/tmp/brickguard-pack-test"' \
		cli/brickguard_blg.c src/sha256.c tests/pack_test.c \
		-o $(BUILD)/pack_test_sanitize
	./$(BUILD)/policy_test_sanitize
	./$(BUILD)/sha256_test_sanitize
	./$(BUILD)/pack_test_sanitize

$(CLI_OUT): cli/brickguard.c cli/brickguard_blg.c src/sha256.c \
		cli/brickguard_cli.h include/brickguard_protocol.h \
		include/brickguard_sha256.h include/brickguard_version.h | $(BUILD)
	$(CLI_CC) $(CLI_CFLAGS) cli/brickguard.c cli/brickguard_blg.c \
		src/sha256.c -o $@

cli: $(CLI_OUT)
	$(TARGET_COMPILE)readelf -h $(CLI_OUT) | sed -n '1,18p'
	@echo "Built: $(CLI_OUT)"

check: test cli

check-kdir:
	@if [ -z "$(KDIR)" ] || \
	    [ -z "$(KOUT)" ] || \
	    [ ! -f "$(KOUT)/include/generated/autoconf.h" ]; then \
		echo "error: prepare the exact target KDIR first"; \
		echo "       make ARCH=arm64 O=out gki_defconfig prepare"; \
		exit 1; \
	fi

$(BUILD)/%.o: kpm/%.c kpm/brickguard_internal.h \
		include/brickguard_policy.h include/brickguard_protocol.h \
		include/brickguard_version.h | $(BUILD) check-kdir
	$(KPM_CC) $(KPM_CFLAGS) -c $< -o $@

$(BUILD)/policy_kpm.o: src/policy.c include/brickguard_policy.h | \
		$(BUILD) check-kdir
	$(KPM_CC) $(KPM_CFLAGS) -c $< -o $@

$(KPM_OUT): $(KPM_OBJS) $(KPM_VALIDATE)
	$(KPM_CC) -r -o $@ $(KPM_OBJS)

kpm: $(KPM_OUT)
	$(KPM_READELF) -h $(KPM_OUT) | sed -n '1,18p'
	sh $(KPM_VALIDATE) $(KPM_OUT) \
		$(KPM_READELF) $(KPM_NM) $(VERSION)
	@echo "Built: $(KPM_OUT)"

clean:
	rm -rf $(BUILD)
