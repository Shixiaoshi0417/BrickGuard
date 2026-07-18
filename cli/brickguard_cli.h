/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BRICKGUARD_CLI_H
#define BRICKGUARD_CLI_H

#include <sys/types.h>

#include "../include/brickguard_protocol.h"

#ifndef BG_CONTROL_PATH
#define BG_CONTROL_PATH "/proc/brickguard/control"
#endif
#ifndef BG_CACHE_PATH
#define BG_CACHE_PATH "/proc/brickguard/cache"
#endif
#ifndef BG_VAULT
#define BG_VAULT "/data/adb/brickguard/blg-recovery-pack"
#endif

int bg_rpc(const char *command, char *reply, size_t reply_size);

int bg_pack_create(void);
int bg_pack_verify(int verbose);
int bg_blg_prepare(void);
int bg_blg_verify(void);
int bg_blg_release(void);
int bg_blg_selftest(void);

#endif
