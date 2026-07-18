/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BRICKGUARD_SHA256_H
#define BRICKGUARD_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define BG_SHA256_SIZE 32
#define BG_SHA256_HEX_SIZE 64

struct bg_sha256_ctx {
    uint32_t state[8];
    uint64_t total_bytes;
    unsigned char block[64];
    size_t block_used;
};

void bg_sha256_init(struct bg_sha256_ctx *ctx);
void bg_sha256_update(struct bg_sha256_ctx *ctx, const void *data,
                      size_t length);
void bg_sha256_final(struct bg_sha256_ctx *ctx,
                     unsigned char digest[BG_SHA256_SIZE]);

#endif
