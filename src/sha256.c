/* SPDX-License-Identifier: GPL-2.0-only */
#include "../include/brickguard_sha256.h"

static const uint32_t bg_sha256_k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t bg_rotr32(uint32_t value, unsigned int shift)
{
    return (value >> shift) | (value << (32U - shift));
}

static uint32_t bg_load_be32(const unsigned char *bytes)
{
    return ((uint32_t)bytes[0] << 24) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

static void bg_store_be32(unsigned char *bytes, uint32_t value)
{
    bytes[0] = (unsigned char)(value >> 24);
    bytes[1] = (unsigned char)(value >> 16);
    bytes[2] = (unsigned char)(value >> 8);
    bytes[3] = (unsigned char)value;
}

static void bg_sha256_transform(struct bg_sha256_ctx *ctx,
                                const unsigned char block[64])
{
    uint32_t words[64];
    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];
    uint32_t f = ctx->state[5];
    uint32_t g = ctx->state[6];
    uint32_t h = ctx->state[7];
    unsigned int index;

    for (index = 0; index < 16; index++)
        words[index] = bg_load_be32(block + index * 4U);
    for (; index < 64; index++) {
        uint32_t s0 = bg_rotr32(words[index - 15], 7) ^
                      bg_rotr32(words[index - 15], 18) ^
                      (words[index - 15] >> 3);
        uint32_t s1 = bg_rotr32(words[index - 2], 17) ^
                      bg_rotr32(words[index - 2], 19) ^
                      (words[index - 2] >> 10);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }

    for (index = 0; index < 64; index++) {
        uint32_t sum1 = bg_rotr32(e, 6) ^ bg_rotr32(e, 11) ^
                        bg_rotr32(e, 25);
        uint32_t choose = (e & f) ^ (~e & g);
        uint32_t first = h + sum1 + choose + bg_sha256_k[index] +
                         words[index];
        uint32_t sum0 = bg_rotr32(a, 2) ^ bg_rotr32(a, 13) ^
                        bg_rotr32(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t second = sum0 + majority;

        h = g;
        g = f;
        f = e;
        e = d + first;
        d = c;
        c = b;
        b = a;
        a = first + second;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void bg_sha256_init(struct bg_sha256_ctx *ctx)
{
    static const uint32_t initial[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    };
    unsigned int index;

    for (index = 0; index < 8; index++)
        ctx->state[index] = initial[index];
    ctx->total_bytes = 0;
    ctx->block_used = 0;
}

void bg_sha256_update(struct bg_sha256_ctx *ctx, const void *data,
                      size_t length)
{
    const unsigned char *bytes = data;

    ctx->total_bytes += length;
    while (length) {
        size_t space = sizeof(ctx->block) - ctx->block_used;
        size_t chunk = length < space ? length : space;
        size_t index;

        for (index = 0; index < chunk; index++)
            ctx->block[ctx->block_used + index] = bytes[index];
        ctx->block_used += chunk;
        bytes += chunk;
        length -= chunk;
        if (ctx->block_used == sizeof(ctx->block)) {
            bg_sha256_transform(ctx, ctx->block);
            ctx->block_used = 0;
        }
    }
}

void bg_sha256_final(struct bg_sha256_ctx *ctx,
                     unsigned char digest[BG_SHA256_SIZE])
{
    uint64_t bit_length = ctx->total_bytes * 8U;
    size_t index;

    ctx->block[ctx->block_used++] = 0x80;
    if (ctx->block_used > 56) {
        while (ctx->block_used < sizeof(ctx->block))
            ctx->block[ctx->block_used++] = 0;
        bg_sha256_transform(ctx, ctx->block);
        ctx->block_used = 0;
    }
    while (ctx->block_used < 56)
        ctx->block[ctx->block_used++] = 0;
    for (index = 0; index < 8; index++)
        ctx->block[56 + index] =
            (unsigned char)(bit_length >> (56U - (unsigned int)index * 8U));
    bg_sha256_transform(ctx, ctx->block);

    for (index = 0; index < 8; index++)
        bg_store_be32(digest + index * 4U, ctx->state[index]);
}
