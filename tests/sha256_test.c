/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../include/brickguard_sha256.h"

static void digest_hex(const unsigned char digest[BG_SHA256_SIZE],
                       char output[BG_SHA256_HEX_SIZE + 1])
{
    static const char hex[] = "0123456789abcdef";
    size_t index;

    for (index = 0; index < BG_SHA256_SIZE; index++) {
        output[index * 2] = hex[digest[index] >> 4];
        output[index * 2 + 1] = hex[digest[index] & 0x0f];
    }
    output[BG_SHA256_HEX_SIZE] = '\0';
}

static void check_vector(const char *input, const char *expected)
{
    struct bg_sha256_ctx ctx;
    unsigned char digest[BG_SHA256_SIZE];
    char actual[BG_SHA256_HEX_SIZE + 1];
    size_t length = strlen(input);
    size_t split = length / 2;

    bg_sha256_init(&ctx);
    bg_sha256_update(&ctx, input, split);
    bg_sha256_update(&ctx, input + split, length - split);
    bg_sha256_final(&ctx, digest);
    digest_hex(digest, actual);
    assert(strcmp(actual, expected) == 0);
}

int main(void)
{
    check_vector("",
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855");
    check_vector("abc",
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad");
    check_vector("The quick brown fox jumps over the lazy dog",
        "d7a8fbb307d7809469ca9abcb0082e4f"
        "8d5651e46d3cdb762d02d0bf37c9e592");
    puts("BrickGuard SHA-256 tests passed.");
    return 0;
}
