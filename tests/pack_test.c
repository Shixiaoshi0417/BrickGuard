/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../cli/brickguard_cli.h"
#include "../include/brickguard_sha256.h"

#define TEST_IMAGE_DIR BG_VAULT "/images"
#define TEST_EXTERNAL "/tmp/brickguard-pack-external-link"

static const char valid_device[] =
    "format=BrickGuard-BLG-Pack\n"
    "format_version=3\n"
    "created_utc=2026-07-18T00:00:00Z\n"
    "product=test\n"
    "hardware=test\n"
    "slot=_a\n"
    "kernel=6.12.0-test\n"
    "image_count=2\n";
static const char valid_image[] = "brickguard-test-image";

int bg_rpc(const char *command, char *reply, size_t reply_size)
{
    (void)command;
    (void)reply;
    (void)reply_size;
    return -1;
}

static void cleanup(void)
{
    unlink(TEST_EXTERNAL);
    unlink(TEST_IMAGE_DIR "/unexpected.tmp");
    unlink(TEST_IMAGE_DIR "/xbl_b.img");
    unlink(TEST_IMAGE_DIR "/xbl_a.img");
    unlink(BG_VAULT "/unexpected.tmp");
    unlink(BG_VAULT "/manifest.sha256");
    unlink(BG_VAULT "/device.txt");
    rmdir(TEST_IMAGE_DIR);
    rmdir(BG_VAULT);
}

static void write_all(int fd, const void *data, size_t length)
{
    const unsigned char *cursor = data;

    while (length) {
        ssize_t written = write(fd, cursor, length);

        assert(written > 0);
        cursor += written;
        length -= (size_t)written;
    }
}

static void write_file(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

    assert(fd >= 0);
    write_all(fd, content, strlen(content));
    assert(close(fd) == 0);
}

static void hash_text(const char *text, char output[BG_SHA256_HEX_SIZE + 1])
{
    static const char hex[] = "0123456789abcdef";
    struct bg_sha256_ctx context;
    unsigned char digest[BG_SHA256_SIZE];
    size_t index;

    bg_sha256_init(&context);
    bg_sha256_update(&context, text, strlen(text));
    bg_sha256_final(&context, digest);
    for (index = 0; index < BG_SHA256_SIZE; index++) {
        output[index * 2] = hex[digest[index] >> 4];
        output[index * 2 + 1] = hex[digest[index] & 0x0f];
    }
    output[BG_SHA256_HEX_SIZE] = '\0';
}

static void write_manifest(const char *device)
{
    char device_hash[BG_SHA256_HEX_SIZE + 1];
    char image_hash[BG_SHA256_HEX_SIZE + 1];
    FILE *manifest;

    hash_text(device, device_hash);
    hash_text(valid_image, image_hash);
    manifest = fopen(BG_VAULT "/manifest.sha256", "w");
    assert(manifest != NULL);
    assert(fprintf(manifest, "%s  device.txt\n", device_hash) > 0);
    assert(fprintf(manifest, "%s  images/xbl_a.img\n", image_hash) > 0);
    assert(fprintf(manifest, "%s  images/xbl_b.img\n", image_hash) > 0);
    assert(fclose(manifest) == 0);
}

static void write_valid_manifest(void)
{
    write_file(BG_VAULT "/device.txt", valid_device);
    write_file(TEST_IMAGE_DIR "/xbl_a.img", valid_image);
    assert(link(TEST_IMAGE_DIR "/xbl_a.img",
                TEST_IMAGE_DIR "/xbl_b.img") == 0);
    write_manifest(valid_device);
}

static void replace_device(const char *device)
{
    write_file(BG_VAULT "/device.txt", device);
    write_manifest(device);
}

static void reset_pack(void)
{
    cleanup();
    assert(mkdir(BG_VAULT, 0700) == 0);
    assert(mkdir(TEST_IMAGE_DIR, 0700) == 0);
    write_valid_manifest();
}

static void test_valid_pack(void)
{
    reset_pack();
    assert(bg_pack_verify(0) == 0);
}

static void test_extra_file(void)
{
    reset_pack();
    write_file(TEST_IMAGE_DIR "/unexpected.tmp", "unexpected");
    assert(bg_pack_verify(0) != 0);
}

static void test_symlink(void)
{
    reset_pack();
    assert(unlink(TEST_IMAGE_DIR "/xbl_b.img") == 0);
    assert(symlink("xbl_a.img", TEST_IMAGE_DIR "/xbl_b.img") == 0);
    assert(bg_pack_verify(0) != 0);
}

static void test_external_hardlink(void)
{
    reset_pack();
    assert(link(TEST_IMAGE_DIR "/xbl_a.img", TEST_EXTERNAL) == 0);
    assert(bg_pack_verify(0) != 0);
}

static void test_wrong_version(void)
{
    static const char device[] =
        "format=BrickGuard-BLG-Pack\n"
        "format_version=2\n"
        "created_utc=2026-07-18T00:00:00Z\n"
        "product=test\n"
        "hardware=test\n"
        "slot=_a\n"
        "kernel=6.12.0-test\n"
        "image_count=2\n";

    reset_pack();
    replace_device(device);
    assert(bg_pack_verify(0) != 0);
}

static void test_wrong_image_count(void)
{
    static const char device[] =
        "format=BrickGuard-BLG-Pack\n"
        "format_version=3\n"
        "created_utc=2026-07-18T00:00:00Z\n"
        "product=test\n"
        "hardware=test\n"
        "slot=_a\n"
        "kernel=6.12.0-test\n"
        "image_count=1\n";

    reset_pack();
    replace_device(device);
    assert(bg_pack_verify(0) != 0);
}

static void test_root_extra(void)
{
    reset_pack();
    write_file(BG_VAULT "/unexpected.tmp", "unexpected");
    assert(bg_pack_verify(0) != 0);
}

static void test_checksum_mismatch(void)
{
    reset_pack();
    write_file(TEST_IMAGE_DIR "/xbl_a.img", "changed");
    assert(bg_pack_verify(0) != 0);
}

static void test_manifest_escape(void)
{
    char device_hash[BG_SHA256_HEX_SIZE + 1];
    char image_hash[BG_SHA256_HEX_SIZE + 1];
    FILE *manifest;

    reset_pack();
    hash_text(valid_device, device_hash);
    hash_text(valid_image, image_hash);
    manifest = fopen(BG_VAULT "/manifest.sha256", "w");
    assert(manifest != NULL);
    assert(fprintf(manifest, "%s  device.txt\n", device_hash) > 0);
    assert(fprintf(manifest, "%s  ../outside.img\n", image_hash) > 0);
    assert(fclose(manifest) == 0);
    assert(bg_pack_verify(0) != 0);
}

int main(void)
{
    test_valid_pack();
    test_extra_file();
    test_symlink();
    test_external_hardlink();
    test_wrong_version();
    test_wrong_image_count();
    test_root_extra();
    test_checksum_mismatch();
    test_manifest_escape();
    cleanup();
    puts("BrickGuard Recovery Pack tests passed.");
    return 0;
}
