/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "brickguard_cli.h"
#include "../include/brickguard_sha256.h"

#define BG_MAX_IMAGES 64
#define BG_IO_CHUNK (1024UL * 1024UL)

struct bg_blob {
    char path[PATH_MAX];
    int fd;
    off_t size;
    dev_t device;
    ino_t inode;
    nlink_t links;
    uint64_t cache_offset;
    unsigned char digest[BG_SHA256_SIZE];
};

struct bg_alias {
    char name[BG_BLG_MAP_NAME];
    int blob_index;
};

struct bg_inventory {
    struct bg_blob blobs[BG_MAX_IMAGES];
    struct bg_alias aliases[BG_MAX_IMAGES];
    int blob_count;
    int alias_count;
    uint64_t total_size;
    char pack_id[BG_SHA256_HEX_SIZE + 1];
    char product[128];
    char hardware[128];
    unsigned int declared_image_count;
};

static void bg_inventory_close(struct bg_inventory *inventory);
static int bg_inventory_load(struct bg_inventory *inventory);

static int bg_run_shell(const char *script)
{
    int status;
    pid_t pid = fork();

    if (pid == 0) {
        execl("/system/bin/sh", "sh", "-c", script, (char *)NULL);
        _exit(127);
    }
    if (pid < 0) {
        perror("fork");
        return 1;
    }
    if (waitpid(pid, &status, 0) < 0) {
        perror("waitpid");
        return 1;
    }
    return !(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int bg_pack_create(void)
{
    static const char script[] =
        "set -eu\n"
        "umask 077\n"
        "V='" BG_VAULT "'\n"
        "N=\"${V}.new.$$\"\n"
        "O=\"${V}.old\"\n"
        "trap 'rm -rf \"$N\"' EXIT INT TERM\n"
        "mkdir -p \"$(dirname \"$V\")\" \"$N/images\"\n"
        "COUNT=0\n"
        "for P in xbl_a xbl_b xbl_config_a xbl_config_b abl_a abl_b "
        "devcfg_a devcfg_b tz_a tz_b hyp_a hyp_b rpm_a rpm_b "
        "aop_a aop_b aop_config_a aop_config_b keymaster_a keymaster_b "
        "cmnlib_a cmnlib_b cmnlib64_a cmnlib64_b qupfw_a qupfw_b "
        "uefisecapp_a uefisecapp_b imagefv_a imagefv_b shrm_a shrm_b "
        "multiimgoem_a multiimgoem_b efisp efisp_a efisp_b "
        "ocdt ocdt_a ocdt_b; do\n"
        "  D=\"/dev/block/by-name/$P\"\n"
        "  [ -b \"$D\" ] || continue\n"
        "  S=$(blockdev --getsize64 \"$D\")\n"
        "  [ \"$S\" -gt 0 ] && [ \"$S\" -le 67108864 ] || { "
        "echo \"Skipping unsafe size: $P ($S bytes)\"; continue; }\n"
        "  echo \"  extracting $P ($S bytes)\"\n"
        "  dd if=\"$D\" of=\"$N/images/$P.img\" bs=1048576 status=none\n"
        "  COUNT=$((COUNT + 1))\n"
        "done\n"
        "[ \"$COUNT\" -gt 0 ] || { echo 'No supported partitions found.'; exit 4; }\n"
        "for A in \"$N\"/images/*_a.img; do\n"
        "  [ -e \"$A\" ] || continue\n"
        "  B=\"${A%_a.img}_b.img\"\n"
        "  [ -e \"$B\" ] || continue\n"
        "  if cmp -s \"$A\" \"$B\"; then\n"
        "    rm -f \"$B\" && ln \"$A\" \"$B\"\n"
        "  fi\n"
        "done\n"
        "{\n"
        "  echo 'format=BrickGuard-BLG-Pack'\n"
        "  echo 'format_version=3'\n"
        "  echo \"created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)\"\n"
        "  echo \"product=$(getprop ro.product.device)\"\n"
        "  echo \"hardware=$(getprop ro.hardware)\"\n"
        "  echo \"slot=$(getprop ro.boot.slot_suffix)\"\n"
        "  echo \"kernel=$(uname -r)\"\n"
        "  echo \"image_count=$COUNT\"\n"
        "} > \"$N/device.txt\"\n"
        "(cd \"$N\" && sha256sum device.txt images/*.img > manifest.sha256)\n"
        "(cd \"$N\" && sha256sum -c manifest.sha256)\n"
        "chmod -R go-rwx \"$N\"\n"
        "sync\n"
        "rm -rf \"$O\"\n"
        "[ ! -e \"$V\" ] || mv \"$V\" \"$O\"\n"
        "mv \"$N\" \"$V\"\n"
        "trap - EXIT INT TERM\n"
        "sync\n"
        "echo \"Recovery Pack created: $V\"\n";
    static const char rollback_script[] =
        "set -eu\n"
        "V='" BG_VAULT "'\n"
        "O=\"${V}.old\"\n"
        "B=\"${V}.invalid.$$\"\n"
        "trap 'rm -rf \"$B\"' EXIT INT TERM\n"
        "[ ! -e \"$V\" ] || mv \"$V\" \"$B\"\n"
        "[ ! -e \"$O\" ] || mv \"$O\" \"$V\"\n"
        "rm -rf \"$B\"\n"
        "trap - EXIT INT TERM\n"
        "sync\n";
    static const char finish_script[] =
        "set -eu\n"
        "rm -rf '" BG_VAULT ".old'\n"
        "sync\n";

    int rc;

    puts("Creating BrickGuard BLG Recovery Pack...");
    rc = bg_run_shell(script);
    if (rc)
        return rc;
    rc = bg_pack_verify(0);
    if (rc) {
        if (bg_run_shell(rollback_script))
            fprintf(stderr, "Pack validation and rollback both failed.\n");
        return rc;
    }
    if (bg_run_shell(finish_script))
        fprintf(stderr, "warning: verified Pack kept its .old backup.\n");
    return 0;
}

int bg_pack_verify(int verbose)
{
    struct bg_inventory inventory;

    if (bg_inventory_load(&inventory)) {
        if (verbose)
            puts("Recovery Pack: INVALID");
        return 1;
    }
    if (verbose)
        printf("Recovery Pack: VERIFIED (%d images, %d unique, %llu bytes)\n"
               "Pack ID: %s\n",
               inventory.alias_count, inventory.blob_count,
               (unsigned long long)inventory.total_size,
               inventory.pack_id);
    bg_inventory_close(&inventory);
    return 0;
}

static int bg_hex_string(const char *text, size_t length)
{
    size_t index;

    for (index = 0; index < length; index++)
        if (!((text[index] >= '0' && text[index] <= '9') ||
              (text[index] >= 'a' && text[index] <= 'f') ||
              (text[index] >= 'A' && text[index] <= 'F')))
            return 0;
    return 1;
}

static int bg_hex_value(char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -1;
}

static int bg_hex_digest(const char *text,
                         unsigned char digest[BG_SHA256_SIZE])
{
    size_t index;

    if (!bg_hex_string(text, BG_SHA256_HEX_SIZE))
        return 1;
    for (index = 0; index < BG_SHA256_SIZE; index++) {
        int high = bg_hex_value(text[index * 2]);
        int low = bg_hex_value(text[index * 2 + 1]);

        digest[index] = (unsigned char)((high << 4) | low);
    }
    return 0;
}

static void bg_digest_hex(const unsigned char digest[BG_SHA256_SIZE],
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

static int bg_digest_equal(const unsigned char left[BG_SHA256_SIZE],
                           const unsigned char right[BG_SHA256_SIZE])
{
    unsigned char difference = 0;
    size_t index;

    for (index = 0; index < BG_SHA256_SIZE; index++)
        difference |= left[index] ^ right[index];
    return difference == 0;
}

static int bg_hash_fd(int fd, unsigned char digest[BG_SHA256_SIZE])
{
    struct bg_sha256_ctx context;
    unsigned char buffer[64 * 1024];
    ssize_t received;

    if (lseek(fd, 0, SEEK_SET) != 0)
        return 1;
    bg_sha256_init(&context);
    for (;;) {
        received = read(fd, buffer, sizeof(buffer));
        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0)
            return 1;
        if (!received)
            break;
        bg_sha256_update(&context, buffer, (size_t)received);
    }
    bg_sha256_final(&context, digest);
    return lseek(fd, 0, SEEK_SET) != 0;
}

enum bg_device_field {
    BG_DEVICE_FORMAT = 1u << 0,
    BG_DEVICE_VERSION = 1u << 1,
    BG_DEVICE_CREATED = 1u << 2,
    BG_DEVICE_PRODUCT = 1u << 3,
    BG_DEVICE_HARDWARE = 1u << 4,
    BG_DEVICE_SLOT = 1u << 5,
    BG_DEVICE_KERNEL = 1u << 6,
    BG_DEVICE_IMAGE_COUNT = 1u << 7,
};

#define BG_DEVICE_FIELDS_ALL ((1u << 8) - 1u)

static int bg_device_value_valid(const char *value, int allow_empty)
{
    size_t length = strlen(value);
    size_t index;

    if ((!allow_empty && !length) || length >= 128)
        return 0;
    for (index = 0; index < length; index++)
        if ((unsigned char)value[index] < 0x20 ||
            (unsigned char)value[index] > 0x7e)
            return 0;
    return 1;
}

static int bg_parse_image_count(const char *value, unsigned int *count)
{
    unsigned int result = 0;

    if (!*value)
        return 1;
    while (*value) {
        unsigned int digit;

        if (*value < '0' || *value > '9')
            return 1;
        digit = (unsigned int)(*value - '0');
        if (result > (BG_MAX_IMAGES - digit) / 10u)
            return 1;
        result = result * 10u + digit;
        value++;
    }
    if (!result || result > BG_MAX_IMAGES)
        return 1;
    *count = result;
    return 0;
}

static int bg_device_info_load(int fd, struct bg_inventory *inventory)
{
    char line[512];
    FILE *stream;
    unsigned int seen = 0;
    int stream_fd = dup(fd);
    int rc = 1;

    if (stream_fd < 0)
        return 1;
    stream = fdopen(stream_fd, "r");
    if (!stream) {
        close(stream_fd);
        return 1;
    }

    while (fgets(line, sizeof(line), stream) != NULL) {
        char *separator;
        char *key;
        char *value;
        size_t length = strlen(line);
        unsigned int field = 0;

        if (!length || line[length - 1] != '\n')
            goto out;
        line[--length] = '\0';
        if (length && line[length - 1] == '\r')
            line[--length] = '\0';
        separator = strchr(line, '=');
        if (!separator || separator == line)
            goto out;
        *separator = '\0';
        key = line;
        value = separator + 1;

        if (!strcmp(key, "format")) {
            field = BG_DEVICE_FORMAT;
            if (strcmp(value, "BrickGuard-BLG-Pack"))
                goto out;
        } else if (!strcmp(key, "format_version")) {
            field = BG_DEVICE_VERSION;
            if (strcmp(value, "3"))
                goto out;
        } else if (!strcmp(key, "created_utc")) {
            field = BG_DEVICE_CREATED;
            if (!bg_device_value_valid(value, 0))
                goto out;
        } else if (!strcmp(key, "product")) {
            field = BG_DEVICE_PRODUCT;
            if (!bg_device_value_valid(value, 0))
                goto out;
            memcpy(inventory->product, value, strlen(value) + 1);
        } else if (!strcmp(key, "hardware")) {
            field = BG_DEVICE_HARDWARE;
            if (!bg_device_value_valid(value, 0))
                goto out;
            memcpy(inventory->hardware, value, strlen(value) + 1);
        } else if (!strcmp(key, "slot")) {
            field = BG_DEVICE_SLOT;
            if (!bg_device_value_valid(value, 1) ||
                (*value && strcmp(value, "a") && strcmp(value, "b") &&
                 strcmp(value, "_a") && strcmp(value, "_b")))
                goto out;
        } else if (!strcmp(key, "kernel")) {
            field = BG_DEVICE_KERNEL;
            if (!bg_device_value_valid(value, 0))
                goto out;
        } else if (!strcmp(key, "image_count")) {
            field = BG_DEVICE_IMAGE_COUNT;
            if (bg_parse_image_count(value,
                                     &inventory->declared_image_count))
                goto out;
        } else {
            goto out;
        }
        if (seen & field)
            goto out;
        seen |= field;
    }
    if (!ferror(stream) && seen == BG_DEVICE_FIELDS_ALL)
        rc = 0;

out:
    fclose(stream);
    if (rc)
        fprintf(stderr, "Invalid BrickGuard Pack v3 device.txt.\n");
    return rc;
}

static int bg_has_img_suffix(const char *name)
{
    size_t length = strlen(name);
    return length > 4 && !strcmp(name + length - 4, ".img");
}

static int bg_valid_logical_name(const char *name, size_t length)
{
    size_t index;

    if (!length || length >= BG_BLG_MAP_NAME)
        return 0;
    for (index = 0; index < length; index++)
        if (!((name[index] >= 'a' && name[index] <= 'z') ||
              (name[index] >= '0' && name[index] <= '9') ||
              name[index] == '_'))
            return 0;
    return 1;
}

static void bg_inventory_close(struct bg_inventory *inventory)
{
    int index;

    for (index = 0; index < inventory->blob_count; index++) {
        if (inventory->blobs[index].fd >= 0)
            close(inventory->blobs[index].fd);
        inventory->blobs[index].fd = -1;
    }
}

static int bg_alias_exists(const struct bg_inventory *inventory,
                           const char *name)
{
    int index;

    for (index = 0; index < inventory->alias_count; index++)
        if (!strcmp(inventory->aliases[index].name, name))
            return 1;
    return 0;
}

static int bg_inventory_check_extras(const struct bg_inventory *inventory,
                                     int images_fd)
{
    DIR *dir;
    struct dirent *entry;
    int scan_fd;
    int rc = 0;

    scan_fd = dup(images_fd);
    if (scan_fd < 0)
        return 1;
    dir = fdopendir(scan_fd);
    if (!dir) {
        close(scan_fd);
        return 1;
    }
    while ((entry = readdir(dir)) != NULL) {
        char name[BG_BLG_MAP_NAME];
        size_t length;

        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        if (!bg_has_img_suffix(entry->d_name)) {
            fprintf(stderr, "Unexpected Recovery Pack entry: %s\n",
                    entry->d_name);
            rc = 1;
            break;
        }
        length = strlen(entry->d_name) - 4;
        if (!length || length >= sizeof(name)) {
            rc = 1;
            break;
        }
        memcpy(name, entry->d_name, length);
        name[length] = '\0';
        if (!bg_alias_exists(inventory, name)) {
            fprintf(stderr, "Unmanifested image rejected: %s\n",
                    entry->d_name);
            rc = 1;
            break;
        }
    }
    closedir(dir);
    return rc;
}

static int bg_inventory_check_root(int vault_fd)
{
    DIR *dir;
    struct dirent *entry;
    int scan_fd = dup(vault_fd);
    int rc = 0;

    if (scan_fd < 0)
        return 1;
    dir = fdopendir(scan_fd);
    if (!dir) {
        close(scan_fd);
        return 1;
    }
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;

        if (!strcmp(name, ".") || !strcmp(name, "..") ||
            !strcmp(name, "images") || !strcmp(name, "device.txt") ||
            !strcmp(name, "manifest.sha256"))
            continue;
        fprintf(stderr, "Unexpected Recovery Pack root entry: %s\n", name);
        rc = 1;
        break;
    }
    closedir(dir);
    return rc;
}

static int bg_inventory_load(struct bg_inventory *inventory)
{
    char line[512];
    struct bg_sha256_ctx manifest_hash;
    unsigned char manifest_digest[BG_SHA256_SIZE];
    FILE *manifest = NULL;
    int vault_fd = -1;
    int images_fd = -1;
    int manifest_fd = -1;
    int device_seen = 0;
    int rc = 1;
    int initialize;

    memset(inventory, 0, sizeof(*inventory));
    for (initialize = 0; initialize < BG_MAX_IMAGES; initialize++)
        inventory->blobs[initialize].fd = -1;
    vault_fd = open(BG_VAULT, O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                   O_NOFOLLOW);
    if (vault_fd < 0)
        goto out;
    images_fd = openat(vault_fd, "images",
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (images_fd < 0)
        goto out;
    manifest_fd = openat(vault_fd, "manifest.sha256",
                         O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (manifest_fd < 0)
        goto out;
    {
        struct stat manifest_stat;

        if (fstat(manifest_fd, &manifest_stat) ||
            !S_ISREG(manifest_stat.st_mode) || manifest_stat.st_size <= 0 ||
            manifest_stat.st_nlink != 1)
            goto out;
    }
    manifest = fdopen(manifest_fd, "r");
    if (!manifest)
        goto out;
    manifest_fd = -1;
    bg_sha256_init(&manifest_hash);

    while (fgets(line, sizeof(line), manifest) != NULL) {
        char *relative;
        char *filename;
        char full_path[PATH_MAX];
        char logical_name[BG_BLG_MAP_NAME];
        unsigned char expected_digest[BG_SHA256_SIZE];
        size_t line_length;
        size_t name_length;
        struct stat file_stat;
        int fd = -1;
        int blob_index = -1;
        int index;

        line_length = strlen(line);
        bg_sha256_update(&manifest_hash, line, line_length);
        if (!line_length || line[line_length - 1] != '\n') {
            fprintf(stderr, "Malformed manifest line.\n");
            goto out;
        }
        line[--line_length] = '\0';
        if (line_length < 67 || bg_hex_digest(line, expected_digest) ||
            line[64] != ' ' || (line[65] != ' ' && line[65] != '*')) {
            fprintf(stderr, "Malformed manifest entry.\n");
            goto out;
        }
        relative = line + 66;
        if (!strcmp(relative, "device.txt")) {
            if (device_seen)
                goto out;
            fd = openat(vault_fd, "device.txt",
                        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            if (fd < 0 || fstat(fd, &file_stat) ||
                !S_ISREG(file_stat.st_mode) || file_stat.st_size <= 0 ||
                file_stat.st_size > 65536 || file_stat.st_nlink != 1 ||
                bg_hash_fd(fd, manifest_digest) ||
                !bg_digest_equal(manifest_digest, expected_digest) ||
                bg_device_info_load(fd, inventory)) {
                if (fd >= 0)
                    close(fd);
                fprintf(stderr, "Invalid device.txt in Recovery Pack.\n");
                goto out;
            }
            close(fd);
            device_seen = 1;
            continue;
        }
        if (strncmp(relative, "images/", 7)) {
            fprintf(stderr, "Manifest path outside images/: %s\n",
                    relative);
            goto out;
        }
        filename = relative + 7;
        if (!*filename || strchr(filename, '/') || !bg_has_img_suffix(filename))
            goto out;
        name_length = strlen(filename) - 4;
        if (!bg_valid_logical_name(filename, name_length))
            goto out;
        memcpy(logical_name, filename, name_length);
        logical_name[name_length] = '\0';
        if (bg_alias_exists(inventory, logical_name) ||
            inventory->alias_count >= BG_MAX_IMAGES) {
            fprintf(stderr, "Duplicate or excessive logical image: %s\n",
                    logical_name);
            goto out;
        }

        if (snprintf(full_path, sizeof(full_path), "%s/images/%s",
                     BG_VAULT, filename) >= (int)sizeof(full_path)) {
            fprintf(stderr, "Recovery Pack path is too long.\n");
            goto out;
        }
        fd = openat(images_fd, filename, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0 || fstat(fd, &file_stat) ||
            !S_ISREG(file_stat.st_mode) || file_stat.st_size <= 0) {
            if (fd >= 0)
                close(fd);
            fprintf(stderr, "Cannot open image safely: %s\n", full_path);
            goto out;
        }

        for (index = 0; index < inventory->blob_count; index++)
            if (inventory->blobs[index].device == file_stat.st_dev &&
                inventory->blobs[index].inode == file_stat.st_ino)
                blob_index = index;
        if (blob_index < 0) {
            struct bg_blob *blob;

            if (inventory->blob_count >= BG_MAX_IMAGES ||
                (uint64_t)file_stat.st_size >
                    UINT64_MAX - inventory->total_size ||
                inventory->total_size + (uint64_t)file_stat.st_size >
                    BG_BLG_CACHE_MAX) {
                close(fd);
                fprintf(stderr, "Recovery Pack exceeds cache limits.\n");
                goto out;
            }
            blob_index = inventory->blob_count++;
            blob = &inventory->blobs[blob_index];
            if (bg_hash_fd(fd, blob->digest) ||
                !bg_digest_equal(blob->digest, expected_digest)) {
                close(fd);
                inventory->blob_count--;
                fprintf(stderr, "SHA-256 mismatch: %s\n", full_path);
                goto out;
            }
            memcpy(blob->path, full_path, strlen(full_path) + 1);
            blob->fd = fd;
            blob->size = file_stat.st_size;
            blob->device = file_stat.st_dev;
            blob->inode = file_stat.st_ino;
            blob->links = file_stat.st_nlink;
            blob->cache_offset = inventory->total_size;
            inventory->total_size += (uint64_t)file_stat.st_size;
        } else {
            if (inventory->blobs[blob_index].size != file_stat.st_size ||
                !bg_digest_equal(inventory->blobs[blob_index].digest,
                                 expected_digest)) {
                close(fd);
                goto out;
            }
            close(fd);
        }

        snprintf(inventory->aliases[inventory->alias_count].name,
                 sizeof(inventory->aliases[inventory->alias_count].name),
                 "%s", logical_name);
        inventory->aliases[inventory->alias_count].blob_index = blob_index;
        inventory->alias_count++;
    }
    if (ferror(manifest) || !device_seen || !inventory->alias_count ||
        !inventory->blob_count || !inventory->total_size ||
        inventory->declared_image_count !=
            (unsigned int)inventory->alias_count)
        goto out;
    bg_sha256_final(&manifest_hash, manifest_digest);
    bg_digest_hex(manifest_digest, inventory->pack_id);
    for (initialize = 0; initialize < inventory->blob_count; initialize++) {
        int aliases = 0;
        int index;

        for (index = 0; index < inventory->alias_count; index++)
            if (inventory->aliases[index].blob_index == initialize)
                aliases++;
        if ((nlink_t)aliases != inventory->blobs[initialize].links) {
            fprintf(stderr, "External hardlink rejected: %s\n",
                    inventory->blobs[initialize].path);
            goto out;
        }
    }
    if (bg_inventory_check_extras(inventory, images_fd) ||
        bg_inventory_check_root(vault_fd))
        goto out;
    rc = 0;

out:
    if (manifest)
        fclose(manifest);
    else if (manifest_fd >= 0)
        close(manifest_fd);
    if (images_fd >= 0)
        close(images_fd);
    if (vault_fd >= 0)
        close(vault_fd);
    if (rc)
        bg_inventory_close(inventory);
    return rc;
}

static int bg_inventory_revalidate(const struct bg_inventory *inventory)
{
    int index;

    for (index = 0; index < inventory->blob_count; index++) {
        const struct bg_blob *blob = &inventory->blobs[index];
        unsigned char digest[BG_SHA256_SIZE];
        struct stat current;

        if (fstat(blob->fd, &current) ||
            !S_ISREG(current.st_mode) ||
            current.st_size != blob->size ||
            current.st_dev != blob->device ||
            current.st_ino != blob->inode ||
            current.st_nlink != blob->links ||
            bg_hash_fd(blob->fd, digest) ||
            !bg_digest_equal(digest, blob->digest)) {
            fprintf(stderr, "Recovery Pack changed while loading: %s\n",
                    blob->path);
            return 1;
        }
    }
    return 0;
}

static int bg_write_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *cursor = buffer;

    while (length) {
        ssize_t written = write(fd, cursor, length);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return 1;
        cursor += written;
        length -= (size_t)written;
    }
    return 0;
}

static int bg_read_full(int fd, void *buffer, size_t length)
{
    unsigned char *cursor = buffer;

    while (length) {
        ssize_t received = read(fd, cursor, length);
        if (received < 0 && errno == EINTR)
            continue;
        if (received <= 0)
            return 1;
        cursor += received;
        length -= (size_t)received;
    }
    return 0;
}

static int bg_get_property(const char *name, char *value, size_t value_size)
{
    int descriptors[2];
    int status;
    pid_t child;
    size_t used = 0;
    int rc = 1;

    if (!name || !value || value_size < 2 ||
        pipe2(descriptors, O_CLOEXEC))
        return 1;
    child = fork();
    if (child == 0) {
        close(descriptors[0]);
        if (dup2(descriptors[1], STDOUT_FILENO) < 0)
            _exit(127);
        close(descriptors[1]);
        execl("/system/bin/getprop", "getprop", name, (char *)NULL);
        _exit(127);
    }
    close(descriptors[1]);
    if (child < 0) {
        close(descriptors[0]);
        return 1;
    }

    while (used < value_size - 1) {
        ssize_t received = read(descriptors[0], value + used,
                                value_size - 1 - used);

        if (received < 0 && errno == EINTR)
            continue;
        if (received < 0)
            goto wait;
        if (!received)
            break;
        used += (size_t)received;
    }
    if (used == value_size - 1) {
        char extra;
        ssize_t received;

        do {
            received = read(descriptors[0], &extra, 1);
        } while (received < 0 && errno == EINTR);
        if (received != 0)
            goto wait;
    }
    value[used] = '\0';
    while (used && (value[used - 1] == '\n' || value[used - 1] == '\r'))
        value[--used] = '\0';
    rc = used ? 0 : 1;

wait:
    close(descriptors[0]);
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR)
            return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 1;
    return rc;
}

static int bg_inventory_device_matches(const struct bg_inventory *inventory)
{
    char product[128];
    char hardware[128];

    if (bg_get_property("ro.product.device", product, sizeof(product)) ||
        bg_get_property("ro.hardware", hardware, sizeof(hardware))) {
        fprintf(stderr, "Cannot read current Android device identity.\n");
        return 1;
    }
    if (strcmp(product, inventory->product) ||
        strcmp(hardware, inventory->hardware)) {
        fprintf(stderr,
                "Recovery Pack belongs to %s/%s, current device is %s/%s.\n",
                inventory->product, inventory->hardware, product, hardware);
        return 1;
    }
    return 0;
}

static char bg_active_slot(void)
{
    char value[32] = {0};
    char *slot = value;

    if (!bg_get_property("ro.boot.slot_suffix", value, sizeof(value))) {
        if (*slot == '_')
            slot++;
        if ((slot[0] == 'a' || slot[0] == 'b') && slot[1] == '\0')
            return slot[0];
    }

    {
        static const char *paths[] = {"/proc/bootconfig", "/proc/cmdline"};
        char buffer[8192];
        size_t index;

        for (index = 0; index < sizeof(paths) / sizeof(paths[0]); index++) {
            int fd = open(paths[index], O_RDONLY | O_CLOEXEC);
            ssize_t received;
            char *slot;

            if (fd < 0)
                continue;
            received = read(fd, buffer, sizeof(buffer) - 1);
            close(fd);
            if (received <= 0)
                continue;
            buffer[received] = '\0';
            slot = strstr(buffer, "androidboot.slot_suffix");
            if (!slot)
                continue;
            slot += strlen("androidboot.slot_suffix");
            while (*slot == ' ' || *slot == '\t')
                slot++;
            if (*slot == '=')
                slot++;
            while (*slot == ' ' || *slot == '\t' || *slot == '"')
                slot++;
            if (*slot == '_')
                slot++;
            if (*slot == 'a' || *slot == 'b')
                return *slot;
        }
    }
    return 0;
}

static unsigned int bg_partition_tier(const char *name)
{
    if (!strncmp(name, "xbl", 3))
        return 0;
    if (!strncmp(name, "multiimgoem", 11))
        return 2;
    return 1;
}

static int bg_map_build(const struct bg_inventory *inventory)
{
    char reply[128] = {0};
    char command[256];
    char active = bg_active_slot();
    dev_t targets[BG_MAX_IMAGES];
    int target_count = 0;
    int mapped = 0;
    uint64_t map_total = 0;
    int index;

    if (active != 'a' && active != 'b') {
        fprintf(stderr, "Cannot determine active A/B slot.\n");
        return 1;
    }
    if (bg_rpc("BLG MAP BEGIN", reply, sizeof(reply)) < 0 ||
        strcmp(reply, "OK MAP BEGIN")) {
        fprintf(stderr, "Map begin failed: %s\n", reply);
        return 1;
    }

    for (index = 0; index < inventory->alias_count; index++) {
        const struct bg_alias *alias = &inventory->aliases[index];
        const struct bg_blob *blob =
            &inventory->blobs[alias->blob_index];
        char target[BG_BLG_MAP_NAME];
        char target_path[128];
        size_t length = strnlen(alias->name, sizeof(alias->name));
        unsigned int flags;
        unsigned int tier;
        struct stat target_stat;
        uint64_t target_size = 0;
        int target_fd;
        int duplicate = 0;
        int previous;
        int formatted;

        if (!length || length >= sizeof(alias->name) ||
            length >= sizeof(target)) {
            fprintf(stderr, "Invalid logical image name.\n");
            return 1;
        }
        memcpy(target, alias->name, length + 1);
        if (!strcmp(alias->name, "efisp") ||
            !strcmp(alias->name, "efisp_a") ||
            !strcmp(alias->name, "efisp_b")) {
            flags = BG_BLG_FLAG_SHARED | BG_BLG_FLAG_EFISP;
            tier = 0;
        } else if (length >= 3 && alias->name[length - 2] == '_' &&
            (alias->name[length - 1] == 'a' ||
             alias->name[length - 1] == 'b')) {
            if (alias->name[length - 1] != active)
                continue;
            target[length - 1] = active == 'a' ? 'b' : 'a';
            flags = BG_BLG_FLAG_AB;
            tier = bg_partition_tier(alias->name);
        } else {
            flags = BG_BLG_FLAG_SHARED;
            tier = 0;
        }

        if ((uint64_t)blob->size > BG_BLG_CACHE_MAX - map_total) {
            fprintf(stderr, "Image Map exceeds %lu bytes.\n",
                    (unsigned long)BG_BLG_CACHE_MAX);
            return 1;
        }
        map_total += (uint64_t)blob->size;

        if (snprintf(target_path, sizeof(target_path),
                     "/dev/block/by-name/%s", target) >=
            (int)sizeof(target_path))
            return 1;
        target_fd = open(target_path, O_RDONLY | O_CLOEXEC);
        if (target_fd < 0 || fstat(target_fd, &target_stat) ||
            !S_ISBLK(target_stat.st_mode) ||
            ioctl(target_fd, BLKGETSIZE64, &target_size)) {
            if (target_fd >= 0)
                close(target_fd);
            fprintf(stderr, "Invalid map target: %s\n", target_path);
            return 1;
        }
        close(target_fd);
        if ((uint64_t)blob->size > target_size) {
            fprintf(stderr, "Image is larger than target: %s\n",
                    target_path);
            return 1;
        }
        for (previous = 0; previous < target_count; previous++)
            if (targets[previous] == target_stat.st_rdev)
                duplicate = 1;
        if (duplicate) {
            fprintf(stderr, "Duplicate map target rejected: %s\n",
                    target_path);
            return 1;
        }
        targets[target_count++] = target_stat.st_rdev;

        formatted = snprintf(
            command, sizeof(command),
            "BLG MAP ADD %s %llu %llu %u %u %llu %u %u",
            target, (unsigned long long)blob->cache_offset,
            (unsigned long long)blob->size, major(target_stat.st_rdev),
            minor(target_stat.st_rdev), (unsigned long long)target_size,
            flags, tier);
        if (formatted < 0 || formatted >= (int)sizeof(command) ||
            bg_rpc(command, reply, sizeof(reply)) < 0 ||
            strcmp(reply, "OK MAP ADD")) {
            fprintf(stderr, "Map add failed for %s: %s\n", target, reply);
            return 1;
        }
        mapped++;
    }

    if (!mapped ||
        bg_rpc("BLG MAP COMMIT", reply, sizeof(reply)) < 0 ||
        strcmp(reply, "OK PLAN READY NO WRITE") ||
        bg_rpc("BLG MAP VERIFY", reply, sizeof(reply)) < 0 ||
        strcmp(reply, "OK MAP INTACT")) {
        fprintf(stderr, "Map commit or verification failed: %s\n", reply);
        return 1;
    }
    printf("BLG Image Map: READY (%d targets, active slot _%c, NO WRITE)\n",
           mapped, active);
    return 0;
}

int bg_blg_prepare(void)
{
    struct bg_inventory inventory;
    unsigned char *input = NULL;
    unsigned char *output = NULL;
    char command[128];
    char reply[128] = {0};
    int cache_fd = -1;
    int rc = 1;
    int index;

    if (bg_inventory_load(&inventory))
        return 1;
    if (bg_inventory_device_matches(&inventory))
        goto out;

    if (snprintf(command, sizeof(command), "BLG CACHE BEGIN %llu %s",
                 (unsigned long long)inventory.total_size,
                 inventory.pack_id) >= (int)sizeof(command))
        goto out;
    if (bg_rpc(command, reply, sizeof(reply)) < 0 ||
        strcmp(reply, "OK CACHE BEGIN")) {
        fprintf(stderr, "Cache allocation failed: %s\n", reply);
        goto out;
    }
    cache_fd = open(BG_CACHE_PATH, O_WRONLY | O_CLOEXEC);
    if (cache_fd < 0) {
        perror(BG_CACHE_PATH);
        goto out;
    }
    input = malloc(BG_IO_CHUNK);
    output = malloc(BG_IO_CHUNK);
    if (!input || !output) {
        perror("cache buffers");
        goto out;
    }

    for (index = 0; index < inventory.blob_count; index++) {
        struct bg_blob *blob = &inventory.blobs[index];
        uint64_t left = (uint64_t)blob->size;

        if (lseek(blob->fd, 0, SEEK_SET) != 0)
            goto out;
        while (left) {
            size_t chunk = left > BG_IO_CHUNK ?
                           BG_IO_CHUNK : (size_t)left;
            if (bg_read_full(blob->fd, input, chunk) ||
                bg_write_all(cache_fd, input, chunk)) {
                fprintf(stderr, "Cache upload failed: %s\n", blob->path);
                goto out;
            }
            left -= chunk;
        }
    }
    close(cache_fd);
    cache_fd = -1;
    if (bg_inventory_revalidate(&inventory))
        goto out;
    if (bg_rpc("BLG CACHE COMMIT", reply, sizeof(reply)) < 0 ||
        strcmp(reply, "OK CACHE READY RO")) {
        fprintf(stderr, "Cache commit failed: %s\n", reply);
        goto out;
    }

    cache_fd = open(BG_CACHE_PATH, O_RDONLY | O_CLOEXEC);
    if (cache_fd < 0) {
        perror(BG_CACHE_PATH);
        goto out;
    }
    for (index = 0; index < inventory.blob_count; index++) {
        struct bg_blob *blob = &inventory.blobs[index];
        uint64_t left = (uint64_t)blob->size;
        struct bg_sha256_ctx context;
        unsigned char digest[BG_SHA256_SIZE];

        bg_sha256_init(&context);
        while (left) {
            size_t chunk = left > BG_IO_CHUNK ?
                           BG_IO_CHUNK : (size_t)left;
            if (bg_read_full(cache_fd, output, chunk)) {
                fprintf(stderr, "Cache readback failed: %s\n", blob->path);
                goto out;
            }
            bg_sha256_update(&context, output, chunk);
            left -= chunk;
        }
        bg_sha256_final(&context, digest);
        if (!bg_digest_equal(digest, blob->digest)) {
            fprintf(stderr, "Cache digest mismatch: %s\n", blob->path);
            goto out;
        }
    }
    if (read(cache_fd, output, 1) != 0) {
        fprintf(stderr, "Cache contains trailing data.\n");
        goto out;
    }
    close(cache_fd);
    cache_fd = -1;
    if (bg_rpc("BLG CACHE VERIFY", reply, sizeof(reply)) < 0 ||
        strcmp(reply, "OK CACHE INTACT")) {
        fprintf(stderr, "Kernel cache digest failed: %s\n", reply);
        goto out;
    }
    if (bg_map_build(&inventory))
        goto out;

    printf("BLG RAM Cache: READY RO (%d unique blobs, %llu bytes)\n",
           inventory.blob_count,
           (unsigned long long)inventory.total_size);
    rc = 0;

out:
    if (cache_fd >= 0)
        close(cache_fd);
    free(input);
    free(output);
    if (rc)
        bg_rpc("BLG CACHE DROP", reply, sizeof(reply));
    bg_inventory_close(&inventory);
    return rc;
}

int bg_blg_verify(void)
{
    struct bg_inventory inventory;
    char reply[128] = {0};
    int rc = 1;

    if (bg_inventory_load(&inventory)) {
        puts("Recovery Pack: INVALID");
        return 1;
    }
    if (bg_inventory_device_matches(&inventory))
        goto out;
    printf("Recovery Pack: VERIFIED (%s)\n", inventory.pack_id);
    if (bg_rpc("BLG PACK ID", reply, sizeof(reply)) < 0 ||
        strncmp(reply, "OK PACK ", 8) ||
        strcmp(reply + 8, inventory.pack_id)) {
        printf("Pack binding: %s\n", reply[0] ? reply : "UNAVAILABLE");
        goto out;
    }
    puts("Pack binding: MATCHED");
    if (bg_rpc("BLG CACHE VERIFY", reply, sizeof(reply)) < 0 ||
        strcmp(reply, "OK CACHE INTACT")) {
        printf("RAM Cache: %s\n", reply);
        goto out;
    }
    puts("RAM Cache: INTACT");
    if (bg_rpc("BLG MAP VERIFY", reply, sizeof(reply)) < 0 ||
        strcmp(reply, "OK MAP INTACT")) {
        printf("Image Map: %s\n", reply);
        goto out;
    }
    puts("Image Map: INTACT");
    rc = 0;

out:
    bg_inventory_close(&inventory);
    return rc;
}

int bg_blg_release(void)
{
    char reply[128] = {0};
    int rc = bg_rpc("BLG CACHE DROP", reply, sizeof(reply));

    if (rc < 0) {
        fprintf(stderr, "BLG CACHE DROP failed: %s\n", strerror(-rc));
        return 1;
    }
    puts(reply);
    return strcmp(reply, "OK CACHE EMPTY") != 0;
}

static int bg_open_loop_control(void)
{
    int fd = open("/dev/block/loop-control", O_RDWR | O_CLOEXEC);
    if (fd < 0)
        fd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
    return fd;
}

static int bg_map_info(unsigned int *entries, uint64_t *total,
                       char pack_id[BG_SHA256_HEX_SIZE + 1])
{
    char reply[128] = {0};
    unsigned long long parsed_total;
    char extra;

    if (bg_rpc("BLG MAP INFO", reply, sizeof(reply)) < 0 ||
        sscanf(reply, "OK MAP %u %llu %64s %c", entries, &parsed_total,
               pack_id, &extra) != 3 ||
        !*entries || !parsed_total ||
        strlen(pack_id) != BG_SHA256_HEX_SIZE ||
        !bg_hex_string(pack_id, BG_SHA256_HEX_SIZE)) {
        fprintf(stderr, "Map info unavailable: %s\n", reply);
        return 1;
    }
    *total = (uint64_t)parsed_total;
    return 0;
}

int bg_blg_selftest(void)
{
    struct bg_inventory inventory;
    struct loop_info64 loop_info;
    char image[] = "/data/local/tmp/brickguard-blg.XXXXXX";
    char loop_path[64];
    char command[128];
    char reply[128] = {0};
    char map_pack_id[BG_SHA256_HEX_SIZE + 1];
    uint64_t map_total;
    unsigned int map_entries;
    int image_fd = -1;
    int control_fd = -1;
    int loop_fd = -1;
    int loop_index;
    int attached = 0;
    int rc = 1;

    if (bg_inventory_load(&inventory))
        return 1;
    if (bg_inventory_device_matches(&inventory)) {
        bg_inventory_close(&inventory);
        return 1;
    }
    if (bg_map_info(&map_entries, &map_total, map_pack_id) ||
        strcmp(map_pack_id, inventory.pack_id)) {
        fprintf(stderr, "Selftest refused: Pack/cache/map IDs differ.\n");
        bg_inventory_close(&inventory);
        return 1;
    }
    image_fd = mkstemp(image);
    if (image_fd < 0) {
        perror("mkstemp");
        goto out;
    }
    if (map_total > (uint64_t)INT64_MAX - BG_IO_CHUNK ||
        ftruncate(image_fd, (off_t)(map_total + BG_IO_CHUNK))) {
        perror("ftruncate");
        goto out;
    }
    control_fd = bg_open_loop_control();
    if (control_fd < 0) {
        perror("loop-control");
        goto out;
    }
    loop_index = ioctl(control_fd, LOOP_CTL_GET_FREE);
    if (loop_index < 0) {
        perror("LOOP_CTL_GET_FREE");
        goto out;
    }
    snprintf(loop_path, sizeof(loop_path), "/dev/block/loop%d", loop_index);
    loop_fd = open(loop_path, O_RDWR | O_CLOEXEC);
    if (loop_fd < 0) {
        snprintf(loop_path, sizeof(loop_path), "/dev/loop%d", loop_index);
        loop_fd = open(loop_path, O_RDWR | O_CLOEXEC);
    }
    if (loop_fd < 0 || ioctl(loop_fd, LOOP_SET_FD, image_fd)) {
        perror("LOOP_SET_FD");
        goto out;
    }
    attached = 1;
    memset(&loop_info, 0, sizeof(loop_info));
    loop_info.lo_flags = LO_FLAGS_AUTOCLEAR;
    if (ioctl(loop_fd, LOOP_SET_STATUS64, &loop_info) ||
        ioctl(loop_fd, LOOP_SET_CAPACITY)) {
        perror("loop configure");
        goto out;
    }

    snprintf(command, sizeof(command), "BLG SELFTEST %s INJECT",
             loop_path);
    if (bg_rpc(command, reply, sizeof(reply)) < 0 ||
        strcmp(reply, "OK SELFTEST REPAIRED")) {
        fprintf(stderr, "BLG selftest failed: %s\n", reply);
        goto out;
    }
    puts(reply);
    rc = 0;

out:
    if (attached && ioctl(loop_fd, LOOP_CLR_FD))
        perror("LOOP_CLR_FD");
    if (loop_fd >= 0)
        close(loop_fd);
    if (control_fd >= 0)
        close(control_fd);
    if (image_fd >= 0)
        close(image_fd);
    unlink(image);
    bg_inventory_close(&inventory);
    return rc;
}
