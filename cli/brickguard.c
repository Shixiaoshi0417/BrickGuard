/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "brickguard_cli.h"
#include "../include/brickguard_version.h"

int bg_rpc(const char *command, char *reply, size_t reply_size)
{
    int fd;
    ssize_t written;
    ssize_t received;

    if (!reply || reply_size < 2)
        return -EINVAL;
    reply[0] = '\0';
    fd = open(BG_CONTROL_PATH, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    written = write(fd, command, strlen(command));
    if (written != (ssize_t)strlen(command)) {
        int error = written < 0 ? errno : EIO;
        close(fd);
        return -error;
    }
    received = read(fd, reply, reply_size - 1);
    if (received < 0) {
        int error = errno;
        close(fd);
        return -error;
    }
    reply[received] = '\0';
    close(fd);
    return 0;
}

static int bg_check_compatibility(void)
{
    char reply[128];
    int api = 0;
    char version[64];
    int rc = bg_rpc("HELLO 1", reply, sizeof(reply));

    if (rc < 0) {
        fprintf(stderr, "BrickGuard KPM unavailable: %s\n", strerror(-rc));
        return 1;
    }
    if (sscanf(reply, "OK HELLO %d %63s", &api, version) != 2 ||
        api != BG_RPC_API_VERSION) {
        fprintf(stderr, "Incompatible KPM response: %s\n", reply);
        return 1;
    }
    return 0;
}

static int bg_status(void)
{
    char mode[128];
    char blg[128];
    int rc;

    rc = bg_rpc("MODE STATUS", mode, sizeof(mode));
    if (rc < 0) {
        fprintf(stderr, "Mode status failed: %s\n", strerror(-rc));
        return 1;
    }
    rc = bg_rpc("STATUS", blg, sizeof(blg));
    if (rc < 0) {
        fprintf(stderr, "BLG status failed: %s\n", strerror(-rc));
        return 1;
    }
    printf("BrickGuard %s\n%s\n%s\n", BG_VERSION, mode, blg);
    return 0;
}

static void bg_usage(FILE *stream)
{
    fprintf(stream,
            "Usage:\n"
            "  brickguard status\n"
            "  brickguard pack create|verify\n"
            "  brickguard setup\n"
            "  brickguard prepare\n"
            "  brickguard verify\n"
            "  brickguard release\n"
            "  brickguard selftest\n"
            "\n"
            "Modes are selected by the KPM load parameter or trusted CTL0:\n"
            "  0 = OFF, 1 = DENY, 2 = SIMULATE\n");
}

int main(int argc, char **argv)
{
    if (geteuid() != 0)
        fprintf(stderr, "warning: BrickGuard requires root on device\n");
    if (argc < 2) {
        bg_usage(stderr);
        return 2;
    }

    if (!strcmp(argv[1], "pack")) {
        if (argc != 3) {
            bg_usage(stderr);
            return 2;
        }
        if (!strcmp(argv[2], "create"))
            return bg_pack_create();
        if (!strcmp(argv[2], "verify"))
            return bg_pack_verify(1);
        bg_usage(stderr);
        return 2;
    }

    if (bg_check_compatibility())
        return 1;
    if (!strcmp(argv[1], "status") && argc == 2)
        return bg_status();
    if (!strcmp(argv[1], "setup") && argc == 2) {
        if (bg_pack_create())
            return 1;
        return bg_blg_prepare();
    }
    if (!strcmp(argv[1], "prepare") && argc == 2)
        return bg_blg_prepare();
    if (!strcmp(argv[1], "verify") && argc == 2)
        return bg_blg_verify();
    if (!strcmp(argv[1], "release") && argc == 2)
        return bg_blg_release();
    if (!strcmp(argv[1], "selftest") && argc == 2)
        return bg_blg_selftest();

    bg_usage(stderr);
    return 2;
}
