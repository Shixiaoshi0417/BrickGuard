/* SPDX-License-Identifier: GPL-2.0-only */
#include "../include/brickguard_policy.h"

int bg_parse_mode(const char *text, enum bg_mode *mode)
{
    if (!text || !mode)
        return -1;
    if (text[0] < '0' || text[0] > '2' || text[1] != '\0')
        return -1;
    *mode = (enum bg_mode)(text[0] - '0');
    return 0;
}

int bg_mode_valid(int mode)
{
    return mode >= BG_MODE_OFF && mode <= BG_MODE_SIMULATE;
}

const char *bg_mode_name(enum bg_mode mode)
{
    switch (mode) {
    case BG_MODE_OFF:
        return "OFF";
    case BG_MODE_DENY:
        return "DENY";
    case BG_MODE_SIMULATE:
        return "SIMULATE";
    default:
        return "INVALID";
    }
}

enum bg_action bg_action_for_mode(enum bg_mode mode)
{
    switch (mode) {
    case BG_MODE_DENY:
        return BG_ACTION_DENY;
    case BG_MODE_SIMULATE:
        return BG_ACTION_SIMULATE;
    case BG_MODE_OFF:
        return BG_ACTION_PASS;
    default:
        return BG_ACTION_DENY;
    }
}

long bg_write_result(enum bg_action action, unsigned long count)
{
    if (action == BG_ACTION_DENY)
        return -1;
    if (action == BG_ACTION_SIMULATE)
        return (long)count;
    return 0;
}

long bg_zero_result(enum bg_action action)
{
    if (action == BG_ACTION_DENY)
        return -1;
    return 0;
}
