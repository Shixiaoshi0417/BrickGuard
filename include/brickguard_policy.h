/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BRICKGUARD_POLICY_H
#define BRICKGUARD_POLICY_H

enum bg_mode {
    BG_MODE_OFF = 0,
    BG_MODE_DENY = 1,
    BG_MODE_SIMULATE = 2,
};

enum bg_action {
    BG_ACTION_PASS = 0,
    BG_ACTION_DENY,
    BG_ACTION_SIMULATE,
};

int bg_parse_mode(const char *text, enum bg_mode *mode);
int bg_mode_valid(int mode);
const char *bg_mode_name(enum bg_mode mode);
enum bg_action bg_action_for_mode(enum bg_mode mode);
long bg_write_result(enum bg_action action, unsigned long count);
long bg_zero_result(enum bg_action action);

#endif
