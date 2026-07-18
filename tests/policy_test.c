/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdio.h>

#include "../include/brickguard_policy.h"

static void test_parse(void)
{
    enum bg_mode mode = BG_MODE_OFF;

    assert(bg_parse_mode("0", &mode) == 0 && mode == BG_MODE_OFF);
    assert(bg_parse_mode("", &mode) < 0);
    assert(bg_parse_mode("3", &mode) < 0);
    assert(bg_parse_mode("02", &mode) < 0);
    assert(bg_parse_mode("1\n", &mode) < 0);
    assert(bg_parse_mode(" 2", &mode) < 0);
    assert(bg_parse_mode("mode=2", &mode) < 0);
    assert(bg_parse_mode("MODE2", &mode) < 0);
    assert(bg_parse_mode("1 extra", &mode) < 0);
    assert(bg_parse_mode(0, &mode) < 0);
    assert(bg_parse_mode("0", 0) < 0);
}

static void test_actions(void)
{
    assert(bg_action_for_mode(BG_MODE_OFF) == BG_ACTION_PASS);
    assert(bg_action_for_mode(BG_MODE_DENY) == BG_ACTION_DENY);
    assert(bg_action_for_mode(BG_MODE_SIMULATE) == BG_ACTION_SIMULATE);
    assert(bg_action_for_mode((enum bg_mode)99) == BG_ACTION_DENY);

    assert(bg_write_result(BG_ACTION_PASS, 4096) == 0);
    assert(bg_write_result(BG_ACTION_DENY, 4096) == -1);
    assert(bg_write_result(BG_ACTION_SIMULATE, 4096) == 4096);
    assert(bg_zero_result(BG_ACTION_PASS) == 0);
    assert(bg_zero_result(BG_ACTION_DENY) == -1);
    assert(bg_zero_result(BG_ACTION_SIMULATE) == 0);
}

int main(void)
{
    test_parse();
    test_actions();
    puts("BrickGuard policy tests passed.");
    return 0;
}
