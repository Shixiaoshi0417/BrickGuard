/* SPDX-License-Identifier: GPL-2.0-only */
#include "brickguard_internal.h"

#define BG_KPM_INFO(key, value, limit)                                  \
    _Static_assert(sizeof(value) <= limit, "KPM info too long");        \
    static const char bg_kpm_info_##key[] __attribute__((used,           \
        section(".kpm.info"), aligned(1))) = #key "=" value
#define KPM_NAME(value)        BG_KPM_INFO(name, value, 32)
#define KPM_VERSION(value)     BG_KPM_INFO(version, value, 32)
#define KPM_LICENSE(value)     BG_KPM_INFO(license, value, 32)
#define KPM_AUTHOR(value)      BG_KPM_INFO(author, value, 32)
#define KPM_DESCRIPTION(value) BG_KPM_INFO(description, value, 512)

typedef long (*bg_kpm_init_t)(const char *, const char *, void __user *);
typedef long (*bg_kpm_ctl0_t)(const char *, char __user *, int);
typedef long (*bg_kpm_exit_t)(void __user *);

#define KPM_INIT(fn) static bg_kpm_init_t bg_init_##fn                  \
    __attribute__((used, section(".kpm.init"))) = fn
#define KPM_CTL0(fn) static bg_kpm_ctl0_t bg_ctl_##fn                   \
    __attribute__((used, section(".kpm.ctl0"))) = fn
#define KPM_EXIT(fn) static bg_kpm_exit_t bg_exit_##fn                  \
    __attribute__((used, section(".kpm.exit"))) = fn

KPM_NAME(BG_PRODUCT_NAME);
KPM_VERSION(BG_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("BrickGuard contributors");
KPM_DESCRIPTION("Global raw block-device bricker guard and BLG recovery rehearsal");

int bg_mode_value = BG_MODE_OFF;
int bg_admin_busy;
int bg_shutting_down;
int bg_degraded;
int bg_io_active;
int bg_mode_transition;

extern int bg_kpm_exit_veto_supported
    __asm__("kpm_exit_veto_supported");

static int bg_live;

_Static_assert(BG_MODE_OFF == 0, "mode ABI");
_Static_assert(BG_MODE_DENY == 1, "mode ABI");
_Static_assert(BG_MODE_SIMULATE == 2, "mode ABI");

static int bg_text_len(const char *text)
{
    int len = 0;
    while (text && text[len])
        len++;
    return len;
}

static int bg_streq(const char *left, const char *right)
{
    if (!left || !right)
        return 0;
    while (*left && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

static int bg_prefix(const char *text, const char *prefix)
{
    while (*prefix && *text == *prefix) {
        text++;
        prefix++;
    }
    return *prefix == '\0';
}

static long bg_ctl_reply(char __user *out, int out_len, const char *text)
{
    int len = bg_text_len(text) + 1;

    if (!out || out_len <= 0)
        return 0;
    if (len > out_len)
        len = out_len;
    return compat_copy_to_user(out, text, len) > 0 ? 0 : -EFAULT;
}

static const char *bg_mode_status(enum bg_mode mode)
{
    if (bg_degraded)
        return "DEGRADED MODE 1 REBOOT REQUIRED";
    if (mode == BG_MODE_OFF)
        return "MODE 0 OFF";
    if (mode == BG_MODE_DENY)
        return "MODE 1 DENY";
    if (mode == BG_MODE_SIMULATE)
        return "MODE 2 SIMULATE";
    return "MODE INVALID";
}

static long brickguard_init(const char *args, const char *event,
                            void __user *reserved)
{
    enum bg_mode requested;
    int rc;

    (void)event;
    (void)reserved;
    if (bg_parse_mode(args, &requested)) {
        bg_log("load rejected: parameter must be exactly 0, 1, or 2\n");
        return -EINVAL;
    }

    /* Any hook which becomes visible during init starts fail-closed. */
    bg_mode_store(BG_MODE_DENY);
    __atomic_store_n(&bg_admin_busy, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&bg_io_active, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&bg_mode_transition, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&bg_degraded, 0, __ATOMIC_RELAXED);
    bg_shutdown_store(0);
    bg_live = 0;

    if (__atomic_load_n(&bg_kpm_exit_veto_supported,
                        __ATOMIC_ACQUIRE) != 1) {
        bg_log("loader lacks the required KPM exit-veto contract\n");
        return -EPROTONOSUPPORT;
    }

    rc = bg_block_init();
    if (rc)
        goto init_failed;
    rc = bg_blg_init();
    if (rc)
        goto init_failed;

    bg_mode_switch(requested);
    bg_live = 1;
    bg_log("loaded version=%s mode=%d(%s)\n", BG_VERSION, requested,
           bg_mode_name(requested));
    return 0;

init_failed:
    if (!bg_block_has_hooks())
        return rc;
    bg_degraded = rc ? rc : -EIO;
    bg_mode_switch(BG_MODE_DENY);
    bg_live = 1;
    bg_log("loaded degraded rc=%d; mode=1 and reboot required\n", rc);
    return 0;
}

static long brickguard_ctl0(const char *args, char __user *out, int out_len)
{
    enum bg_mode requested;
    const char *mode_arg = args;

    if (!args)
        return -EINVAL;
    if (bg_streq(args, "STATUS"))
        return bg_ctl_reply(out, out_len, bg_mode_status(bg_mode_get()));
    if (bg_streq(args, "BLG STATUS")) {
        long rc;

        if (bg_shutdown_get() || !bg_admin_try_lock())
            return -EBUSY;
        rc = bg_ctl_reply(out, out_len, bg_blg_status_text());
        bg_admin_unlock();
        return rc;
    }
    if (bg_prefix(args, "MODE "))
        mode_arg = args + 5;
    if (bg_parse_mode(mode_arg, &requested))
        return -EINVAL;
    if (bg_degraded)
        return -EIO;
    if (bg_shutdown_get() || !bg_admin_try_lock())
        return -EBUSY;
    bg_mode_switch(requested);
    bg_admin_unlock();
    bg_log("manager changed mode=%d(%s)\n", requested,
           bg_mode_name(requested));
    return bg_ctl_reply(out, out_len, bg_mode_status(requested));
}

static long brickguard_exit(void __user *reserved)
{
    (void)reserved;
    if (bg_live) {
        bg_log("runtime unload refused; reboot is required\n");
        return -EBUSY;
    }

    bg_block_exit();
    return 0;
}

KPM_INIT(brickguard_init);
KPM_CTL0(brickguard_ctl0);
KPM_EXIT(brickguard_exit);
