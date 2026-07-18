/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BRICKGUARD_INTERNAL_H
#define BRICKGUARD_INTERNAL_H

#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/stddef.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <uapi/linux/fs.h>

#include "../include/brickguard_policy.h"
#include "../include/brickguard_protocol.h"
#include "../include/brickguard_version.h"

struct bg_hook_local {
    u64 data[8];
};

struct bg_hook_fargs4 {
    void *chain;
    int skip_origin;
    struct bg_hook_local local;
    u64 ret;
    union {
        struct {
            u64 arg0;
            u64 arg1;
            u64 arg2;
            u64 arg3;
        };
        u64 args[4];
    };
} __attribute__((aligned(8)));

_Static_assert(offsetof(struct bg_hook_fargs4, chain) == 0,
               "KernelPatch hook chain ABI changed");
_Static_assert(offsetof(struct bg_hook_fargs4, skip_origin) == 8,
               "KernelPatch hook skip ABI changed");
_Static_assert(offsetof(struct bg_hook_fargs4, local) == 16,
               "KernelPatch hook local ABI changed");
_Static_assert(offsetof(struct bg_hook_fargs4, ret) == 80,
               "KernelPatch hook return ABI changed");
_Static_assert(offsetof(struct bg_hook_fargs4, arg0) == 88,
               "KernelPatch hook arg0 ABI changed");
_Static_assert(offsetof(struct bg_hook_fargs4, arg3) == 112,
               "KernelPatch hook arg3 ABI changed");
_Static_assert(sizeof(struct bg_hook_fargs4) == 120,
               "KernelPatch hook frame ABI changed");

typedef struct bg_hook_fargs4 bg_hook_fargs1_t;
typedef struct bg_hook_fargs4 bg_hook_fargs2_t;
typedef struct bg_hook_fargs4 bg_hook_fargs3_t;
typedef struct bg_hook_fargs4 bg_hook_fargs4_t;

extern int hook_wrap(void *func, int argc, void *before, void *after,
                     void *udata);
extern int compat_copy_to_user(void __user *to, const void *from, int n);

extern unsigned long (*bg_lookup_name)(const char *name)
    __asm__("kallsyms_lookup_name");
extern int (*bg_printk)(const char *fmt, ...) __asm__("printk");

#define bg_log(fmt, ...) bg_printk("[brickguard] " fmt, ##__VA_ARGS__)

extern int bg_mode_value;
extern int bg_admin_busy;
extern int bg_shutting_down;
extern int bg_degraded;
extern int bg_io_active;
extern int bg_mode_transition;
extern void (*bg_iov_iter_advance)(struct iov_iter *iter, size_t bytes);

static inline enum bg_mode bg_mode_get(void)
{
    return (enum bg_mode)__atomic_load_n(&bg_mode_value, __ATOMIC_ACQUIRE);
}

static inline void bg_mode_store(enum bg_mode mode)
{
    __atomic_store_n(&bg_mode_value, (int)mode, __ATOMIC_RELEASE);
}

static inline int bg_shutdown_get(void)
{
    return __atomic_load_n(&bg_shutting_down, __ATOMIC_ACQUIRE);
}

static inline void bg_shutdown_store(int shutting_down)
{
    __atomic_store_n(&bg_shutting_down, shutting_down, __ATOMIC_RELEASE);
}

static inline int bg_admin_try_lock(void)
{
    int expected = 0;
    return __atomic_compare_exchange_n(&bg_admin_busy, &expected, 1, 0,
                                       __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static inline void bg_admin_unlock(void)
{
    __atomic_store_n(&bg_admin_busy, 0, __ATOMIC_RELEASE);
}

int bg_block_init(void);
int bg_block_has_hooks(void);
void bg_block_exit(void);
void bg_mode_switch(enum bg_mode mode);

int bg_blg_init(void);
int bg_blg_begin_shutdown(void);
int bg_blg_exit_locked(void);
const char *bg_blg_status_text(void);

#endif
