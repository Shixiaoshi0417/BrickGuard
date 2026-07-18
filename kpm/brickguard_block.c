/* SPDX-License-Identifier: GPL-2.0-only */
#include "brickguard_internal.h"

static void *bg_sym_write_iter;
static void *bg_sym_ioctl;
static void *bg_sym_compat_ioctl;
static void *bg_sym_fallocate;
static void *bg_sym_mmap;
static void *bg_sym_uring_cmd;

static int bg_hooked_write_iter;
static int bg_hooked_ioctl;
static int bg_hooked_compat_ioctl;
static int bg_hooked_fallocate;
static int bg_hooked_mmap;
static int bg_hooked_uring_cmd;

void (*bg_iov_iter_advance)(struct iov_iter *iter, size_t bytes);

static enum bg_action bg_enter_action(void)
{
    __atomic_add_fetch(&bg_io_active, 1, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(&bg_mode_transition, __ATOMIC_SEQ_CST))
        return BG_ACTION_DENY;
    return bg_action_for_mode(bg_mode_get());
}

static void bg_after_io(bg_hook_fargs4_t *args, void *udata)
{
    (void)args;
    (void)udata;
    __atomic_sub_fetch(&bg_io_active, 1, __ATOMIC_SEQ_CST);
}

static void bg_before_write_iter(bg_hook_fargs2_t *args, void *udata)
{
    struct kiocb *iocb = (struct kiocb *)args->arg0;
    struct iov_iter *from = (struct iov_iter *)args->arg1;
    enum bg_action action = bg_enter_action();
    size_t count;

    (void)udata;
    if (action == BG_ACTION_PASS || !iocb || !from)
        return;

    count = iov_iter_count(from);
    args->skip_origin = 1;
    if (action == BG_ACTION_DENY) {
        args->ret = (u64)(long)-EPERM;
        return;
    }

    bg_iov_iter_advance(from, count);
    iocb->ki_pos += count;
    args->ret = count;
}

static int bg_dangerous_ioctl(unsigned int cmd)
{
    return cmd == BLKZEROOUT || cmd == BLKDISCARD ||
           cmd == BLKSECDISCARD;
}

static void bg_before_ioctl(bg_hook_fargs3_t *args, void *udata)
{
    unsigned int cmd = (unsigned int)args->arg1;
    enum bg_action action = bg_enter_action();

    (void)udata;
    if (!bg_dangerous_ioctl(cmd))
        return;
    if (action == BG_ACTION_PASS)
        return;

    args->skip_origin = 1;
    args->ret = action == BG_ACTION_DENY ? (u64)(long)-EPERM : 0;
}

static void bg_before_fallocate(bg_hook_fargs4_t *args, void *udata)
{
    enum bg_action action = bg_enter_action();

    (void)udata;
    if (action == BG_ACTION_PASS)
        return;
    args->skip_origin = 1;
    args->ret = action == BG_ACTION_DENY ? (u64)(long)-EPERM : 0;
}

static void bg_before_mmap(bg_hook_fargs2_t *args, void *udata)
{
    struct vm_area_struct *vma = (struct vm_area_struct *)args->arg1;
    enum bg_action action = bg_enter_action();

    (void)udata;
    if (action == BG_ACTION_PASS || !vma ||
        !(vma->vm_flags & VM_SHARED) || !(vma->vm_flags & VM_WRITE))
        return;

    args->skip_origin = 1;
    args->ret = (u64)(long)(action == BG_ACTION_DENY ?
                            -EPERM : -EOPNOTSUPP);
}

static void bg_before_uring_cmd(bg_hook_fargs2_t *args, void *udata)
{
    enum bg_action action = bg_enter_action();

    (void)udata;
    if (action == BG_ACTION_PASS)
        return;
    args->skip_origin = 1;
    args->ret = action == BG_ACTION_DENY ? (u64)(long)-EPERM : 0;
}

static int bg_install_hook(const char *name, void *address, int argc,
                           void *before, int *installed)
{
    int rc;

    rc = hook_wrap(address, argc, before, bg_after_io, NULL);
    if (rc) {
        bg_log("hook failed: %s rc=%d\n", name, rc);
        return rc < 0 ? rc : -rc;
    }
    *installed = 1;
    return 0;
}

static int bg_install_optional_hook(const char *name, int argc, void *before,
                                    void **saved, int *installed)
{
    int rc;

    *saved = (void *)bg_lookup_name(name);
    if (!*saved) {
        bg_log("optional coverage unavailable: %s\n", name);
        return 0;
    }
    rc = bg_install_hook(name, *saved, argc, before, installed);
    if (rc) {
        *saved = NULL;
        bg_log("optional hook unavailable: %s rc=%d\n", name, rc);
    }
    return 0;
}

int bg_block_init(void)
{
    int rc;

    bg_iov_iter_advance = (void *)bg_lookup_name("iov_iter_advance");
    bg_sym_write_iter = (void *)bg_lookup_name("blkdev_write_iter");
    bg_sym_ioctl = (void *)bg_lookup_name("blkdev_ioctl");
    bg_sym_fallocate = (void *)bg_lookup_name("blkdev_fallocate");
    bg_sym_mmap = (void *)bg_lookup_name("blkdev_mmap");
    if (!bg_iov_iter_advance || !bg_sym_write_iter || !bg_sym_ioctl ||
        !bg_sym_fallocate || !bg_sym_mmap) {
        bg_log("required raw-block symbol missing\n");
        return -ENOENT;
    }

    rc = bg_install_hook("blkdev_write_iter", bg_sym_write_iter, 2,
                         bg_before_write_iter, &bg_hooked_write_iter);
    if (rc)
        return rc;
    rc = bg_install_hook("blkdev_ioctl", bg_sym_ioctl, 3,
                         bg_before_ioctl, &bg_hooked_ioctl);
    if (rc)
        return rc;
    rc = bg_install_hook("blkdev_fallocate", bg_sym_fallocate, 4,
                         bg_before_fallocate, &bg_hooked_fallocate);
    if (rc)
        return rc;
    rc = bg_install_hook("blkdev_mmap", bg_sym_mmap, 2,
                         bg_before_mmap, &bg_hooked_mmap);
    if (rc)
        return rc;
    bg_install_optional_hook("compat_blkdev_ioctl", 3, bg_before_ioctl,
                             &bg_sym_compat_ioctl,
                             &bg_hooked_compat_ioctl);
    bg_install_optional_hook("blkdev_uring_cmd", 2, bg_before_uring_cmd,
                             &bg_sym_uring_cmd, &bg_hooked_uring_cmd);
    return 0;
}

int bg_block_has_hooks(void)
{
    return bg_hooked_write_iter || bg_hooked_ioctl ||
           bg_hooked_compat_ioctl || bg_hooked_fallocate ||
           bg_hooked_mmap || bg_hooked_uring_cmd;
}

void bg_mode_switch(enum bg_mode mode)
{
    __atomic_store_n(&bg_mode_transition, 1, __ATOMIC_SEQ_CST);
    while (__atomic_load_n(&bg_io_active, __ATOMIC_SEQ_CST))
        __asm__ __volatile__("yield" ::: "memory");
    bg_mode_store(mode);
    __atomic_store_n(&bg_mode_transition, 0, __ATOMIC_SEQ_CST);
}

void bg_block_exit(void)
{
    if (bg_block_has_hooks()) {
        bg_log("hook teardown refused; reboot is required\n");
        return;
    }
    bg_sym_uring_cmd = NULL;
    bg_sym_compat_ioctl = NULL;
    bg_sym_mmap = NULL;
    bg_sym_fallocate = NULL;
    bg_sym_ioctl = NULL;
    bg_sym_write_iter = NULL;
}
