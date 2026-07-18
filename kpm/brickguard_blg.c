/* SPDX-License-Identifier: GPL-2.0-only */
#include "brickguard_internal.h"

#define BG_CONTROL_MAX 256
#define BG_SELFTEST_CHUNK (1024UL * 1024UL)

static struct proc_dir_entry *bg_proc_dir;
static struct proc_dir_entry *bg_proc_control;
static struct proc_dir_entry *bg_proc_cache;

static struct proc_dir_entry *(*bg_proc_mkdir_fn)(
    const char *, struct proc_dir_entry *);
static struct proc_dir_entry *(*bg_proc_create_fn)(
    const char *, umode_t, struct proc_dir_entry *, const struct proc_ops *);
static void (*bg_proc_remove_fn)(struct proc_dir_entry *);

static void *(*bg_vmalloc_fn)(unsigned long size);
static void (*bg_vfree_fn)(const void *address);
static int (*bg_set_memory_ro_fn)(unsigned long address, int pages);
static int (*bg_set_memory_rw_fn)(unsigned long address, int pages);
static void (*bg_sha256_fn)(const unsigned char *data, unsigned int length,
                            unsigned char *digest);
static unsigned long (*bg_copy_from_user_fn)(
    void *to, const void __user *from, unsigned long length);
static struct file *(*bg_filp_open_fn)(
    const char *path, int flags, umode_t mode);
static int (*bg_filp_close_fn)(struct file *file, fl_owner_t id);
static ssize_t (*bg_kernel_write_fn)(
    struct file *file, const void *buffer, size_t length, loff_t *position);
static ssize_t (*bg_kernel_read_fn)(
    struct file *file, void *buffer, size_t length, loff_t *position);
static int (*bg_vfs_fsync_fn)(struct file *file, int datasync);
static struct block_device *(*bg_i_bdev_fn)(struct inode *inode);
static void (*bg_invalidate_bdev_fn)(struct block_device *bdev);

static void *bg_cache;
static unsigned long bg_cache_size;
static unsigned long bg_cache_written;
static int bg_cache_ready;
static int bg_cache_read_only;
static unsigned char bg_cache_digest[32];
static char bg_pack_id[BG_PACK_ID_HEX_SIZE + 1];

static struct bg_blg_map_entry bg_map[BG_BLG_MAP_MAX];
static unsigned int bg_map_count;
static int bg_map_ready;
static unsigned char bg_map_digest[32];

struct bg_control_session {
    char reply[128];
};

static int bg_proc_users;
static char *bg_reply_target;

static int bg_streq_local(const char *left, const char *right)
{
    if (!left || !right)
        return 0;
    while (*left && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

static int bg_prefix_local(const char *text, const char *prefix)
{
    while (*prefix && *text == *prefix) {
        text++;
        prefix++;
    }
    return *prefix == '\0';
}

static int bg_strlen_local(const char *text)
{
    int length = 0;
    while (text && text[length])
        length++;
    return length;
}

static void bg_copy_reply(char *target, const char *text)
{
    int index = 0;

    while (text[index] && index < 127) {
        target[index] = text[index];
        index++;
    }
    target[index] = '\0';
}

static void bg_set_reply(const char *text)
{
    if (bg_reply_target)
        bg_copy_reply(bg_reply_target, text);
}

static void bg_zero_bytes(void *buffer, unsigned long length)
{
    unsigned long index;
    unsigned char *bytes = buffer;

    for (index = 0; index < length; index++)
        bytes[index] = 0;
}

static int bg_digest_equal(const unsigned char *left,
                           const unsigned char *right)
{
    unsigned char difference = 0;
    int index;

    for (index = 0; index < 32; index++)
        difference |= left[index] ^ right[index];
    return difference == 0;
}

static int bg_bytes_equal(const unsigned char *left,
                          const unsigned char *right, size_t length)
{
    size_t index;

    for (index = 0; index < length; index++)
        if (left[index] != right[index])
            return 0;
    return 1;
}

static void bg_clear_map_locked(void)
{
    bg_zero_bytes(bg_map, sizeof(bg_map));
    bg_zero_bytes(bg_map_digest, sizeof(bg_map_digest));
    bg_map_count = 0;
    bg_map_ready = 0;
}

static void bg_clear_cache_digest(void)
{
    bg_zero_bytes(bg_cache_digest, sizeof(bg_cache_digest));
}

static void bg_clear_pack_id(void)
{
    bg_zero_bytes(bg_pack_id, sizeof(bg_pack_id));
}

static int bg_free_cache_locked(void)
{
    int pages;
    int rc;

    if (!bg_cache) {
        bg_cache_size = 0;
        bg_cache_written = 0;
        bg_cache_ready = 0;
        bg_cache_read_only = 0;
        bg_clear_cache_digest();
        bg_clear_pack_id();
        bg_clear_map_locked();
        return 0;
    }
    pages = (int)((bg_cache_size + PAGE_SIZE - 1) / PAGE_SIZE);
    if (bg_cache_read_only) {
        rc = bg_set_memory_rw_fn((unsigned long)bg_cache, pages);
        if (rc)
            return rc;
        bg_cache_read_only = 0;
    }
    bg_vfree_fn(bg_cache);
    bg_cache = NULL;
    bg_cache_size = 0;
    bg_cache_written = 0;
    bg_cache_ready = 0;
    bg_clear_cache_digest();
    bg_clear_pack_id();
    bg_clear_map_locked();
    return 0;
}

static int bg_valid_pack_id(const char *text)
{
    int index;

    if (!text)
        return 0;
    for (index = 0; index < BG_PACK_ID_HEX_SIZE; index++) {
        char value = text[index];

        if (!((value >= '0' && value <= '9') ||
              (value >= 'a' && value <= 'f')))
            return 0;
    }
    return text[BG_PACK_ID_HEX_SIZE] == '\0';
}

static void bg_store_pack_id(const char *text)
{
    int index;

    for (index = 0; index < BG_PACK_ID_HEX_SIZE; index++)
        bg_pack_id[index] = text[index];
    bg_pack_id[BG_PACK_ID_HEX_SIZE] = '\0';
}

static int bg_parse_u64(const char *text, unsigned long long *value)
{
    unsigned long long result = 0;
    unsigned int digit;

    if (!text || !*text)
        return -1;
    while (*text) {
        if (*text < '0' || *text > '9')
            return -1;
        digit = (unsigned int)(*text - '0');
        if (result > (~0ULL - digit) / 10ULL)
            return -1;
        result = result * 10ULL + digit;
        text++;
    }
    *value = result;
    return 0;
}

static char *bg_next_token(char **cursor)
{
    char *start;
    char *text = *cursor;

    while (*text == ' ')
        text++;
    if (!*text) {
        *cursor = text;
        return NULL;
    }
    start = text;
    while (*text && *text != ' ')
        text++;
    if (*text)
        *text++ = '\0';
    *cursor = text;
    return start;
}

static int bg_parse_map_entry(char *text, struct bg_blg_map_entry *entry)
{
    unsigned long long values[7];
    char *name;
    char *token;
    int count = 0;
    int length = 0;

    bg_zero_bytes(entry, sizeof(*entry));
    name = bg_next_token(&text);
    if (!name || !*name)
        return -1;
    while (name[length])
        length++;
    if (length >= BG_BLG_MAP_NAME)
        return -1;
    for (count = 0; count < length; count++) {
        char value = name[count];

        if (!((value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') || value == '_'))
            return -1;
    }
    for (count = 0; count <= length; count++)
        entry->name[count] = name[count];

    count = 0;
    while (count < 7 && (token = bg_next_token(&text)) != NULL) {
        if (bg_parse_u64(token, &values[count]))
            return -1;
        count++;
    }
    if (count != 7 || bg_next_token(&text))
        return -1;
    if (values[2] > 0xfffULL || values[3] > 0xfffffULL ||
        values[5] > 0xffffffffULL || values[6] > 0xffffffffULL)
        return -1;
    if (values[5] & ~(unsigned long long)(BG_BLG_FLAG_AB |
                                          BG_BLG_FLAG_SHARED |
                                          BG_BLG_FLAG_EFISP))
        return -1;

    entry->cache_offset = values[0];
    entry->image_size = values[1];
    entry->target_major = (unsigned int)values[2];
    entry->target_minor = (unsigned int)values[3];
    entry->target_size = values[4];
    entry->flags = (unsigned int)values[5];
    entry->tier = (unsigned int)values[6];
    if (!!(entry->flags & BG_BLG_FLAG_AB) ==
        !!(entry->flags & BG_BLG_FLAG_SHARED))
        return -1;
    if (entry->flags & BG_BLG_FLAG_EFISP) {
        if (!(entry->flags & BG_BLG_FLAG_SHARED) ||
            !(bg_streq_local(entry->name, "efisp") ||
              bg_streq_local(entry->name, "efisp_a") ||
              bg_streq_local(entry->name, "efisp_b")))
            return -1;
    } else if (bg_streq_local(entry->name, "efisp") ||
               bg_streq_local(entry->name, "efisp_a") ||
               bg_streq_local(entry->name, "efisp_b")) {
        return -1;
    }
    if (entry->tier > 2)
        return -1;
    return 0;
}

static int bg_validate_map_locked(void)
{
    unsigned int index;
    unsigned int previous;
    unsigned long long end;
    unsigned long long total = 0;

    if (!bg_cache || !bg_cache_ready || !bg_cache_read_only ||
        !bg_map_count)
        return -1;
    for (index = 0; index < bg_map_count; index++) {
        struct bg_blg_map_entry *entry = &bg_map[index];

        if (!entry->name[0] || !entry->image_size ||
            !entry->target_major || entry->image_size > entry->target_size)
            return -1;
        end = entry->cache_offset + entry->image_size;
        if (end < entry->cache_offset || end > bg_cache_size)
            return -1;
        if (entry->image_size > BG_BLG_CACHE_MAX - total)
            return -1;
        total += entry->image_size;
        for (previous = 0; previous < index; previous++)
            if (entry->target_major == bg_map[previous].target_major &&
                entry->target_minor == bg_map[previous].target_minor)
                return -1;
    }
    return 0;
}

static unsigned long long bg_map_total_locked(void)
{
    unsigned long long total = 0;
    unsigned int index;

    for (index = 0; index < bg_map_count; index++)
        total += bg_map[index].image_size;
    return total;
}

static void bg_append_text(char *output, int *length, const char *text)
{
    while (*text && *length < 127)
        output[(*length)++] = *text++;
    output[*length] = '\0';
}

static void bg_append_u64(char *output, int *length,
                          unsigned long long value)
{
    char reverse[24];
    int used = 0;

    do {
        reverse[used++] = (char)('0' + value % 10ULL);
        value /= 10ULL;
    } while (value && used < (int)sizeof(reverse));
    while (used && *length < 127)
        output[(*length)++] = reverse[--used];
    output[*length] = '\0';
}

static void bg_reply_pack_id(void)
{
    char reply[128];
    int length = 0;

    reply[0] = '\0';
    if (!bg_cache || !bg_cache_ready || !bg_pack_id[0]) {
        bg_set_reply("ERR PACK EMPTY");
        return;
    }
    bg_append_text(reply, &length, "OK PACK ");
    bg_append_text(reply, &length, bg_pack_id);
    bg_set_reply(reply);
}

static void bg_reply_map_info(void)
{
    char reply[128];
    int length = 0;

    reply[0] = '\0';
    if (!bg_map_ready || !bg_pack_id[0]) {
        bg_set_reply("ERR MAP NOT READY");
        return;
    }
    bg_append_text(reply, &length, "OK MAP ");
    bg_append_u64(reply, &length, bg_map_count);
    bg_append_text(reply, &length, " ");
    bg_append_u64(reply, &length, bg_map_total_locked());
    bg_append_text(reply, &length, " ");
    bg_append_text(reply, &length, bg_pack_id);
    bg_set_reply(reply);
}

static int bg_loop_backing_valid(const char *path,
                                 unsigned long long required_size)
{
    static const char sysfs_prefix[] = "/sys/block/loop";
    static const char backing_prefix[] =
        "/data/local/tmp/brickguard-blg.";
    const char *digits;
    char sysfs_path[96];
    char backing_path[160];
    struct file *sysfs_file;
    struct file *backing_file;
    struct inode *backing_inode;
    loff_t position = 0;
    ssize_t received;
    int output = 0;
    int index;
    int suffix_length = 0;

    if (bg_prefix_local(path, "/dev/block/loop"))
        digits = path + 15;
    else if (bg_prefix_local(path, "/dev/loop"))
        digits = path + 9;
    else
        return 0;
    if (!*digits)
        return 0;
    for (index = 0; digits[index]; index++) {
        if (digits[index] < '0' || digits[index] > '9' || index >= 5)
            return 0;
    }

    for (index = 0; sysfs_prefix[index]; index++)
        sysfs_path[output++] = sysfs_prefix[index];
    for (index = 0; digits[index]; index++)
        sysfs_path[output++] = digits[index];
    for (index = 0; "/loop/backing_file"[index]; index++)
        sysfs_path[output++] = "/loop/backing_file"[index];
    sysfs_path[output] = '\0';

    sysfs_file = bg_filp_open_fn(sysfs_path, O_RDONLY, 0);
    if (!sysfs_file || IS_ERR(sysfs_file))
        return 0;
    received = bg_kernel_read_fn(sysfs_file, backing_path,
                                 sizeof(backing_path) - 1, &position);
    bg_filp_close_fn(sysfs_file, NULL);
    if (received <= 0 || received >= (ssize_t)sizeof(backing_path))
        return 0;
    backing_path[received] = '\0';
    while (received && (backing_path[received - 1] == '\n' ||
                        backing_path[received - 1] == '\r'))
        backing_path[--received] = '\0';
    if (!bg_prefix_local(backing_path, backing_prefix))
        return 0;
    for (index = sizeof(backing_prefix) - 1; backing_path[index]; index++) {
        char value = backing_path[index];

        if (!((value >= 'a' && value <= 'z') ||
              (value >= 'A' && value <= 'Z') ||
              (value >= '0' && value <= '9')))
            return 0;
        suffix_length++;
    }
    if (suffix_length != 6)
        return 0;

    backing_file = bg_filp_open_fn(backing_path, O_RDWR | O_LARGEFILE, 0);
    if (!backing_file || IS_ERR(backing_file))
        return 0;
    backing_inode = file_inode(backing_file);
    output = backing_inode && S_ISREG(backing_inode->i_mode) &&
             (unsigned long long)i_size_read(backing_inode) >= required_size;
    bg_filp_close_fn(backing_file, NULL);
    return output;
}

static int bg_loop_selftest_locked(const char *path, int inject)
{
    struct file *file;
    struct inode *inode;
    struct inode *capacity_inode;
    struct block_device *bdev;
    unsigned char *verify = NULL;
    unsigned long long total = 0;
    unsigned long long output_offset = 0;
    loff_t position;
    unsigned int index;
    ssize_t io;
    int rc = -EIO;
    int repaired = 0;

    if (bg_mode_get() != BG_MODE_OFF)
        return -EBUSY;
    if (!bg_cache_ready || !bg_cache_read_only || !bg_map_ready)
        return -EINVAL;
    if (!path || path[0] != '/')
        return -EINVAL;

    file = bg_filp_open_fn(path, O_RDWR | O_LARGEFILE, 0);
    if (!file || IS_ERR(file))
        return -ENOENT;
    inode = file_inode(file);
    capacity_inode = file->f_mapping ? file->f_mapping->host : NULL;
    if (!inode || !capacity_inode || !S_ISBLK(inode->i_mode) ||
        MAJOR(inode->i_rdev) != 7) {
        rc = -EPERM;
        goto out;
    }
    bdev = bg_i_bdev_fn(capacity_inode);
    if (!bdev) {
        rc = -ENODEV;
        goto out;
    }

    for (index = 0; index < bg_map_count; index++) {
        if (total > ~0ULL - bg_map[index].image_size) {
            rc = -EOVERFLOW;
            goto out;
        }
        total += bg_map[index].image_size;
    }
    if (!total || total > (unsigned long long)i_size_read(capacity_inode)) {
        rc = -EFBIG;
        goto out;
    }
    if (!bg_loop_backing_valid(path, total)) {
        rc = -EPERM;
        goto out;
    }

    verify = bg_vmalloc_fn(BG_SELFTEST_CHUNK);
    if (!verify) {
        rc = -ENOMEM;
        goto out;
    }

    for (index = 0; index < bg_map_count; index++) {
        unsigned long long left = bg_map[index].image_size;
        unsigned long long source = bg_map[index].cache_offset;

        while (left) {
            size_t chunk = left > BG_SELFTEST_CHUNK ?
                           BG_SELFTEST_CHUNK : (size_t)left;
            position = (loff_t)output_offset;
            io = bg_kernel_write_fn(file, (char *)bg_cache + source,
                                    chunk, &position);
            if (io != (ssize_t)chunk) {
                rc = -EIO;
                goto out;
            }
            source += chunk;
            output_offset += chunk;
            left -= chunk;
        }
    }
    rc = bg_vfs_fsync_fn(file, 0);
    if (rc)
        goto out;
    bg_invalidate_bdev_fn(bdev);

    if (inject && total >= 4096) {
        position = (loff_t)((total / 2) & ~4095ULL);
        io = bg_kernel_read_fn(file, verify, 4096, &position);
        if (io != 4096) {
            rc = -EIO;
            goto out;
        }
        verify[0] ^= 0xff;
        position = (loff_t)((total / 2) & ~4095ULL);
        io = bg_kernel_write_fn(file, verify, 4096, &position);
        if (io != 4096) {
            rc = -EIO;
            goto out;
        }
        rc = bg_vfs_fsync_fn(file, 0);
        if (rc)
            goto out;
        bg_invalidate_bdev_fn(bdev);
    }

    output_offset = 0;
    for (index = 0; index < bg_map_count; index++) {
        unsigned long long left = bg_map[index].image_size;
        unsigned long long source = bg_map[index].cache_offset;

        while (left) {
            size_t chunk = left > BG_SELFTEST_CHUNK ?
                           BG_SELFTEST_CHUNK : (size_t)left;
            position = (loff_t)output_offset;
            io = bg_kernel_read_fn(file, verify, chunk, &position);
            if (io != (ssize_t)chunk) {
                rc = -EIO;
                goto out;
            }
            if (!bg_bytes_equal(verify,
                                (unsigned char *)bg_cache + source, chunk)) {
                position = (loff_t)output_offset;
                io = bg_kernel_write_fn(file, (char *)bg_cache + source,
                                        chunk, &position);
                if (io != (ssize_t)chunk) {
                    rc = -EIO;
                    goto out;
                }
                repaired++;
            }
            source += chunk;
            output_offset += chunk;
            left -= chunk;
        }
    }
    if (repaired) {
        rc = bg_vfs_fsync_fn(file, 0);
        if (rc)
            goto out;
        bg_invalidate_bdev_fn(bdev);
    }

    output_offset = 0;
    for (index = 0; index < bg_map_count; index++) {
        unsigned long long left = bg_map[index].image_size;
        unsigned long long source = bg_map[index].cache_offset;

        while (left) {
            size_t chunk = left > BG_SELFTEST_CHUNK ?
                           BG_SELFTEST_CHUNK : (size_t)left;
            position = (loff_t)output_offset;
            io = bg_kernel_read_fn(file, verify, chunk, &position);
            if (io != (ssize_t)chunk ||
                !bg_bytes_equal(verify,
                                (unsigned char *)bg_cache + source, chunk)) {
                rc = -EIO;
                goto out;
            }
            source += chunk;
            output_offset += chunk;
            left -= chunk;
        }
    }
    rc = repaired ? 1 : 0;

out:
    if (verify)
        bg_vfree_fn(verify);
    bg_filp_close_fn(file, NULL);
    return rc;
}

static int bg_proc_user_enter(void)
{
    if (bg_shutdown_get())
        return -EBUSY;
    __atomic_add_fetch(&bg_proc_users, 1, __ATOMIC_ACQ_REL);
    if (bg_shutdown_get()) {
        __atomic_sub_fetch(&bg_proc_users, 1, __ATOMIC_RELEASE);
        return -EBUSY;
    }
    return 0;
}

static void bg_proc_user_exit(void)
{
    __atomic_sub_fetch(&bg_proc_users, 1, __ATOMIC_RELEASE);
}

static int bg_control_open(struct inode *inode, struct file *file)
{
    struct bg_control_session *session;
    int rc;

    (void)inode;
    rc = bg_proc_user_enter();
    if (rc)
        return rc;
    session = bg_vmalloc_fn(sizeof(*session));
    if (!session) {
        bg_proc_user_exit();
        return -ENOMEM;
    }
    bg_zero_bytes(session, sizeof(*session));
    bg_copy_reply(session->reply, "ERR NO COMMAND");
    file->private_data = session;
    return 0;
}

static int bg_control_release(struct inode *inode, struct file *file)
{
    (void)inode;
    if (file->private_data)
        bg_vfree_fn(file->private_data);
    file->private_data = NULL;
    bg_proc_user_exit();
    return 0;
}

static int bg_cache_open(struct inode *inode, struct file *file)
{
    (void)inode;
    (void)file;
    return bg_proc_user_enter();
}

static int bg_cache_release(struct inode *inode, struct file *file)
{
    (void)inode;
    (void)file;
    bg_proc_user_exit();
    return 0;
}

static ssize_t bg_control_read(struct file *file, char __user *buffer,
                               size_t count, loff_t *position)
{
    struct bg_control_session *session = file->private_data;
    int length;
    int copied;

    if (!session)
        return -EINVAL;
    if (!count)
        return 0;
    if (bg_shutdown_get() || !bg_admin_try_lock())
        return -EBUSY;
    length = bg_strlen_local(session->reply);
    if (*position >= length) {
        bg_admin_unlock();
        return 0;
    }
    if (count > (size_t)(length - *position))
        count = length - *position;
    copied = compat_copy_to_user(buffer, session->reply + *position,
                                 count);
    if (copied <= 0) {
        bg_admin_unlock();
        return -EFAULT;
    }
    *position += copied;
    bg_admin_unlock();
    return copied;
}

static int bg_mutation_allowed(void)
{
    return !bg_shutdown_get() && bg_mode_get() == BG_MODE_OFF;
}

static ssize_t bg_control_write(struct file *file, const char __user *buffer,
                                size_t count, loff_t *position)
{
    struct bg_control_session *session = file->private_data;
    char command[BG_CONTROL_MAX];
    size_t original_count = count;

    if (!session || !count || count >= sizeof(command))
        return -EINVAL;
    if (bg_shutdown_get() || !bg_admin_try_lock())
        return -EBUSY;
    if (bg_copy_from_user_fn(command, buffer, count)) {
        bg_admin_unlock();
        return -EFAULT;
    }
    command[count] = '\0';
    while (count && (command[count - 1] == '\n' ||
                     command[count - 1] == '\r'))
        command[--count] = '\0';
    bg_reply_target = session->reply;
    *position = 0;

    if (bg_streq_local(command, "HELLO 1")) {
        bg_set_reply("OK HELLO 1 " BG_VERSION);
    } else if (bg_streq_local(command, "MODE STATUS")) {
        enum bg_mode mode = bg_mode_get();

        if (mode == BG_MODE_OFF)
            bg_set_reply("MODE 0 OFF");
        else if (mode == BG_MODE_DENY)
            bg_set_reply("MODE 1 DENY");
        else if (mode == BG_MODE_SIMULATE)
            bg_set_reply("MODE 2 SIMULATE");
        else
            bg_set_reply("MODE INVALID");
    } else if (bg_streq_local(command, "STATUS")) {
        bg_set_reply(bg_blg_status_text());
    } else if (bg_streq_local(command, "BLG PACK ID")) {
        bg_reply_pack_id();
    } else if (bg_prefix_local(command, "BLG CACHE BEGIN ")) {
        unsigned long long requested;
        char *cursor = command + 16;
        char *size_text = bg_next_token(&cursor);
        char *pack_id = bg_next_token(&cursor);
        int rc;

        if (!bg_mutation_allowed()) {
            bg_set_reply("ERR MODE LOCKED");
        } else if (!size_text || !pack_id || bg_next_token(&cursor) ||
                   bg_parse_u64(size_text, &requested) ||
                   !bg_valid_pack_id(pack_id) ||
                   !requested || requested > BG_BLG_CACHE_MAX ||
                   requested > (unsigned long long)~0UL) {
            bg_set_reply("ERR CACHE SIZE");
        } else {
            rc = bg_free_cache_locked();
            if (rc) {
                bg_set_reply("ERR CACHE UNLOCK");
            } else {
                bg_cache = bg_vmalloc_fn((unsigned long)requested);
                if (!bg_cache) {
                    bg_set_reply("ERR CACHE MEMORY");
                } else {
                    bg_cache_size = (unsigned long)requested;
                    bg_cache_written = 0;
                    bg_cache_ready = 0;
                    bg_cache_read_only = 0;
                    bg_clear_cache_digest();
                    bg_store_pack_id(pack_id);
                    bg_clear_map_locked();
                    bg_set_reply("OK CACHE BEGIN");
                }
            }
        }
    } else if (bg_streq_local(command, "BLG CACHE COMMIT")) {
        int pages;
        int rc;

        if (!bg_mutation_allowed()) {
            bg_set_reply("ERR MODE LOCKED");
        } else if (!bg_cache || bg_cache_written != bg_cache_size) {
            bg_set_reply("ERR CACHE INCOMPLETE");
        } else {
            bg_sha256_fn(bg_cache, (unsigned int)bg_cache_size,
                         bg_cache_digest);
            pages = (int)((bg_cache_size + PAGE_SIZE - 1) / PAGE_SIZE);
            rc = bg_set_memory_ro_fn((unsigned long)bg_cache, pages);
            if (rc) {
                bg_clear_cache_digest();
                bg_set_reply("ERR CACHE RO");
            } else {
                bg_cache_read_only = 1;
                bg_cache_ready = 1;
                bg_set_reply("OK CACHE READY RO");
            }
        }
    } else if (bg_streq_local(command, "BLG CACHE VERIFY")) {
        unsigned char digest[32];

        if (!bg_cache || !bg_cache_ready || !bg_cache_read_only) {
            bg_set_reply("ERR CACHE NOT READY");
        } else {
            bg_sha256_fn(bg_cache, (unsigned int)bg_cache_size, digest);
            bg_set_reply(bg_digest_equal(digest, bg_cache_digest) ?
                         "OK CACHE INTACT" : "ERR CACHE CORRUPTED");
        }
    } else if (bg_streq_local(command, "BLG CACHE STATUS")) {
        if (bg_cache_ready)
            bg_set_reply(bg_cache_read_only ?
                         "OK CACHE READY RO" : "ERR CACHE RW");
        else
            bg_set_reply(bg_cache ? "OK CACHE LOADING" : "OK CACHE EMPTY");
    } else if (bg_streq_local(command, "BLG CACHE DROP")) {
        if (!bg_mutation_allowed()) {
            bg_set_reply("ERR MODE LOCKED");
        } else if (bg_free_cache_locked()) {
            bg_set_reply("ERR CACHE UNLOCK");
        } else {
            bg_set_reply("OK CACHE EMPTY");
        }
    } else if (bg_streq_local(command, "BLG MAP BEGIN")) {
        if (!bg_mutation_allowed()) {
            bg_set_reply("ERR MODE LOCKED");
        } else if (!bg_cache_ready || !bg_cache_read_only) {
            bg_set_reply("ERR CACHE NOT READY");
        } else {
            bg_clear_map_locked();
            bg_set_reply("OK MAP BEGIN");
        }
    } else if (bg_prefix_local(command, "BLG MAP ADD ")) {
        if (!bg_mutation_allowed()) {
            bg_set_reply("ERR MODE LOCKED");
        } else if (bg_map_ready || bg_map_count >= BG_BLG_MAP_MAX ||
                   bg_parse_map_entry(command + 12,
                                      &bg_map[bg_map_count])) {
            bg_set_reply("ERR MAP ENTRY");
        } else {
            bg_map_count++;
            bg_set_reply("OK MAP ADD");
        }
    } else if (bg_streq_local(command, "BLG MAP COMMIT")) {
        if (!bg_mutation_allowed()) {
            bg_set_reply("ERR MODE LOCKED");
        } else if (bg_validate_map_locked()) {
            bg_set_reply("ERR MAP INVALID");
        } else {
            bg_sha256_fn((unsigned char *)bg_map,
                         bg_map_count * sizeof(bg_map[0]), bg_map_digest);
            bg_map_ready = 1;
            bg_set_reply("OK PLAN READY NO WRITE");
        }
    } else if (bg_streq_local(command, "BLG MAP VERIFY")) {
        unsigned char digest[32];

        if (!bg_map_ready) {
            bg_set_reply("ERR MAP NOT READY");
        } else {
            bg_sha256_fn((unsigned char *)bg_map,
                         bg_map_count * sizeof(bg_map[0]), digest);
            bg_set_reply(bg_digest_equal(digest, bg_map_digest) ?
                         "OK MAP INTACT" : "ERR MAP CORRUPTED");
        }
    } else if (bg_streq_local(command, "BLG MAP STATUS")) {
        if (bg_map_ready)
            bg_set_reply("OK PLAN READY NO WRITE");
        else
            bg_set_reply(bg_map_count ? "OK MAP BUILDING" : "OK MAP EMPTY");
    } else if (bg_streq_local(command, "BLG MAP INFO")) {
        bg_reply_map_info();
    } else if (bg_streq_local(command, "BLG MAP DROP")) {
        if (!bg_mutation_allowed()) {
            bg_set_reply("ERR MODE LOCKED");
        } else {
            bg_clear_map_locked();
            bg_set_reply("OK MAP EMPTY");
        }
    } else if (bg_prefix_local(command, "BLG SELFTEST ")) {
        char *path = command + 13;
        char *space = path;
        int inject = 0;
        int rc;

        if (!bg_mutation_allowed()) {
            bg_set_reply("ERR MODE LOCKED");
        } else {
            while (*space && *space != ' ')
                space++;
            if (*space) {
                *space++ = '\0';
                if (!bg_streq_local(space, "INJECT")) {
                    bg_set_reply("ERR SELFTEST ARG");
                    goto out;
                }
                inject = 1;
            }
            rc = bg_loop_selftest_locked(path, inject);
            if (rc < 0)
                bg_set_reply("ERR SELFTEST");
            else
                bg_set_reply(rc ? "OK SELFTEST REPAIRED" :
                             "OK SELFTEST VERIFIED");
        }
    } else {
        bg_set_reply("ERR COMMAND");
    }

out:
    bg_reply_target = NULL;
    bg_admin_unlock();
    return original_count;
}

static ssize_t bg_cache_write(struct file *file, const char __user *buffer,
                              size_t count, loff_t *position)
{
    unsigned long offset;

    (void)file;
    if (!count)
        return 0;
    if (!bg_admin_try_lock())
        return -EBUSY;
    if (!bg_mutation_allowed()) {
        bg_admin_unlock();
        return -EPERM;
    }
    if (!bg_cache || bg_cache_ready || *position < 0) {
        bg_admin_unlock();
        return -EINVAL;
    }
    offset = (unsigned long)*position;
    if (offset != bg_cache_written ||
        offset > bg_cache_size || count > bg_cache_size - offset) {
        bg_admin_unlock();
        return -ESPIPE;
    }
    if (bg_copy_from_user_fn((char *)bg_cache + offset, buffer, count)) {
        bg_admin_unlock();
        return -EFAULT;
    }
    bg_cache_written += count;
    *position += count;
    bg_admin_unlock();
    return count;
}

static ssize_t bg_cache_read(struct file *file, char __user *buffer,
                             size_t count, loff_t *position)
{
    unsigned long offset;
    unsigned long left;
    int copied;

    (void)file;
    if (!count)
        return 0;
    if (!bg_admin_try_lock())
        return -EBUSY;
    if (!bg_mutation_allowed()) {
        bg_admin_unlock();
        return -EPERM;
    }
    if (!bg_cache || !bg_cache_ready || *position < 0) {
        bg_admin_unlock();
        return -EINVAL;
    }
    offset = (unsigned long)*position;
    if (offset >= bg_cache_size) {
        bg_admin_unlock();
        return 0;
    }
    left = bg_cache_size - offset;
    if (count > left)
        count = left;
    copied = compat_copy_to_user(buffer, (char *)bg_cache + offset, count);
    if (copied <= 0) {
        bg_admin_unlock();
        return -EFAULT;
    }
    *position += copied;
    bg_admin_unlock();
    return copied;
}

static const struct proc_ops bg_control_ops = {
    .proc_open = bg_control_open,
    .proc_read = bg_control_read,
    .proc_write = bg_control_write,
    .proc_release = bg_control_release,
};

static const struct proc_ops bg_cache_ops = {
    .proc_open = bg_cache_open,
    .proc_read = bg_cache_read,
    .proc_write = bg_cache_write,
    .proc_release = bg_cache_release,
};

const char *bg_blg_status_text(void)
{
    if (bg_degraded)
        return "BLG DEGRADED REBOOT REQUIRED";
    if (bg_cache_ready && bg_cache_read_only && bg_map_ready)
        return "BLG READY NO REAL WRITE";
    if (bg_cache_ready && bg_cache_read_only)
        return "BLG CACHE READY MAP EMPTY";
    if (bg_cache)
        return "BLG CACHE LOADING";
    return "BLG EMPTY";
}

static int bg_resolve_helpers(void)
{
    bg_vmalloc_fn = (void *)bg_lookup_name("vmalloc_noprof");
    if (!bg_vmalloc_fn)
        bg_vmalloc_fn = (void *)bg_lookup_name("vmalloc");
    bg_vfree_fn = (void *)bg_lookup_name("vfree");
    bg_set_memory_ro_fn = (void *)bg_lookup_name("set_memory_ro");
    bg_set_memory_rw_fn = (void *)bg_lookup_name("set_memory_rw");
    bg_sha256_fn = (void *)bg_lookup_name("sha256");
    bg_copy_from_user_fn = (void *)bg_lookup_name("_copy_from_user");
    if (!bg_copy_from_user_fn)
        bg_copy_from_user_fn = (void *)bg_lookup_name("raw_copy_from_user");
    bg_filp_open_fn = (void *)bg_lookup_name("filp_open");
    bg_filp_close_fn = (void *)bg_lookup_name("filp_close");
    bg_kernel_write_fn = (void *)bg_lookup_name("kernel_write");
    bg_kernel_read_fn = (void *)bg_lookup_name("kernel_read");
    bg_vfs_fsync_fn = (void *)bg_lookup_name("vfs_fsync");
    bg_i_bdev_fn = (void *)bg_lookup_name("I_BDEV");
    bg_invalidate_bdev_fn = (void *)bg_lookup_name("invalidate_bdev");
    bg_proc_mkdir_fn = (void *)bg_lookup_name("proc_mkdir");
    bg_proc_create_fn = (void *)bg_lookup_name("proc_create");
    bg_proc_remove_fn = (void *)bg_lookup_name("proc_remove");

    if (!bg_vmalloc_fn || !bg_vfree_fn || !bg_set_memory_ro_fn ||
        !bg_set_memory_rw_fn || !bg_sha256_fn || !bg_copy_from_user_fn ||
        !bg_filp_open_fn || !bg_filp_close_fn || !bg_kernel_write_fn ||
        !bg_kernel_read_fn || !bg_vfs_fsync_fn || !bg_i_bdev_fn ||
        !bg_invalidate_bdev_fn || !bg_proc_mkdir_fn ||
        !bg_proc_create_fn || !bg_proc_remove_fn)
        return -ENOENT;
    return 0;
}

int bg_blg_init(void)
{
    int rc;

    bg_cache = NULL;
    bg_cache_size = 0;
    bg_cache_written = 0;
    bg_cache_ready = 0;
    bg_cache_read_only = 0;
    __atomic_store_n(&bg_proc_users, 0, __ATOMIC_RELAXED);
    bg_clear_cache_digest();
    bg_clear_pack_id();
    bg_clear_map_locked();
    bg_reply_target = NULL;

    rc = bg_resolve_helpers();
    if (rc) {
        bg_log("required BLG helper missing\n");
        return rc;
    }

    bg_proc_dir = bg_proc_mkdir_fn("brickguard", NULL);
    if (!bg_proc_dir)
        return -ENOMEM;
    bg_proc_control = bg_proc_create_fn("control", 0600, bg_proc_dir,
                                        &bg_control_ops);
    bg_proc_cache = bg_proc_create_fn("cache", 0600, bg_proc_dir,
                                      &bg_cache_ops);
    if (!bg_proc_control || !bg_proc_cache) {
        if (bg_proc_cache)
            bg_proc_remove_fn(bg_proc_cache);
        if (bg_proc_control)
            bg_proc_remove_fn(bg_proc_control);
        bg_proc_remove_fn(bg_proc_dir);
        bg_proc_cache = NULL;
        bg_proc_control = NULL;
        bg_proc_dir = NULL;
        return -ENOMEM;
    }
    return 0;
}

int bg_blg_begin_shutdown(void)
{
    if (!bg_admin_try_lock())
        return -EBUSY;
    bg_shutdown_store(1);
    if (__atomic_load_n(&bg_proc_users, __ATOMIC_ACQUIRE)) {
        bg_shutdown_store(0);
        bg_admin_unlock();
        return -EBUSY;
    }
    return 0;
}

int bg_blg_exit_locked(void)
{
    int rc;

    rc = bg_free_cache_locked();
    if (rc) {
        bg_log("cache release failed rc=%d; unload refused\n", rc);
        return rc;
    }

    if (bg_proc_cache)
        bg_proc_remove_fn(bg_proc_cache);
    if (bg_proc_control)
        bg_proc_remove_fn(bg_proc_control);
    if (bg_proc_dir)
        bg_proc_remove_fn(bg_proc_dir);
    bg_proc_cache = NULL;
    bg_proc_control = NULL;
    bg_proc_dir = NULL;
    return 0;
}
