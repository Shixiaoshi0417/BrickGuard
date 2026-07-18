/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BRICKGUARD_PROTOCOL_H
#define BRICKGUARD_PROTOCOL_H

#define BG_RPC_API_VERSION 1
#define BG_PACK_ID_HEX_SIZE 64
#define BG_BLG_MAP_MAX 64
#define BG_BLG_MAP_NAME 32
#define BG_BLG_CACHE_MAX (256UL * 1024UL * 1024UL)

#define BG_BLG_FLAG_AB     (1u << 0)
#define BG_BLG_FLAG_SHARED (1u << 1)
#define BG_BLG_FLAG_EFISP  (1u << 2)

struct bg_blg_map_entry {
    char name[BG_BLG_MAP_NAME];
    unsigned int flags;
    unsigned int tier;
    unsigned long long cache_offset;
    unsigned long long image_size;
    unsigned long long target_size;
    unsigned int target_major;
    unsigned int target_minor;
};

#endif
