//go:build ignore
#include "include/vmlinux_part.h"
#include "include/helpers.h"

#include "include/bpf_helpers.h"

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(key_size,    sizeof(u32));
    __uint(value_size,  sizeof(u64));
    __uint(max_entries, 8);
} ssl_stats_map SEC(".maps");

static inline __attribute__((always_inline))
int ssl_stats_increment_read(u64 size) {
    u32 key = 0;
    u64 *value = (u64 *)bpf_map_lookup_elem(&ssl_stats_map, &key);
    if (value == NULL) {
        return -1;
    }

    __sync_fetch_and_add(value, 1);

    key++;
    value = (u64 *)bpf_map_lookup_elem(&ssl_stats_map, &key);
    if (value == NULL) {
        return -1;
    }

    __sync_fetch_and_add(value, size);
    return 0;
}

static inline __attribute__((always_inline))
int ssl_stats_increment_write(u64 size) {
    u32 key = 2;
    u64 *value = (u64 *)bpf_map_lookup_elem(&ssl_stats_map, &key);
    if (value == NULL) {
        return -1;
    }

    __sync_fetch_and_add(value, 1);

    key++;
    value = (u64 *)bpf_map_lookup_elem(&ssl_stats_map, &key);
    if (value == NULL) {
        return -1;
    }

    __sync_fetch_and_add(value, size);
    return 0;
}

static inline __attribute__((always_inline))
int ssl_stats_call_uprobe_read() {
    u32 key = 4;
    u64 *value = (u64 *)bpf_map_lookup_elem(&ssl_stats_map, &key);
    if (value == NULL) {
        return -1;
    }

    __sync_fetch_and_add(value, 1);
    return 0;
}

static inline __attribute__((always_inline))
int ssl_stats_call_uretprobe_read() {
    u32 key = 5;
    u64 *value = (u64 *)bpf_map_lookup_elem(&ssl_stats_map, &key);
    if (value == NULL) {
        return -1;
    }

    __sync_fetch_and_add(value, 1);
    return 0;
}

static inline __attribute__((always_inline))
int ssl_stats_call_uprobe_write() {
    u32 key = 6;
    u64 *value = (u64 *)bpf_map_lookup_elem(&ssl_stats_map, &key);
    if (value == NULL) {
        return -1;
    }

    __sync_fetch_and_add(value, 1);
    return 0;
}

static inline __attribute__((always_inline))
int ssl_stats_call_uretprobe_write() {
    u32 key = 7;
    u64 *value = (u64 *)bpf_map_lookup_elem(&ssl_stats_map, &key);
    if (value == NULL) {
        return -1;
    }

    __sync_fetch_and_add(value, 1);
    return 0;
}
