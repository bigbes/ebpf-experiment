/* vim: set filetype=c */

#include "include/vmlinux_part.h"
#include "include/helpers.h"

#include "include/bpf_helpers.h"

struct active_ssl_buf {
    s32 version;
    u32 fd;
    const char *buf;
};

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(key,         sizeof(u64));
    __uint(value,       sizeof(struct active_ssl_buf));
    __uint(max_entries, 1024);
} active_ssl_read_args_map SEC(".maps");

static inline __attribute__((always_inline))
int ssl_read_args_store(u64 tgid, s32 version, u32 fd, const char *buf) {
    struct active_ssl_buf active_ssl_buf_v = {version, fd, buf};

    return bpf_map_update_elem(&active_ssl_read_args_map, &tgid,
                               &active_ssl_buf_v, BPF_ANY);
}

static inline __attribute__((always_inline))
struct active_ssl_buf *ssl_read_args_fetch_and_delete(u64 tgid) {
    struct active_ssl_buf *active_ssl_buf_v = NULL;
    active_ssl_buf_v = bpf_map_lookup_elem(&active_ssl_read_args_map, &tgid);
    if (active_ssl_buf_v == NULL) {
        return NULL;
    }

    bpf_map_delete_elem(&active_ssl_read_args_map, &tgid);
    return active_ssl_buf_v;
}

struct {
    __uint(type,        BPF_MAP_TYPE_HASH);
    __uint(key,         sizeof(u64));
    __uint(value,       sizeof(struct active_ssl_buf));
    __uint(max_entries, 1024);
} active_ssl_write_args_map SEC(".maps");

static inline __attribute__((always_inline))
int ssl_write_args_store(u64 tgid, s32 version, u32 fd, const char *buf) {
    struct active_ssl_buf active_ssl_buf_v = {version, fd, buf};

    return bpf_map_update_elem(&active_ssl_write_args_map, &tgid,
                               &active_ssl_buf_v, BPF_ANY);
}

static inline __attribute__((always_inline))
struct active_ssl_buf *ssl_write_args_fetch_and_delete(u64 tgid) {
    struct active_ssl_buf *active_ssl_buf_v = NULL;
    active_ssl_buf_v = bpf_map_lookup_elem(&active_ssl_write_args_map, &tgid);
    if (active_ssl_buf_v == NULL) {
        return NULL;
    }

    bpf_map_delete_elem(&active_ssl_write_args_map, &tgid);
    return active_ssl_buf_v;
}
