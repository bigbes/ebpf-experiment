//go:build ignore
#include "include/vmlinux_part.h"
#include "include/helpers.h"

#include "include/bpf_helpers.h"

struct {
    __uint(type,       BPF_MAP_TYPE_HASH);
    __uint(key_size,   sizeof(pid_t));
    __uint(value_size, sizeof(bool));
    __uint(max_entries, 1024); 
} ssl_pid_enabled_map SEC(".maps");

static inline __attribute__((always_inline))
bool ssl_pid_enabled(pid_t pid) {
#if defined(SSL_PID_CHECK_ENABLED)
    bool *enabled = bpf_map_lookup_elem(&ssl_pid_enabled_map, &pid);
    return enabled != NULL && *enabled > 0;
#elif defined(SSL_PID_CHECK_FALSE)
    return false;
#else
    return true;
#endif
}

