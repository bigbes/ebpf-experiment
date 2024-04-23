//go:build ignore

#include "include/vmlinux_part.h"
#include "include/helpers.h"

#include "include/bpf_helpers.h"

// structs structure:
// default types and locations:
// - SSL: include/openssl/types.h [typedef struct ssl_st SSL;]
// - SSL_CTX: include/openssl/types.h [typedef struct ssl_ctx_st SSL_CTX;]
//
// - struct ssl_st: include/ssl/ssl_local.h
// - struct ssl_ctx_st: include/ssl/ssl_local.h
// - struct ssl_connection_st: include/ssl/ssl_local.h


#if OPENSSL_VERSION < 0x30200000L
#  define SSL_VERSION_OFFSET 0x00
#  define SSL_RBIO_OFFSET    0x10
#  define SSL_WBIO_OFFSET    0x18
#  define BIO_FD_OFFSET      0x38
#else
#  define SSL_VERSION_OFFSET 0x40
#  define SSL_RBIO_OFFSET    0x48
#  define SSL_WBIO_OFFSET    0x50
#  define BIO_FD_OFFSET      0x38
#endif

struct ssl_st;

static inline __attribute__((always_inline))
int ssl_read_version(void *ssl, u64 *version) {
    u64 *version_ptr = (u64 *)(ssl + SSL_VERSION_OFFSET);
    return bpf_probe_read(version, sizeof(*version), (void *)version_ptr);
}

static inline __attribute__((always_inline))
int ssl_read_rbio_fd(void *ssl, u32 *fd) {
    u64 rbio_ptr = 0;
    int ret = bpf_probe_read(&rbio_ptr, sizeof(rbio_ptr), ssl + SSL_RBIO_OFFSET);
    if (ret != 0) {
        return ret;
    }

    return bpf_probe_read(fd, sizeof(*fd), (void *)(rbio_ptr + BIO_FD_OFFSET));
}

static inline __attribute__((always_inline))
int ssl_read_wbio_fd(void *ssl, u32 *fd) {
    u64 wbio_ptr = 0;
    int ret = bpf_probe_read(&wbio_ptr, sizeof(wbio_ptr), ssl + SSL_WBIO_OFFSET);
    if (ret != 0) {
        return ret;
    }

    return bpf_probe_read(fd, sizeof(*fd), (void *)(wbio_ptr + BIO_FD_OFFSET));
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} ssl_fd_map SEC(".maps");

static inline __attribute__((always_inline))
int store_ssl_fd(u64 ssl, u32 fd) {
    return bpf_map_update_elem(&ssl_fd_map, &ssl, &fd, BPF_ANY);
}

static inline __attribute__((always_inline))
int fetch_ssl_fd(u64 ssl, u32 *fd) {
    u32 *elem = bpf_map_lookup_elem(&ssl_fd_map, &ssl);
    *fd = elem ? *elem : 0;
    return elem ? 0 : -1;
}
