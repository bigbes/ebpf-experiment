//go:build ignore
#define DEBUG_PRINT

#include "include/vmlinux_part.h"
#include "include/helpers.h"

#include "include/bpf_helpers.h"
#include "include/bpf_tracing.h"

#include "openssl-store.c"
#include "openssl-args.c"

char _license[] SEC("license") = "Dual BSD/GPL";

#define MAX_BLOCK_SIZE  10 * 1024
#define MAX_BLOCK_COUNT 4

const volatile u32 target_pid = 0;

int int_ceil(u64 l, u64 r) {
    return (l + r - 1) / r;
}

struct event {
    u8     op;
    pid_t  pid;

    u64 skipped_bytes;

    u64 event_id;
    s8  block_count;
    u8  block_total;

    u16      byte_size; // u16 is enough, MAX_BLOCK_SIZE << 65536
    const u8 bytes[MAX_BLOCK_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct event));
    __uint(max_entries, 1);
} event_allocator SEC(".maps");

const struct event *unused __attribute__((unused));

static u64 event_count = 0;

inline __attribute__((always_inline)) int common_send_block(struct pt_regs *ctx, struct event *event, u8 block_no, void *block_pos, size_t block_size) {
    if (block_size > MAX_BLOCK_SIZE) {
        block_size = MAX_BLOCK_SIZE;
    }

    event->block_count = block_no;
    event->byte_size = block_size;
    bpf_probe_read_user((void *)&event->bytes, block_size, (const void *)block_pos);

    long rv = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event));
    debug_bpf_printk("common_send_block [block_no: %d, block_size: %d, rv: %d]", block_no, block_size, rv);

    return 0;
}

inline __attribute__((always_inline)) int block_count(struct pt_regs *ctx, size_t total_size) {
    int block_count = int_ceil(total_size, MAX_BLOCK_SIZE);
    if (block_count > MAX_BLOCK_COUNT) {
        block_count = -1;
    }
    return block_count;
}


inline __attribute__((always_inline)) int common_send_block_multi(struct pt_regs *ctx, struct event *event, void *position, size_t total_size) {
    if (total_size > 0) {
        debug_bpf_printk("common_send_block_multi [part 1]");
        common_send_block(ctx, event, 0, (void *)PT_REGS_PARM2(ctx), total_size);
    }

    if (total_size > MAX_BLOCK_SIZE) {
        debug_bpf_printk("common_send_block_multi [part 2]");
        common_send_block(ctx, event, 1, (void *)PT_REGS_PARM2(ctx) + MAX_BLOCK_SIZE, total_size - MAX_BLOCK_SIZE);
    }

    if (total_size > 2 * MAX_BLOCK_SIZE) {
        debug_bpf_printk("common_send_block_multi [part 3]");
        common_send_block(ctx, event, 2, (void *)PT_REGS_PARM2(ctx) + 2 * MAX_BLOCK_SIZE, total_size - 2 * MAX_BLOCK_SIZE);
    }

    if (total_size > 3 * MAX_BLOCK_SIZE) {
        debug_bpf_printk("common_send_block_multi [part 4]");
        common_send_block(ctx, event, 3, (void *)PT_REGS_PARM2(ctx) + 3 * MAX_BLOCK_SIZE, total_size - 3 * MAX_BLOCK_SIZE);
    }

    return 0;
}

SEC("uprobe/SSL_read")
int uprobe_ssl_read(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }

    debug_bpf_printk("uprobe/ssl_read [pid: %d]", pid);



    if (ssl_read_args_store(pid_tgid, 0, 0, (const char *)PT_REGS_PARM2(ctx)) != 0) {
        debug_bpf_printk("uprobe/ssl_read [pid: %d]: failed to store args", pid);
    }

    return 0;
}

/* int SSL_read(SSL *ssl, void *buf, int num); */
SEC("uretprobe/SSL_read")
int uretprobe_ssl_read(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (target_pid != 0 && target_pid != pid) {
        return 0;
    }

    /* debug_bpf_printk("uprobe/ssl_read [pid: %d]", pid); */

    int ret = (int )PT_REGS_RC(ctx);
    if (ret < 0) {
        debug_bpf_printk("uprobe/ssl_read [ret: %d]: skipping", ret);
        return 0;
    }

    u32 key = 0;
    struct event *event = bpf_map_lookup_elem(&event_allocator, &key);
    if (event == NULL) {
        debug_bpf_printk("uprobe/ssl_read [pid: %d]: event is NULL", pid);
        return 0;
    }

    event->op = 1;
    event->pid = (pid_t )pid;
    event->event_id = event_count++;
    event->block_count = 0;
    event->block_total = block_count(ctx, ret);
    event->byte_size = 0;


    if (ret > 4 * MAX_BLOCK_SIZE) {
        debug_bpf_printk("uprobe/ssl_read [size: %d]: skipping", ret);

        event->skipped_bytes = ret;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event));
    } else {
        debug_bpf_printk("uprobe/ssl_read [size: %d]: sending", ret);

        common_send_block_multi(ctx, event, (void *)PT_REGS_PARM2(ctx), ret);
    }

    return 0;
}

/* int SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes); */

/*SEC("uretprobe/SSL_read_ex")*/
/*int uretprobe_ssl_read_ex(struct pt_regs *ctx)*/
/*{*/
    /*u64 pid_tgid = bpf_get_current_pid_tgid();*/
    /*u32 pid = pid_tgid >> 32;*/

    /*debug_bpf_printk("uprobe/ssl_read_ex[pid: %d]", pid);*/

    /*size_t *ret = (size_t *)PT_REGS_PARM3(ctx);*/
    /*if (ret == NULL) {*/
        /*return 0;*/
    /*}*/

    /*size_t read_size;*/
    /*bpf_probe_read_str((void *)&read_size, sizeof(size_t), ret);*/

    /*struct event event = {*/
        /*.op    = 2,*/
        /*.pid   = (pid_t )pid,*/

        /*.event_id    = event_count++,*/
        /*.block_count = 0,*/
        /*.block_total = block_count(ctx, read_size),*/

        /*.byte_size = 0,*/
        /*.bytes     = {0},*/
    /*};*/

    /*if (read_size > 4 * MAX_BLOCK_SIZE) {*/
        /*debug_bpf_printk("uprobe/ssl_read[size: %d]: skipping", read_size);*/

        /*event.skipped_bytes = read_size;*/
        /*bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));*/
    /*} else {*/
        /*debug_bpf_printk("uprobe/ssl_read[size: %d]: sending", read_size);*/

        /*common_send_block_multi(ctx, event, (void *)PT_REGS_PARM2(ctx), read_size);*/
    /*}*/

    /*return 0;*/
/*}*/

SEC("uretprobe/SSL_write")
int uretprobe_ssl_write(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    debug_bpf_printk("uprobe/ssl_write[pid: %d]", pid);

    int ret = (int )PT_REGS_RC(ctx);
    if (ret < 0) {
        return 0;
    }

    u32 key = 0;
    struct event *event = bpf_map_lookup_elem(&event_allocator, &key);
    if (event == NULL) {
        debug_bpf_printk("uprobe/ssl_read [pid: %d]: event is NULL", pid);
        return 0;
    }

    event->op = 2;
    event->pid = (pid_t )pid;
    event->event_id = event_count++;
    event->block_count = 0;
    event->block_total = block_count(ctx, ret);
    event->byte_size = 0;


    if (ret > 4 * MAX_BLOCK_SIZE) {
        debug_bpf_printk("uprobe/ssl_read [size: %d]: skipping", ret);

        event->skipped_bytes = ret;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(struct event));
    } else {
        debug_bpf_printk("uprobe/ssl_read [size: %d]: sending", ret);

        common_send_block_multi(ctx, event, (void *)PT_REGS_PARM2(ctx), ret);
    }

    return 0;
}
//
//SEC("uretprobe/SSL_write_ex")
//int uretprobe_ssl_write_ex(struct pt_regs *ctx)
//{
//    u64 pid_tgid = bpf_get_current_pid_tgid();
//    u32 pid = pid_tgid >> 32;
//
//    debug_bpf_printk("uprobe/ssl_write_ex[pid: %d]", pid);
//
//    size_t *ret = (size_t *)PT_REGS_PARM4(ctx);
//    if (ret == NULL) {
//        return 0;
//    }
//
//    size_t read_size;
//    bpf_probe_read_str((void *)&read_size, sizeof(size_t), ret);
//
//    struct event event = {
//        .op    = 4,
//        .pid   = (pid_t )pid,
//
//        .event_id    = event_count++,
//        .block_count = 0,
//        .block_total = block_count(ctx, read_size),
//
//        .byte_size = 0,
//        .bytes     = {0},
//    };
//
//    if (read_size > 4 * MAX_BLOCK_SIZE) {
//        debug_bpf_printk("uprobe/ssl_read[size: %d]: skipping", read_size);
//
//        event.skipped_bytes = read_size;
//        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
//    } else {
//        debug_bpf_printk("uprobe/ssl_read[size: %d]: sending", read_size);
//
//        common_send_block_multi(ctx, event, (void *)PT_REGS_PARM2(ctx), read_size);
//    }
//
//    return 0;
//}
//
//SEC("uretprobe/SSL_write_ex2")
//int uretprobe_ssl_write_ex2(struct pt_regs *ctx)
//{
//    u64 pid_tgid = bpf_get_current_pid_tgid();
//    u32 pid = pid_tgid >> 32;
//
//    debug_bpf_printk("uprobe/ssl_write_ex2[pid: %d]", pid);
//
//    size_t *ret = (size_t *)PT_REGS_PARM5(ctx);
//    if (ret == NULL) {
//        return 0;
//    }
//
//    size_t read_size;
//    bpf_probe_read_str((void *)&read_size, sizeof(size_t), ret);
//
//    struct event event = {
//        .op    = 5,
//        .pid   = (pid_t )pid,
//
//        .event_id    = event_count++,
//        .block_count = 0,
//        .block_total = block_count(ctx, read_size),
//
//        .byte_size = 0,
//        .bytes     = {0},
//    };
//
//    if (read_size > 4 * MAX_BLOCK_SIZE) {
//        debug_bpf_printk("uprobe/ssl_read[size: %d]: skipping", read_size);
//
//        event.skipped_bytes = read_size;
//        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
//    } else {
//        debug_bpf_printk("uprobe/ssl_read[size: %d]: sending", read_size);
//
//        common_send_block_multi(ctx, event, (void *)PT_REGS_PARM2(ctx), read_size);
//    }
//
//    return 0;
//}
