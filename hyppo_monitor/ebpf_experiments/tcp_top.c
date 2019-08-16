#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct ipv4_key_t {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv4_send_bytes, struct ipv4_key_t, u64);
BPF_HASH(ipv4_recv_bytes, struct ipv4_key_t, u64);

struct ipv6_key_t {
    u32 pid;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv6_send_bytes, struct ipv6_key_t);
BPF_HASH(ipv6_recv_bytes, struct ipv6_key_t);




int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t size) {
    u32 pid = bpf_get_current_pid_tgid();
    FILTER
    u16 dport = 0, family = sk->__sk_common.skc_family;

    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        ipv4_send_bytes.increment(ipv4_key, 1);

    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        __builtin_memcpy(&ipv6_key.saddr,
            sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32, sizeof(ipv6_key.saddr));
        __builtin_memcpy(&ipv6_key.daddr,
            sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32, sizeof(ipv6_key.daddr));
        ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv6_key.dport = ntohs(dport);
        ipv6_send_bytes.increment(ipv6_key, 1);
    }
    // else drop

    return 0;
}

/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied) {
    u32 pid = bpf_get_current_pid_tgid();
    FILTER
    u16 dport = 0, family = sk->__sk_common.skc_family;
    u64 *val, zero = 0;

    if (copied <= 0)
        return 0;

    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        ipv4_recv_bytes.increment(ipv4_key, 1);

    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        __builtin_memcpy(&ipv6_key.saddr,
            sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32, sizeof(ipv6_key.saddr));
        __builtin_memcpy(&ipv6_key.daddr,
            sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32, sizeof(ipv6_key.daddr));
        ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv6_key.dport = ntohs(dport);
        ipv6_recv_bytes.increment(ipv6_key, 1);
    }
    // else drop

    return 0;
}
