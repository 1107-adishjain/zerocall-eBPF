#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * ZeroCall-eBPF data plane.
 *
 * A single raw tracepoint on sys_enter performs one O(1) hash-map lookup per
 * system call and acts on a ternary policy:
 *
 *     0 = DENY    unconditional block (SIGKILL), no argument inspection
 *     1 = ALLOW   native execution, fast path
 *     2 = AUDIT   argument inspection (Algorithm 2); may block on arguments
 *
 * A syscall with no map entry is allowed (default-allow). The control plane
 * (main.go) populates syscall_policy_map before attaching this program.
 *
 * Note: a raw tracepoint cannot alter a syscall's return value, so a blocked
 * call is stopped with bpf_send_signal(SIGKILL) on the calling task rather
 * than with -EPERM.
 */

/* All CLONE_NEW* namespace flags, OR-ed together. A container escape via
 * clone()/unshare() sets one or more of these to build a fresh namespace. */
#define CLONE_NS_MASK 0x7E020000UL
/* First 8 bytes of "/bin/sh\0", little-endian. */
#define BIN_SH_LE 0x0068732f6e69622fULL

#define POLICY_DENY  0
#define POLICY_ALLOW 1
#define POLICY_AUDIT 2

/* x86_64 syscall numbers handled by the argument inspector. */
#define SYS_clone   56
#define SYS_execve  59
#define SYS_ptrace  101
#define SYS_mount   165
#define SYS_unshare 272
#define SYS_bpf     321

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, u32);
    __type(value, u32);
} syscall_policy_map SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int zero_trust_enforcer(struct bpf_raw_tracepoint_args *ctx) {
    /* For sys_enter, args[0] is the pt_regs pointer and args[1] is the
     * syscall number. */
    u32 syscall_id = ctx->args[1];
    u32 *action = bpf_map_lookup_elem(&syscall_policy_map, &syscall_id);

    if (!action)
        return 0; /* default-allow: not in policy */

    if (*action == POLICY_DENY) {
        bpf_printk("[BLOCK] Explicitly denied syscall: %d\n", syscall_id);
        bpf_send_signal(9); /* SIGKILL */
        return 0;
    }

    if (*action == POLICY_ALLOW)
        return 0; /* fast path */

    /* POLICY_AUDIT: Algorithm 2 — inspect arguments before deciding. */
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    switch (syscall_id) {
    case SYS_clone: {
        /* arg0 (rdi) = clone flags on x86_64. */
        unsigned long clone_flags = 0;
        bpf_probe_read_kernel(&clone_flags, sizeof(clone_flags), &regs->di);
        if (clone_flags & CLONE_NS_MASK) {
            bpf_printk("[BLOCK] Malicious clone() namespace escape! flags=%lx\n",
                       clone_flags);
            bpf_send_signal(9);
        }
        break;
    }
    case SYS_execve: {
        /* arg0 (rdi) = pointer to the program path. */
        const char *filename_ptr = 0;
        char filename[8] = {};
        bpf_probe_read_kernel(&filename_ptr, sizeof(filename_ptr), &regs->di);
        bpf_probe_read_user_str(&filename, sizeof(filename), filename_ptr);
        if (*(unsigned long long *)filename == BIN_SH_LE) {
            bpf_printk("[BLOCK] Illegal shell execution detected: /bin/sh\n");
            bpf_send_signal(9);
        }
        break;
    }
    case SYS_ptrace:
        bpf_printk("[BLOCK] ptrace() injection attempt!\n");
        bpf_send_signal(9);
        break;
    case SYS_mount:
        bpf_printk("[BLOCK] Illegal mount() execution!\n");
        bpf_send_signal(9);
        break;
    case SYS_unshare: {
        /* arg0 (rdi) = unshare flags; same namespace flags as clone(). */
        unsigned long unshare_flags = 0;
        bpf_probe_read_kernel(&unshare_flags, sizeof(unshare_flags), &regs->di);
        if (unshare_flags & CLONE_NS_MASK) {
            bpf_printk("[BLOCK] unshare() namespace detachment! flags=%lx\n",
                       unshare_flags);
            bpf_send_signal(9);
        }
        break;
    }
    case SYS_bpf:
        bpf_printk("[BLOCK] Nested eBPF injection attempt blocked!\n");
        bpf_send_signal(9);
        break;
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
