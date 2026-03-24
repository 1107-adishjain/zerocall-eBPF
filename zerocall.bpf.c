#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 1. Define the eBPF Hash Map (Our Policy Bridge)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512); // Enough for all Linux syscalls
    __type(key, u32);         // Syscall ID
    __type(value, u32);       // Action: 0=DENY, 1=ALLOW, 2=AUDIT
} syscall_policy_map SEC(".maps");

// 2. The eBPF Hook (Attaching to every system call entry)
SEC("raw_tracepoint/sys_enter")
int zero_trust_enforcer(struct bpf_raw_tracepoint_args *ctx) {
    // In a raw_tracepoint for sys_enter, ctx->args[1] holds the syscall ID
    u32 syscall_id = ctx->args[1]; 
    
    // Look up the syscall ID in our map
    u32 *action = bpf_map_lookup_elem(&syscall_policy_map, &syscall_id);

    // ----------------------------------------------------
    // ENFORCEMENT LOGIC
    // ----------------------------------------------------

    // If the syscall isn't in our map, let it pass so our VM doesn't crash!
    if (!action) {
        return 0; 
    }

    if (*action == 0) {
        // EXPLICIT DENY
        bpf_printk("[SECURITY BLOCK] Denied syscall: %d\n", syscall_id);
        bpf_send_signal(9); // 9 is SIGKILL
        return 0;
    } 
    else if (*action == 1) {
        // EXPLICIT ALLOW
        return 0; 
    } 
    else if (*action == 2) {
        // AUDIT: Dangerous but necessary
        if (syscall_id == 56) { // 56 is the ID for 'clone' on x86_64
            // ctx->args[0] points to the CPU registers where the arguments are stored
            struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
            unsigned long clone_flags;
            
            // Read the first argument (flags) from the 'di' register safely
            bpf_probe_read_kernel(&clone_flags, sizeof(clone_flags), &regs->di);

            // Check for namespace container escape flags
            if ((clone_flags & 0x10000000) || (clone_flags & 0x20000000)) {
                bpf_printk("[SECURITY BLOCK] Malicious clone() detected! Flags: %lx\n", clone_flags);
                bpf_send_signal(9); 
                return 0;
            }
            bpf_printk("[AUDIT PASS] Normal clone() allowed.\n");
            return 0;
        }
    }
    
    // Catch-all return to satisfy the compiler for all other control paths
    return 0;
}

// Required license for kernel loading
char _license[] SEC("license") = "GPL";