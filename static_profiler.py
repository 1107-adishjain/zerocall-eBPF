import angr
import sys

s_static = set()

def syscall_hook(state):
    # This hook acts as a tripwire. It pauses the simulation right BEFORE a syscall.
    try:
        # Since the simulation actually ran the setup code, RAX is properly filled.
        rax_val = state.solver.eval(state.regs.rax)
        s_static.add(rax_val)
        print(f"    [+] Tripwire triggered! Syscall ID: {rax_val:3} at address {hex(state.addr)}")
    except Exception:
        pass

def extract_s_static(binary_path):
    print(f"[*] ZeroCall-eBPF Static Profiler Initiated")
    print(f"[*] Target Binary: {binary_path}")
    
    project = angr.Project(binary_path, auto_load_libs=False)
    
    # 1. Create a state starting at the very beginning of the program
    state = project.factory.entry_state()
    
    # 2. Plant the tripwire! Hook the exact moment a syscall is attempted
    state.inspect.b('syscall', when=angr.BP_BEFORE, action=syscall_hook)
    
    # 3. Unleash the Simulation Manager to explore all paths mathematically
    simgr = project.factory.simgr(state)
    
    print("[*] Symbolically executing the binary to hunt for hidden syscalls...")
    # Run until there are no more paths left to explore
    simgr.run()
    
    print("\n========================================")
    print(f"[SUCCESS] S_static Profile Extracted")
    print(f"[SUCCESS] Total Unique Syscalls: {len(s_static)}")
    print(f"[SUCCESS] Mathematical Set: {s_static}")
    print("========================================")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 static_profiler.py <path_to_binary>")
        sys.exit(1)
        
    extract_s_static(sys.argv[1])