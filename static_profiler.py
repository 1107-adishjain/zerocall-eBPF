#!/usr/bin/env python3
"""ZeroCall-eBPF Phase 1: static extraction of S_static via symbolic execution.

angr walks the binary from its entry point. A breakpoint fires immediately
before every `syscall` instruction; at that point the concrete value in rax is
the system call number about to be issued, so we record it. The union over all
explored paths is S_static.

The run writes a provenance artifact (JSON) so the syscall count reported in the
paper can be traced back to this script and this binary. See NUMBERS.md.

Usage:
    python3 static_profiler.py <path_to_binary> [-o s_static.json]
"""

import argparse
import datetime
import hashlib
import json
import sys

import angr

s_static = set()


def syscall_hook(state):
    """Tripwire: record rax immediately before a syscall executes."""
    try:
        rax_val = state.solver.eval(state.regs.rax)
        s_static.add(int(rax_val))
        print(f"    [+] Tripwire triggered! Syscall ID: {rax_val:3} "
              f"at address {hex(state.addr)}")
    except Exception:
        pass


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_s_static(binary_path, out_path):
    print("[*] ZeroCall-eBPF Static Profiler Initiated")
    print(f"[*] Target Binary: {binary_path}")
    print(f"[*] SHA-256:       {sha256(binary_path)}")

    project = angr.Project(binary_path, auto_load_libs=False)

    state = project.factory.entry_state()
    state.inspect.b("syscall", when=angr.BP_BEFORE, action=syscall_hook)

    simgr = project.factory.simgr(state)
    print("[*] Symbolically executing the binary to hunt for hidden syscalls...")
    simgr.run()

    ordered = sorted(s_static)
    print("\n========================================")
    print("[SUCCESS] S_static Profile Extracted")
    print(f"[SUCCESS] Total Unique Syscalls: {len(ordered)}")
    print(f"[SUCCESS] Mathematical Set: {{{', '.join(map(str, ordered))}}}")
    print("========================================")

    artifact = {
        "tool": "static_profiler.py",
        "phase": "S_static",
        "binary": binary_path,
        "binary_sha256": sha256(binary_path),
        "auto_load_libs": False,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "count": len(ordered),
        "syscalls": ordered,
    }
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2)
        f.write("\n")
    print(f"[*] Provenance artifact written to: {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Extract S_static via angr.")
    parser.add_argument("binary", help="path to the binary to profile")
    parser.add_argument("-o", "--out", default=None,
                        help="provenance artifact path "
                             "(default: s_static_<binary>.json)")
    args = parser.parse_args()

    out_path = args.out
    if out_path is None:
        base = args.binary.rstrip("/").split("/")[-1]
        out_path = f"s_static_{base}.json"

    extract_s_static(args.binary, out_path)


if __name__ == "__main__":
    main()
