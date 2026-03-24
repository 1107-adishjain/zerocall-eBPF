# ZeroCall-eBPF 🛡️

Deterministic, Zero-Trust System Call Profiling and eBPF Enforcement for Container Security. 

This project implements a decoupled Control Plane (Golang) and Data Plane (eBPF/C) architecture to conditionally audit and enforce system call execution based on dynamic profiling and host-aware vulnerability threat feeds, eliminating the need for assumed-safe generic templates.

## Phase 1: Environment & Data Plane Setup

The following steps detail how to provision the eBPF development lab and compile the kernel-space enforcement engine.

### 1. Provision the Lab (Vagrant)
This project uses a Vagrant Ubuntu 22.04 (Kernel 5.15) virtual machine to safely compile and test eBPF programs.

1. Ensure VirtualBox and Vagrant are installed on your host.
2. Run the environment:

   vagrant up
   vagrant ssh
   cd ~/zerocall-ebpf

2. Enable the BPF LSM Framework in GRUBBy default, Ubuntu 22.04 uses AppArmor and may not have the BPF LSM enabled.Edit the GRUB configuration:

sudo nano /etc/default/grub

Modify the GRUB_CMDLINE_LINUX line to append the lsm= parameter:

GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0 lsm=lockdown,capability,landlock,yama,apparmor,bpf"

Update GRUB and reboot:

sudo update-grub
sudo reboot

Verify bpf is active:
cat /sys/kernel/security/lsm

3. Install eBPF Toolchain DependenciesUbuntu requires specific packages tied to your exact kernel version to extract BTF data and compile eBPF programs.
Bash:
sudo apt-get update
sudo apt-get install -y linux-tools-$(uname -r) linux-tools-common

4. Generate Kernel Headers (vmlinux.h)To ensure our eBPF program perfectly maps to the host's memory layout, we extract the BPF Type Format (BTF) data directly from the kernel into a single C header file.
Bash:
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

5. The Data Plane ImplementationCreate zerocall.bpf.c. This is the universal in-kernel enforcement engine. It performs an $O(1)$ lookup in a BPF Hash Map and executes argument-level inspection if a system call is flagged for auditing (Value 2).

6. Compile the eBPF ObjectCompile the C code using Clang with the specific BPF target architecture and level-2 optimization (required by the kernel verifier).Bash: clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c zerocall.bpf.c -o zerocall.bpf.o

7. Initialize the Go Control Plane
The Control Plane acts as the "brain," responsible for loading the compiled eBPF object into the kernel, generating the zero-trust policy, and populating the BPF Hash Map. We use the cilium/ebpf library to manage this.

Initialize the module and download the dependencies:

Bash:
go mod init zerocall
go get github.com/cilium/ebpf

Troubleshooting Note: Go Version Mismatches
During development, you may encounter an error like go: go.mod file indicates go 1.2x, but maximum version supported by tidy is 1.18. This occurs if your host machine uses a newer Go version than the Ubuntu Vagrant VM.
Fix: Explicitly downgrade the version requirement in your go.mod file to match the VM's compiler before running go mod tidy:

1. Bring the Shield Up
Run the Control Plane. Because it manipulates kernel memory, it must be run with sudo.

Bash:
go mod tidy
sudo go run main.go

Note: The terminal will hang, indicating the eBPF engine is actively monitoring system calls in real-time.

10. Simulating a Container Escape Attack
To verify the zero-trust architecture, we simulate an attacker attempting to break out of a container. A common escape vector involves utilizing the clone system call with specific namespace flags (CLONE_NEWNET and CLONE_NEWPID).

Open a second terminal window, SSH into the Vagrant VM, and create exploit.c:

1.  Compile and Execute the Attack
Compile the payload and run it while the Go Control Plane is running in your other terminal:

Bash
gcc exploit.c -o exploit

./exploit

Expected Result: The executable will immediately terminate with a Killed message. The eBPF data plane successfully intercepted the system call, identified the malicious namespace flags in the CPU registers, and issued a SIGKILL (Signal 9) before the kernel could execute the escape.