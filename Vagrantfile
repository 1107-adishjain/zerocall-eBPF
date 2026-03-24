# Vagrantfile
Vagrant.configure("2") do |config|
  # 1. OS: Ubuntu 22.04 (Kernel 5.15+ for eBPF)
  config.vm.box = "bento/ubuntu-22.04"

  # 2. Hardware Resources
  config.vm.provider "virtualbox" do |vb|
    vb.memory = "4096" # 4GB RAM is recommended for compiling Kernel code
    vb.cpus = 2
  end

  # 3. Network: Private IP to test from Windows -> Linux
  config.vm.network "private_network", ip: "192.168.56.11"

  # 4. SYNCED FOLDER (The Magic Part)
  # Maps your Windows "current directory" (.) to "/home/vagrant/zerocall-ebpf" in Linux
  config.vm.synced_folder ".", "/home/vagrant/zerocall-ebpf"

  # 5. SETUP SCRIPT (Installs everything automatically)
  config.vm.provision "shell", inline: <<-SHELL
    export DEBIAN_FRONTEND=noninteractive

    echo "--- [1/4] Updating System ---"
    apt-get update

    echo "--- [2/4] Installing eBPF Build Tools (Clang, LLVM, Libbpf) ---"
    apt-get install -y clang llvm libbpf-dev make gcc build-essential git gcc-multilib

    echo "--- [3/4] Installing Go (Latest) ---"
    apt-get install -y golang-go

    echo "--- [4/4] Installing Docker (For Containers) ---"
    apt-get install -y docker.io
    systemctl start docker
    systemctl enable docker
    usermod -aG docker vagrant

    echo "--- SETUP COMPLETE: You are ready to rock! ---"
    echo "--- Your code is at: /home/vagrant/zerocall-ebpf ---"
  SHELL
end

