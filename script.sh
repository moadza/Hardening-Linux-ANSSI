#!/bin/bash

# Configuration
BOOTLOADER_PATH="/path/to/your_bootloader.efi"
KERNEL_PATH="/path/to/your_kernel.efi"

# Function to display a whiptail message indicating the current hardening step
show_hardening_step() {
    local message="$1"
    whiptail --title "Hardening Script" --msgbox "$message" 8 50
}

# Function to harden the hardware configuration
harden_hardware_configuration() {
    show_hardening_step "Configuration matérielle..."

    # Check if the system supports UEFI
    if [ -d /sys/firmware/efi ]; then
        echo "UEFI is supported on this system."

        # Check if Secure Boot is already enabled
        if mokutil --sb-state 2>/dev/null | grep -iq "SecureBoot enabled"; then
            echo "Secure Boot is already enabled."
        else
            # Enable Secure Boot
            if command -v mokutil &>/dev/null; then
                sudo mokutil --enable-uefi
                echo "Secure Boot has been enabled. You may need to restart the system and enroll keys."
            else
                echo "mokutil command not found. Please install it or enable Secure Boot manually."
            fi
        fi

        # Generate new keys
        openssl req -new -x509 -newkey rsa:2048 -keyout my_uefi_key.key -out my_uefi_cert.crt -days 365 -nodes

        # Enroll the new keys in UEFI
        sudo openssl x509 -outform DER -in my_uefi_cert.crt -out my_uefi_cert.der
        sudo efivar -n EFI/secureboot/my_uefi_cert -t 7 -v $(xxd -p -c 32 my_uefi_cert.der)

        # Find bootloader path
        bootloader_path=$(find /boot/efi/EFI -name "*.efi" | head -n 1)

        if [ -n "$bootloader_path" ]; then
            # Sign the bootloader
            sbsign --key my_uefi_key.key --cert my_uefi_cert.crt --output "$bootloader_path" "$BOOTLOADER_PATH"
            echo "UEFI Keys replaced, bootloader signed: $bootloader_path"
        else
            echo "Error: Bootloader not found. Please specify the bootloader path."
        fi

        # Find kernel path
        kernel_path=$(find /boot/efi/EFI -name "*.efi" | grep -v "$bootloader_path" | head -n 1)

        if [ -n "$kernel_path" ]; then
            # Sign the Linux kernel
            sbsign --key my_uefi_key.key --cert my_uefi_cert.crt --output "$kernel_path" "$KERNEL_PATH"
            echo "Kernel signed: $kernel_path"
        else
            echo "Error: Kernel not found. Please specify the kernel path."
        fi

        # Prompt user to restart the system
        whiptail --title "Restart Required" --yesno "Restart the system to apply changes. Do you want to restart now?" 8 50
        if [ $? -eq 0 ]; then
            sudo reboot
        fi

    else
        echo "UEFI is not supported on this system."
    fi

    echo "Hardware configuration hardened."
}

# Function to harden the Linux kernel configuration
harden_linux_kernel_configuration() {
    show_hardening_step "Configuration du noyau Linux..."
    
    # Configure a password for the bootloader (GRUB 2)
    if command -v grub-mkpasswd-pbkdf2 &>/dev/null; then
        echo "Configuring password for GRUB 2 bootloader..."
        
        # Generate a hashed password for GRUB
        password_hash=$(grub-mkpasswd-pbkdf2)

        # Update the GRUB configuration with the password
        sudo bash -c 'echo "set superusers=\"root\"" > /etc/grub.d/01_users'
        sudo bash -c 'echo "password_pbkdf2 root $password_hash" >> /etc/grub.d/01_users'
        sudo chmod 600 /etc/grub.d/01_users

        # Update GRUB
        sudo update-grub

        echo "GRUB 2 bootloader password configured."
    else
        echo "grub-mkpasswd-pbkdf2 command not found. Do you want to install it? (y/n)"
        read -r install_choice
        if [ "$install_choice" == "y" ]; then
            sudo apt-get update
            sudo apt-get install grub2-common
            echo "grub-mkpasswd-pbkdf2 installed. Please re-run the script."
        else
            echo "Please install grub-mkpasswd-pbkdf2 manually to configure a password for GRUB."
        fi
    fi

    # Protect kernel command-line parameters and initramfs for UEFI Secure Boot
    echo "Protecting kernel command-line parameters and initramfs for UEFI Secure Boot..."
    
    # Create a Unified kernel image
    sudo dracut --uefi --kver "$(uname -r)"

    echo "Kernel command-line parameters and initramfs protected for UEFI Secure Boot."

    # Activate IOMMU
    echo "Activating IOMMU..."
    echo "iommu=force" | sudo tee -a /etc/default/grub
    # Add intel_iommu=on to GRUB_CMDLINE_LINUX_DEFAULT
    sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="/&intel_iommu=on /' /etc/default/grub
    sudo update-grub

    echo "IOMMU activated."

     # Configure memory options
    echo "Configuring memory options..."

    # Add recommended memory options to the kernel command-line parameters
    echo "l1tf=full,force page_poison=on pti=on slab_nomerge=yes slub_debug=FZP spec_store_bypass_disable=seccomp spectre_v2=on mds=full,nosmt mce=0 page_alloc.shuffle=1 rng_core.default_quality=500" | sudo tee -a /etc/default/grub

    # Update GRUB
    sudo update-grub

    echo "Memory options configured."

        # Configure kernel options
    echo "Configuring kernel options..."

    # Add recommended kernel options
    echo "kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.pid_max=65536
kernel.perf_cpu_time_max_percent=1
kernel.perf_event_max_sample_rate=1
kernel.perf_event_paranoid=2
kernel.randomize_va_space=2
kernel.sysrq=0
kernel.unprivileged_bpf_disabled=1
kernel.panic_on_oops=1" | sudo tee -a /etc/sysctl.conf

    # Apply sysctl configurations
    sudo sysctl -p

    echo "Kernel options configured."

        # Disable loading of kernel modules
    echo "Disabling loading of kernel modules..."

    # Add the option to /etc/sysctl.conf
    echo "# Disable loading of kernel modules
kernel.modules_disabled=1" | sudo tee -a /etc/sysctl.conf

    # Apply sysctl configurations
    sudo sysctl -p

    echo "Kernel module loading disabled."

    # Configure Yama LSM for ptrace_scope
    echo "Configuring Yama LSM for ptrace_scope..."

    # Prompt the user to choose a value for ptrace_scope
    while true; do
        echo "Choose a value for kernel.yama.ptrace_scope:"
        echo "0: Allow all processes with the same UID to be debugged"
        echo "1: Allow a non-privileged process to debug its descendants"
        echo "2: Allow only privileged processes to use ptrace"
        echo "3: Disallow all processes from using ptrace"

        read -p "Enter the desired value (0, 1, 2, or 3): " selected_value

        # Check if the user entered a valid value
        if [[ "$selected_value" =~ ^[0-3]$ ]]; then
            # Set kernel.yama.ptrace_scope to the selected value
            echo "# Configure Yama LSM for ptrace_scope
kernel.yama.ptrace_scope=$selected_value" | sudo tee -a /etc/sysctl.conf

            # Apply sysctl configurations
            sudo sysctl -p

            echo "Yama LSM configured for ptrace_scope with the selected value: $selected_value."
            break
        else
            echo "Invalid input. Please enter a valid value (0, 1, 2, or 3)."
        fi
    done   

        # Configure Yama LSM for ptrace_scope
    echo "Configuring Yama LSM for ptrace_scope..."

    # Prompt the user to choose a value for ptrace_scope
    while true; do
        echo "Choose a value for kernel.yama.ptrace_scope:"
        echo "0: Allow all processes with the same UID to be debugged"
        echo "1: Allow a non-privileged process to debug its descendants"
        echo "2: Allow only privileged processes to use ptrace"
        echo "3: Disallow all processes from using ptrace"

        read -p "Enter the desired value (0, 1, 2, or 3): " selected_value

        # Check if the user entered a valid value
        if [[ "$selected_value" =~ ^[0-3]$ ]]; then
            # Set kernel.yama.ptrace_scope to the selected value
            echo "# Configure Yama LSM for ptrace_scope
kernel.yama.ptrace_scope=$selected_value" | sudo tee -a /etc/sysctl.conf

            # Apply sysctl configurations
            sudo sysctl -p

            echo "Yama LSM configured for ptrace_scope with the selected value: $selected_value."
            break
        else
            echo "Invalid input. Please enter a valid value (0, 1, 2, or 3)."
        fi
    done

        # Configure IPv4 network settings
    echo "Configuring IPv4 network settings..."

    cat << EOF >> /etc/sysctl.conf
# IPv4 Network Configuration
net.core.bpf_jit_harden=2
net.ipv4.ip_forward=0
net.ipv4.conf.all.accept_local=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.shared_media=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.arp_filter=1
net.ipv4.conf.all.arp_ignore=2
net.ipv4.conf.all.route_localnet=0
net.ipv4.conf.all.drop_gratuitous_arp=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_local_port_range=32768 65535
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_syncookies=1
EOF

    # Apply the changes
    sysctl -p
    echo "IPv4 network configuration applied."

    # Configure IPv4 network settings
    echo "Configuring IPv4 network settings..."

    cat << EOF >> /etc/sysctl.conf
# IPv4 Network Configuration
net.core.bpf_jit_harden=2
net.ipv4.ip_forward=0
net.ipv4.conf.all.accept_local=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.shared_media=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.arp_filter=1
net.ipv4.conf.all.arp_ignore=2
net.ipv4.conf.all.route_localnet=0
net.ipv4.conf.all.drop_gratuitous_arp=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_local_port_range=32768 65535
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_syncookies=1
EOF

    # Apply the changes
    sysctl -p
    echo "IPv4 network configuration applied."

    # Prompt user for IPv6 usage
    read -p "Do you use IPv6? (y/n): " use_ipv6

    # Configure IPv4 network settings
    echo "Configuring IPv4 network settings..."
    cat << EOF >> /etc/sysctl.conf
# IPv4 Network Configuration
net.core.bpf_jit_harden=2
net.ipv4.ip_forward=0
net.ipv4.conf.all.accept_local=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.shared_media=0
net.ipv4.conf.default.shared_media=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.arp_filter=1
net.ipv4.conf.all.arp_ignore=2
net.ipv4.conf.all.route_localnet=0
net.ipv4.conf.all.drop_gratuitous_arp=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.ip_local_port_range=32768 65535
net.ipv4.tcp_rfc1337=1
net.ipv4.tcp_syncookies=1
EOF

    # Configure IPv6 network settings if not disabled
    if [ "$use_ipv6" == "y" ]; then
        echo "Configuring IPv6 network settings..."
        cat << EOF >> /etc/sysctl.conf
# IPv6 Network Configuration
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.all.disable_ipv6=1
EOF
    else
        echo "IPv6 configuration skipped as per user input."
    fi

    # Apply the changes
    sysctl -p
    echo "Network configuration applied."

 cat << EOF >> /etc/sysctl.conf
# File System Configuration
# Disable core dumps for setuid executables
fs.suid_dumpable = 0
# For kernel version 4.19 and later, restrict opening FIFOS and "regular" files
# in sticky, world-writable directories to the file owner
fs.protected_fifos=2
fs.protected_regular=2
# Restrict symbolic link creation to files owned by the user
fs.protected_symlinks=1
# Restrict hard link creation to files owned by the user
fs.protected_hardlinks=1
EOF

    # Apply the changes
    sysctl -p
    echo "File system configuration applied."



    echo "Linux kernel configuration hardened."
}

# Function to harden the system configuration
harden_system_configuration() {
    show_hardening_step "Configuration système..."

    # Configuration de sudo pour journaliser les commandes réalisées
    echo "Defaults log_input,log_output" | sudo tee -a /etc/sudoers

    # Configuration d'auditd pour journaliser la création de tout nouveau processus
    sudo auditctl -a exit,always -F arch=b64 -S execve,execveat
    sudo auditctl -a exit,always -F arch=b32 -S execve,execveat

        # Enable SELinux
    echo "Enabling SELinux..."
    
    # Install SELinux utilities (if not already installed)
    sudo apt-get install selinux-utils
    
    # Install SELinux policy (policycoreutils) and set it to enforcing mode
    sudo apt-get install policycoreutils
    sudo selinux-activate

    # Edit the sudoers file
    sudo visudo

    # Add or modify the following directives to match the recommendations
    Defaults   noexec
    Defaults   requiretty
    Defaults   use_pty
    Defaults   umask=0077
    Defaults   ignore_dot
    Defaults   env_reset


    echo "System configuration applied."
}
