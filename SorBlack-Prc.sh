#!/bin/bash
#sorblack free world

clear

# Green, Yellow & Red Messages.
green_msg() {
    tput setaf 2
    echo "[*] ----- $1"
    tput sgr0
}

yellow_msg() {
    tput setaf 3
    echo "[*] ----- $1"
    tput sgr0
}

red_msg() {
    tput setaf 1
    echo "[*] ----- $1"
    tput sgr0
}

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

# Intro
echo
green_msg '================================================================='
green_msg 'This script will automatically Install All Custom VPN and Optimize your Linux Server.'
green_msg 'Wireguard + Tunnel, Openvpn + Tunnel, X-ui + Tunnel, SSH Panel + Tls, Cisco Anyconnect + Tunnel'
green_msg 'Tested And Works on: Ubuntu 20+ Other OS will work soon ...'
green_msg 'Root access is required.'
green_msg 'Source is @ '
green_msg '================================================================='
echo

# Paths
HOST_PATH="/etc/hosts"
PRF_PATH="/etc/profile"
DNS_PATH="/etc/resolv.conf"
SYS_PATH="/etc/sysctl.conf"
SSH_PORT=""
SSH_PATH="/etc/ssh/sshd_config"
IPBAN_INSTALL="/opt/ipban_install.flag"
RULES_FILE="rules.txt"
#public_ip=$(curl ifconfig.me -4)

# Check root
# [[ $EUID -ne 0 ]] && echo -e "${red}Fatal error: ${plain} Please run this script with root privilege \n " && exit 1
check_if_running_as_root() {
    # If you want to run as another user, please modify $EUID to be owned by this user
    if [[ "$EUID" -ne '0' ]]; then
        echo
        red_msg 'Error: You must run this script as root!'
        echo
        sleep 0.5
        exit 1
    fi
}

check_if_running_as_root
sleep 0.5

# Check OS
check_os() {
    # Check OS and set release variable
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        release=$ID
    elif [[ -f /usr/lib/os-release ]]; then
        source /usr/lib/os-release
        release=$ID
    else
        echo "Failed to check the system OS, please contact the author!" >&2
        exit 1
    fi

    #echo "The OS release is: $release"

    # Function to determine CPU architecture
    arch() {
        case "$(uname -m)" in
        x86_64 | amd64) echo 'amd64' ;;
        armv8 | arm64 | aarch64) echo 'arm64' ;;
        armv7 | arm | armhf) echo 'armhf' ;;
        *)
            echo "Unsupported CPU architecture!" >&2
            exit 1
            ;;
        esac
    }

    architecture=$(arch)
    #echo "arch: $architecture"

    # Extract OS version
    os_version=$(grep -i version_id /etc/os-release | cut -d '"' -f2 | cut -d '.' -f1)

    # Check OS version compatibility
    check_version() {
        local os=$1
        local required_version=$2
        if [[ $os_version < $required_version ]]; then
            echo "Please use $os $required_version or higher."
            exit 1
        fi
    }

    # Compare current OS version with minimum required version
    case "$release" in
    centos) check_version CentOS 8 ;;
    ubuntu) check_version Ubuntu 20 ;;
    fedora) check_version Fedora 36 ;;
    debian) check_version Debian 10 ;;
    almalinux) check_version AlmaLinux 9 ;;
    arch) echo "Your OS is Arch Linux." ;;
    manjaro) echo "Your OS is Manjaro." ;;
    armbian) echo "Your OS is Armbian." ;;
    *) echo "Failed to check the OS version, please contact the author!" && exit 1 ;;
    esac
}

# Run Check OS
check_os

# Function to find the SSH port and set it in the SSH_PORT variable
find_ssh_port() {
    echo
    yellow_msg "Finding SSH port..."
    echo

    ## Check if the SSH configuration file exists
    if [ -e "$SSH_PATH" ]; then
        ## Use grep to search for the 'Port' directive in the SSH configuration file
        SSH_PORT=$(grep -oP '^Port\s+\K\d+' "$SSH_PATH" 2>/dev/null)

        if [ -n "$SSH_PORT" ]; then
            echo
            green_msg "SSH port found: $SSH_PORT"
            echo
            sleep 0.5
        else
            echo
            green_msg "SSH port is default 22."
            echo
            SSH_PORT=22
            sleep 0.5
        fi
    else
        red_msg "SSH configuration file not found at $SSH_PATH"
    fi
}

# Show port of this server
find_ssh_port
sleep 0.5

# Main
echo -n "Enter the Port number of this server (optional): "
read my_port

echo -n "Enter the IR tunnel Domain --or-- Ip address (If you had): "
read ip_address

# resolv="#resolv optimized by sorblack plz dont change it !
# nameserver 8.8.8.8
# nameserver 1.1.1.1
# "

# echo "${resolv}" | sudo tee /etc/resolv.conf > /dev/null

# Install dependencies
install_dependencies_debian_based() {
    echo
    yellow_msg 'Installing Dependencies...'
    echo
    sleep 0.5

    sudo apt -q update
    sudo apt -y upgrade
    sudo apt -y autoremove

    sleep 1

    sudo apt -y -q autoclean
    sudo apt -y clean
    sudo apt -q update
    sudo apt -y upgrade
    sudo apt install -y wget curl sudo jq
    ## Networking packages
    sudo apt -y install apt-transport-https iptables iptables-persistent nftables
    ## System utilities
    sudo apt -y install apt-utils bash-completion busybox ca-certificates cron curl gnupg2 locales lsb-release nano preload screen software-properties-common ufw unzip vim wget xxd zip
    ## Programming and development tools
    sudo apt -y install autoconf automake bash-completion build-essential git libtool make pkg-config python3 python3-pip
    ## Additional libraries and dependencies
    sudo apt -y install bc binutils binutils-common binutils-x86-64-linux-gnu ubuntu-keyring haveged libsodium-dev libsqlite3-dev libssl-dev packagekit qrencode socat
    ## Miscellaneous
    sudo apt -y install dialog htop net-tools

    #update and optimize system
    sync
    echo 1 >/proc/sys/vm/drop_caches
    sync
    echo 2 >/proc/sys/vm/drop_caches
    sync
    echo 3 >/proc/sys/vm/drop_caches

    echo
    green_msg 'Dependencies Installed.'
    echo
    sleep 0.5
}

# Install dependencies
install_dependencies_rhel_based() {
    echo
    yellow_msg 'Installing Dependencies...'
    echo
    sleep 0.5

    # dnf up -y
    dnf install -y wget curl sudo jq iptables-persistent
    echo
    #update and optimize system
    sync
    echo 1 >/proc/sys/vm/drop_caches
    sync
    echo 2 >/proc/sys/vm/drop_caches
    sync
    echo 3 >/proc/sys/vm/drop_caches

    echo
    green_msg 'Dependencies Installed.'
    echo
    sleep 0.5
}

# OS Detection
if [[ $(grep -oP '(?<=^NAME=").*(?=")' /etc/os-release) == "Ubuntu" ]]; then
    OS="ubuntu"
    echo
    sleep 0.5
    yellow_msg "OS: Ubuntu"
    echo
    sleep 0.5
elif [[ $(grep -oP '(?<=^NAME=").*(?=")' /etc/os-release) == "Debian GNU/Linux" ]]; then
    OS="debian"
    echo
    sleep 0.5
    yellow_msg "OS: Debian"
    echo
    sleep 0.5
elif [[ $(grep -oP '(?<=^NAME=").*(?=")' /etc/os-release) == "CentOS Stream" ]]; then
    OS="centos"
    echo
    sleep 0.5
    yellow_msg "OS: Centos Stream"
    echo
    sleep 0.5
elif [[ $(grep -oP '(?<=^NAME=").*(?=")' /etc/os-release) == "AlmaLinux" ]]; then
    OS="almalinux"
    echo
    sleep 0.5
    yellow_msg "OS: AlmaLinux"
    echo
    sleep 0.5
elif [[ $(grep -oP '(?<=^NAME=").*(?=")' /etc/os-release) == "Fedora Linux" ]]; then
    OS="fedora"
    echo
    sleep 0.5
    yellow_msg "OS: Fedora"
    echo
    sleep 0.5
else
    echo
    sleep 0.5
    red_msg "Unknown OS, Please Contact Us :)"
    OS="unknown"
    echo
    sleep 2
fi

# Install dependencies on Ubuntu & Debian
if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    if ! grep -q "nameserver 8.8.8.8" /etc/resolv.conf || ! grep -q "nameserver 1.1.1.1" /etc/resolv.conf; then
        echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
        echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf
        yellow_msg "Added nameserver 8.8.8.8 and nameserver 1.1.1.1 to /etc/resolv.conf !!!"
    else
        yellow_msg "nameserver 8.8.8.8 and nameserver 1.1.1.1 already exist in /etc/resolv.conf !!!"
    fi
    install_dependencies_debian_based
# Install dependencies for Centos-based systems
elif [[ "$OS" == "centos" || "$OS" == "fedora" || "$OS" == "almalinux" ]]; then
    if ! grep -q "nameserver 8.8.8.8" /etc/resolv.conf || ! grep -q "nameserver 1.1.1.1" /etc/resolv.conf; then
        echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
        echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf
        yellow_msg "Added nameserver 8.8.8.8 and nameserver 1.1.1.1 to /etc/resolv.conf !!!"
    else
        yellow_msg "nameserver 8.8.8.8 and nameserver 1.1.1.1 already exist in /etc/resolv.conf !!!"
    fi
    install_dependencies_rhel_based
fi

# Fix Hosts file
fix_hosts() {
    echo
    yellow_msg "Fixing Hosts file."
    sleep 0.5

    cp $HOST_PATH /etc/hosts.bak
    yellow_msg "Default hosts file saved. Directory: /etc/hosts.bak"
    sleep 0.5

    if ! grep -q $(hostname) $HOST_PATH; then
        echo "127.0.1.1 $(hostname)" | sudo tee -a $HOST_PATH >/dev/null
        green_msg "Hosts Fixed."
        echo
        sleep 0.5
    else
        green_msg "Hosts OK. No changes made."
        echo
        sleep 0.5
    fi
}

# Set timezone base on VPS
set_timezone() {
    echo
    yellow_msg 'Setting TimeZone based on VPS IP address...'
    sleep 0.5

    get_location_info() {
        local ip_sources=("https://ipv4.icanhazip.com" "https://api.ipify.org" "https://ipv4.ident.me/")
        local location_info

        for source in "${ip_sources[@]}"; do
            local ip=$(curl -s "$source")
            if [ -n "$ip" ]; then
                location_info=$(curl -s "http://ip-api.com/json/$ip")
                if [ -n "$location_info" ]; then
                    echo "$location_info"
                    return 0
                fi
            fi
        done

        red_msg "Error: Failed to fetch location information from known sources. Setting timezone to UTC."
        sudo timedatectl set-timezone "UTC"
        return 1
    }

    # Fetch location information from three sources
    location_info_1=$(get_location_info)
    location_info_2=$(get_location_info)
    location_info_3=$(get_location_info)

    # Extract timezones from the location information
    timezones=($(echo "$location_info_1 $location_info_2 $location_info_3" | jq -r '.timezone'))

    # Check if at least two timezones are equal
    if [[ "${timezones[0]}" == "${timezones[1]}" || "${timezones[0]}" == "${timezones[2]}" || "${timezones[1]}" == "${timezones[2]}" ]]; then
        # Set the timezone based on the first matching pair
        timezone="${timezones[0]}"
        sudo timedatectl set-timezone "$timezone"
        green_msg "Timezone set to $timezone"
    else
        red_msg "Error: Failed to fetch consistent location information from known sources. Setting timezone to UTC."
        sudo timedatectl set-timezone "UTC"
    fi

    echo
    sleep 0.5
}

# Remove old SSH config to prevent duplicates.
rm_ssh_config() {
    ## Create a backup of the Original sshd_config file
    cp $SSH_PATH /etc/ssh/sshd_config.bak

    echo
    yellow_msg 'Default SSH Config file Saved. Directory: /etc/ssh/sshd_config.bak'
    echo
    sleep 1

    ## Remove these lines
    sed -i '/#UseDNS yes/d' "$SSH_PATH"
    sed -i '/#Compression no/d' "$SSH_PATH"
    sed -i '/Ciphers aes256-ctr,chacha20-poly1305@openssh.com/d' "$SSH_PATH"
    sed -i 's/Ciphers .*/Ciphers aes256-ctr,chacha20-poly1305@openssh.com/' "$SSH_PATH"
    sed -i '/MaxAuthTries/d' "$SSH_PATH"
    sed -i '/MaxSessions/d' "$SSH_PATH"
    sed -i '/TCPKeepAlive/d' "$SSH_PATH"
    sed -i '/ClientAliveInterval/d' "$SSH_PATH"
    sed -i '/ClientAliveCountMax/d' "$SSH_PATH"
    sed -i '/AllowAgentForwarding/d' "$SSH_PATH"
    sed -i '/AllowTcpForwarding/d' "$SSH_PATH"
    sed -i '/GatewayPorts/d' "$SSH_PATH"
    sed -i '/PermitTunnel/d' "$SSH_PATH"
    sed -i '/X11Forwarding/d' "$SSH_PATH"
}

# Update SSH config
update_ssh_config() {
    echo
    yellow_msg 'Optimizing SSH...'
    echo
    sleep 0.5

    # Check if the user has entered a port number
    if [ -n "$my_port" ]; then
        #Delete Default SSH Port
        sed -i '/Port/d' "$SSH_PATH"
        ## Change SSH default Port
        echo "Port" ${my_port} | tee -a "$SSH_PATH"
        ## Restart the SSH service to apply the changes
        sudo systemctl restart ssh
        sudo systemctl restart sshd
        sudo systemctl restart sshd.service
        echo
        green_msg 'SSH Port was Changed.'
        echo
        sleep 0.5
    else
        echo
        green_msg 'No port number entered. SSH port will not be changed.'
        echo
        sleep 0.5
    fi

    ## Set SSH Encrypt algorithm
    echo "Ciphers aes256-ctr,chacha20-poly1305@openssh.com" | tee -a "$SSH_PATH"

    ## Enable TCP keep-alive messages
    echo "TCPKeepAlive yes" | tee -a "$SSH_PATH"

    ## Configure client keep-alive messages
    echo "ClientAliveInterval 3000" | tee -a "$SSH_PATH"
    echo "ClientAliveCountMax 100" | tee -a "$SSH_PATH"

    ## Allow agent forwarding
    echo "AllowAgentForwarding yes" | tee -a "$SSH_PATH"

    ## Allow TCP forwarding
    echo "AllowTcpForwarding yes" | tee -a "$SSH_PATH"

    ## Enable gateway ports
    echo "GatewayPorts yes" | tee -a "$SSH_PATH"

    ## Enable tunneling
    echo "PermitTunnel yes" | tee -a "$SSH_PATH"

    ## Enable X11 graphical interface forwarding
    echo "X11Forwarding yes" | tee -a "$SSH_PATH"

    ## Restart the SSH service to apply the changes
    sudo systemctl restart ssh
    sudo systemctl restart sshd
    sudo systemctl restart sshd.service

    echo
    green_msg 'SSH is Optimized.'
    echo
    sleep 0.5
}

# SYSCTL Optimization
sysctl_optimizations() {
    ## Make a backup of the original sysctl.conf file
    cp $SYS_PATH /etc/sysctl.conf.bak

    echo
    yellow_msg 'Default sysctl.conf file Saved. Directory: /etc/sysctl.conf.bak'
    echo
    sleep 1

    echo
    yellow_msg 'Optimizing the Network...'
    echo
    sleep 0.5

    sysctl="# File system settings

# Maximum open file descriptors
fs.file-max = 67108864

# Network core settings

# Default queuing discipline for network devices
net.core.default_qdisc = fq_codel
# Maximum network device backlog
net.core.netdev_max_backlog = 32768
# Maximum socket receive buffer
net.core.optmem_max = 65536
# Maximum backlog of pending connections
net.core.somaxconn = 65536
# Maximum TCP receive buffer size
net.core.rmem_max = 16777216
# Default TCP receive buffer size
net.core.rmem_default = 1048576
# Maximum TCP send buffer size
net.core.wmem_max = 16777216
# Default TCP send buffer size
net.core.wmem_default = 1048576

# TCP settings
# Socket receive buffer sizes
net.ipv4.tcp_rmem = 8192 1048576 16777216
# Socket send buffer sizes
net.ipv4.tcp_wmem = 8192 1048576 16777216
# TCP congestion control algorithm
net.ipv4.tcp_congestion_control = bbr
# Enable TCP Fast Open
net.ipv4.tcp_fastopen = 3
# TCP FIN timeout period
net.ipv4.tcp_fin_timeout = 25
# Keepalive time (seconds)
net.ipv4.tcp_keepalive_time = 1200
# Keepalive probes count
net.ipv4.tcp_keepalive_probes = 7
# Keepalive interval (seconds)
net.ipv4.tcp_keepalive_intvl = 30
# Maximum orphaned TCP sockets
net.ipv4.tcp_max_orphans = 819200
# Maximum TCP SYN backlog
net.ipv4.tcp_max_syn_backlog = 20480
# Maximum TCP Time Wait buckets
net.ipv4.tcp_max_tw_buckets = 1440000
# TCP memory limits
net.ipv4.tcp_mem = 65536 1048576 16777216
# Enable TCP MTU probing
net.ipv4.tcp_mtu_probing = 1
# Minimum amount of data in the send buffer before TCP starts sending
net.ipv4.tcp_notsent_lowat = 16384
# Retries for TCP socket to establish connection
net.ipv4.tcp_retries2 = 8
# Enable TCP SACK
net.ipv4.tcp_sack = 1
# Enable TCP DSACK
net.ipv4.tcp_dsack = 1
# Disable TCP slow start after idle
net.ipv4.tcp_slow_start_after_idle = 0
# Enable TCP window scaling
net.ipv4.tcp_window_scaling = 1
# Enable TCP ECN
net.ipv4.tcp_ecn = 1

# IP settings

# Enable IP forwarding
net.ipv4.ip_forward = 1

# UDP settings

# UDP memory limits
net.ipv4.udp_mem = 65536 1048576 16777216

# IPv6 settings

# Enable IPv6
net.ipv6.conf.all.disable_ipv6 = 0
# Enable IPv6 forwarding
net.ipv6.conf.all.forwarding = 1
# Enable IPv6 by default
net.ipv6.conf.default.disable_ipv6 = 0

# UNIX domain sockets

# Maximum queue length of UNIX domain sockets
net.unix.max_dgram_qlen = 50

# Virtual memory (VM) settings

# Minimum free Kbytes at which VM pressure happens
vm.min_free_kbytes = 65536
# How aggressively swap memory pages are used
vm.swappiness = 10
# Controls the tendency of the kernel to reclaim the memory which is used for caching of directory and inode objects.
vm.vfs_cache_pressure = 50
"

    echo "${sysctl}" | sudo tee /etc/sysctl.conf >/dev/null
    sleep 0.5
    sudo sysctl -p

    echo
    green_msg 'Network is Optimized.'
    echo
    sleep 0.5
}

# System Limits Optimizations
limits_optimizations() {
    echo
    yellow_msg 'Optimizing System Limits...'
    echo
    sleep 0.5

    ## Clear old ulimits
    sed -i '/ulimit -c/d' $PRF_PATH
    sed -i '/ulimit -d/d' $PRF_PATH
    sed -i '/ulimit -f/d' $PRF_PATH
    sed -i '/ulimit -i/d' $PRF_PATH
    sed -i '/ulimit -l/d' $PRF_PATH
    sed -i '/ulimit -m/d' $PRF_PATH
    sed -i '/ulimit -n/d' $PRF_PATH
    sed -i '/ulimit -q/d' $PRF_PATH
    sed -i '/ulimit -s/d' $PRF_PATH
    sed -i '/ulimit -t/d' $PRF_PATH
    sed -i '/ulimit -u/d' $PRF_PATH
    sed -i '/ulimit -v/d' $PRF_PATH
    sed -i '/ulimit -x/d' $PRF_PATH
    sed -i '/ulimit -s/d' $PRF_PATH

    ## The maximum size of core files created.
    echo "ulimit -c unlimited" | tee -a $PRF_PATH

    ## The maximum size of a process's data segment
    echo "ulimit -d unlimited" | tee -a $PRF_PATH

    ## The maximum size of files created by the shell (default option)
    echo "ulimit -f unlimited" | tee -a $PRF_PATH

    ## The maximum number of pending signals
    echo "ulimit -i unlimited" | tee -a $PRF_PATH

    ## The maximum size that may be locked into memory
    echo "ulimit -l unlimited" | tee -a $PRF_PATH

    ## The maximum memory size
    echo "ulimit -m unlimited" | tee -a $PRF_PATH

    ## The maximum number of open file descriptors
    echo "ulimit -n 1048576" | tee -a $PRF_PATH

    ## The maximum POSIX message queue size
    echo "ulimit -q unlimited" | tee -a $PRF_PATH

    ## The maximum stack size
    echo "ulimit -s -H 65536" | tee -a $PRF_PATH
    echo "ulimit -s 32768" | tee -a $PRF_PATH

    ## The maximum number of seconds to be used by each process.
    echo "ulimit -t unlimited" | tee -a $PRF_PATH

    ## The maximum number of processes available to a single user
    echo "ulimit -u unlimited" | tee -a $PRF_PATH

    ## The maximum amount of virtual memory available to the process
    echo "ulimit -v unlimited" | tee -a $PRF_PATH

    ## The maximum number of file locks
    echo "ulimit -x unlimited" | tee -a $PRF_PATH

    echo
    green_msg 'System Limits are Optimized.'
    echo
    sleep 0.5
}

# Iptables securities rules
iptables_config_rules() {
    # Function to add iptables rules
    add_iptables_rules() {
        sudo iptables-restore <$RULES_FILE
    }

    # Function to check if the rules are already added
    check_if_rules_exist() {
        # Create temporary files to store the iptables content
        iptables_tmp=$(mktemp)
        rules_tmp=$(mktemp)

        # Save the current iptables rules to the temporary file
        sudo iptables-save | sudo tee "$iptables_tmp"

        # Check if the rules file exists and is not empty
        if [ -s "$RULES_FILE" ]; then
            # Compare the content of iptables and the rules file
            cmp -s "$iptables_tmp" "$RULES_FILE"
            result=$?
        else
            # If the rules file does not exist or is empty, consider them not equal
            result=1
        fi

        # Remove temporary files
        rm "$iptables_tmp" "$rules_tmp"

        return $result
    }

    # Main part of the script
    if check_if_rules_exist; then
        echo "The iptables rules already exist. No changes made."
    else
        # Clear all existing rules
        sudo iptables -t filter -F INPUT
        sudo iptables -t filter -F OUTPUT
        sudo iptables -t mangle -F PREROUTING

        # Add the rules to the file
        sudo iptables -I INPUT -p tcp -m tcp --dport 80 -j ACCEPT
        sudo iptables -I INPUT -p udp -m udp --dport 80 -j ACCEPT
        sudo iptables -I INPUT -p tcp -m tcp --dport 443 -j ACCEPT
        sudo iptables -I INPUT -p udp -m udp --dport 443 -j ACCEPT
        sudo iptables -I INPUT -p tcp -m tcp --dport 22 -j ACCEPT
        sudo iptables -I INPUT -p udp -m udp --dport 22 -j ACCEPT
        sudo iptables -A OUTPUT -p tcp -m tcp --sport 40000 -j ACCEPT
        sudo iptables -I INPUT -p tcp -m tcp --dport $SSH_PORT -j ACCEPT
        sudo iptables -I INPUT -p udp -m udp --dport $SSH_PORT -j ACCEPT
        sudo iptables -t mangle -A PREROUTING -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j DROP
        sudo iptables -t mangle -A PREROUTING -p icmp -j DROP
        sudo iptables -t mangle -A PREROUTING -f -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
        sudo iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP
        sudo iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
        sudo iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
        sudo iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP
        sudo iptables -A OUTPUT -p tcp -m string --string "fast.com" --algo kmp --to 65535 -j DROP
        sudo iptables -A OUTPUT -p tcp -m string --string "testspeed.ir" --algo kmp --to 65535 -j DROP
        sudo iptables -A OUTPUT -p tcp -m string --string "www.testspeed.ir" --algo kmp --to 65535 -j DROP
        sudo iptables -A OUTPUT -p tcp -m string --string "pishgaman.net" --algo kmp --to 65535 -j DROP
        sudo iptables -A OUTPUT -p tcp -m string --string "speedcheck.ir" --algo kmp --to 65535 -j DROP
        sudo iptables -A OUTPUT -p tcp -m string --string "www.speedcheck.ir" --algo kmp --to 65535 -j DROP
        sudo iptables -A OUTPUT -p tcp -m string --string "www.speedtest.net" --algo kmp --to 65535 -j DROP
        sudo iptables -A OUTPUT -p tcp -m string --string "speedtest.net" --algo kmp --to 65535 -j DROP

        # Save the rules to the file
        sudo iptables-save | sudo tee $RULES_FILE

        # Add the rules to the iptables
        add_iptables_rules

        echo
        green_msg 'UFW is Disabled & Added iptables Security Rules. (Open your custom ports manually - Automate Script is soon...)'
        echo
        sleep 0.5
    fi
}

# Security Rules And Firewall Managements
iptsec_rules() {
    echo
    yellow_msg 'Config Security Rules...'
    echo
    sleep 0.5

    ## Purge firewalld to install UFW.
    sudo apt -y purge firewalld
    ## Disable UFW
    sudo ufw disable
    ## Open default ports.
    sudo ufw allow $SSH_PORT
    sudo ufw allow $SSH_PORT/udp
    sudo ufw allow 80
    sudo ufw allow 80/udp
    sudo ufw allow 443
    sudo ufw allow 443/udp
    sleep 0.5

    # Define iptables Securities Rules
    iptables_config_rules
}

# Modified dns
resolvconf() {
    if wget http://kr.archive.ubuntu.com/ubuntu/pool/universe/r/resolvconf/resolvconf_1.82_all.deb; then
        if dpkg -i resolvconf_1.82_all.deb; then
            systemctl enable --now resolvconf.service
            echo "" >/etc/resolvconf/resolv.conf.d/head
            {
                echo "#resolv optimized by sorblack plz dont change it !"
                echo "nameserver 178.22.122.100"
                echo "nameserver 8.8.8.8"
                echo "nameserver 1.1.1.1"
                echo "nameserver 8.8.4.4"
                echo "nameserver 2001:4860:4860::8888"
                echo "nameserver 2001:4860:4860::8844"
            } >>/etc/resolvconf/resolv.conf.d/head
            resolvconf -u
        else
            echo "Package installation failed."
            exit 1
        fi
    else
        echo "Package download failed."
        exit 1
    fi
}

# Block all IRAN and CHINA ip range with ipban
ipban() {
    red_msg "Installing IPBan..."
    if [ ! -f "$IPBAN_INSTALL" ]; then
        if [ ! -f ipban.sh ]; then
            curl -o ipban.sh https://raw.githubusercontent.com/AliDbg/IPBAN/main/ipban.sh
        fi
        chmod +x ipban.sh
        ./ipban.sh -install yes -io OUTPUT -geoip CN,IR -limit DROP -icmp no
        touch "$IPBAN_INSTALL"
        #save iptables rules
        iptables-save > /etc/iptables/rules.v4
    else
        echo "ipban is already installed."
    fi
}

# Install 3xui Panel
3xui() {
    sleep 0.5
    red_msg "Installing 3xui Panel..."
    if [ -f install.sh ]; then
        chmod +x install.sh && ./install.sh
    else
        curl -o install.sh https://raw.githubusercontent.com/mhsanaei/3x-ui/master/install.sh
    fi
}

# Install ... :
# Fix Hosts file
fix_hosts
sleep 0.5

# Timezone
set_timezone
sleep 0.5

# SYSCTL Optimization
sysctl_optimizations
sleep 0.5

# Update and Optimize SSH config
rm_ssh_config
sleep 0.5
update_ssh_config
sleep 0.5

# Limits Optimization
limits_optimizations
sleep 0.5

# Config Security Rules And Firewall Managements
iptsec_rules
sleep 0.5

# Modified dns with resolvconf
resolvconf
sleep 0.5

# Block all IRAN and CHINA ip range with ipban
ipban
sleep 0.5

# Install 3xui Panel
3xui
sleep 0.5
#echo -e "\n\nInstallation is complete.\nPlease wait while we configure the"

echo
sleep 0.5
green_msg '========================='
green_msg 'Installation has completed.'
green_msg '========================='
