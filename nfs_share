#!/bin/bash

# ==============================================================================
# Script Name : nfs_share
# Description : This script installs and configures NFS exports.
#               It allows sharing specific directories over NFS with specified
#               IP addresses or subnets, applying correct permissions, firewall
#               rules, and ensuring the NFS server is running.
# Author      : Pankaj Jackson
# Version     : 1.0.0
# Date        : 2025-08-04
# License     : MIT License
# ==============================================================================
#
# Usage:
#   ./nfs_share.sh                        # Share default directory with everyone (*)
#   ./nfs_share.sh /some/dir             # Share /some/dir with everyone (*)
#   ./nfs_share.sh /some/dir 192.168.1.0/24   # Share /some/dir with specific subnet/IP
#
# Arguments:
#   /some/dir     - Absolute path to the directory to share.
#   subnet/ip     - Subnet or IP in CIDR (192.168.1.0/24) or IP (192.168.1.10) format, or *.
#
# Dependencies:
#   - nfs-kernel-server
#   - iptables (or ufw if available)
#
# Notes:
#   - This script validates directory path and subnet/IP before exporting.
#   - Automatically installs required packages if missing.
#   - Applies permissive directory permissions (777) for accessibility.
#
# ==============================================================================


# Colors
GREEN="\e[32m"
RED="\e[31m"
RESET="\e[0m"

# Constants
NFS_PACKAGE="nfs-kernel-server"
EXPORTS_FILE="/etc/exports"
DEFAULT_DIR="/opt/storage/nfs/public"
DEFAULT_SUBNET="*"

# Helpers
echo_ok() { echo -e "${GREEN}[OK]${RESET} $1"; }
echo_warn() { echo -e "${RED}[WARN]${RESET} $1"; }
echo_error() { echo -e "${RED}[ERROR]${RESET} $1"; }

is_valid_path() {
    local path="$1"
    [[ "$path" == /* && "$path" != "" ]]
}

is_valid_subnet_or_ip() {
    local input="$1"
    [[ "$input" == "*" ]] && return 0

    # CIDR format
    if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$ ]]; then
        return 0
    fi

    # IP format
    if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        return 0
    fi

    return 1
}

install_nfs() {
    if ! dpkg -l | grep -q "$NFS_PACKAGE"; then
        echo "[INFO] Installing $NFS_PACKAGE..."
        sudo apt update && sudo apt install -y $NFS_PACKAGE
        echo_ok "$NFS_PACKAGE installed"
    else
        echo_ok "$NFS_PACKAGE already installed"
    fi
}

create_shared_directory() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        sudo mkdir -p "$dir"
        sudo chown nobody:nogroup "$dir" 2>/dev/null || sudo chown nobody:nobody "$dir"
        sudo chmod 777 "$dir"
        echo_ok "Directory created with open permissions: $dir"
    else
        echo_ok "Directory already exists: $dir"
    fi
}

add_export() {
    local dir="$1"
    local subnet="$2"
    local line="$dir $subnet(rw,sync,no_subtree_check,no_root_squash)"
    if ! grep -Fxq "$line" "$EXPORTS_FILE"; then
        echo "$line" | sudo tee -a "$EXPORTS_FILE" >/dev/null
        echo_ok "Export added to /etc/exports: $line"
    else
        echo_ok "Export already exists: $line"
    fi
}

reload_exports() {
    sudo exportfs -ra
    echo_ok "/etc/exports reloaded"
}

start_nfs_service() {
    if systemctl is-active --quiet nfs-server; then
        echo_ok "nfs-server already running"
    else
        sudo systemctl enable nfs-server
        sudo systemctl start nfs-server
        echo_ok "nfs-server started and enabled"
    fi
}

add_firewall_rule() {
    local subnet="$1"
    if [[ "$subnet" == "*" ]]; then
        echo_warn "Skipping firewall for wildcard subnet (*)"
        return
    fi

    if command -v ufw >/dev/null 2>&1; then
        if sudo ufw status | grep -q "Status: active"; then
            if ! sudo ufw status | grep -q "2049"; then
                sudo ufw allow from "$subnet" to any port nfs
                echo_ok "UFW rule added to allow NFS from $subnet"
            else
                echo_ok "UFW rule for NFS already exists"
            fi
        else
            echo_warn "UFW is not active. Skipping UFW rules."
        fi
    else
        echo_warn "UFW not installed. Using iptables..."
        if ! command -v iptables >/dev/null 2>&1; then
            sudo apt install -y iptables
            echo_ok "iptables installed"
        fi

        if ! sudo iptables -C INPUT -p tcp --dport 2049 -s "$subnet" -j ACCEPT 2>/dev/null; then
            sudo iptables -A INPUT -p tcp --dport 2049 -s "$subnet" -j ACCEPT
            echo_ok "iptables rule added for NFS (port 2049)"
        else
            echo_ok "iptables rule already exists"
        fi
    fi
}

nfs_share() {
    local dir="$1"
    local subnet="$2"

    dir="${dir:-$DEFAULT_DIR}"
    subnet="${subnet:-$DEFAULT_SUBNET}"

    # ✅ Path check
    if ! is_valid_path "$dir"; then
        echo_error "Invalid directory path. Use absolute path like /opt/storage/data"
        exit 1
    fi

    # ✅ Subnet/IP check
    if ! is_valid_subnet_or_ip "$subnet"; then
        echo_error "Invalid subnet or IP address: $subnet"
        echo "Use valid format: 192.168.1.0/24 or 192.168.1.10 or '*'"
        exit 1
    fi

    install_nfs
    create_shared_directory "$dir"
    add_export "$dir" "$subnet"
    reload_exports
    start_nfs_service
    add_firewall_rule "$subnet"

    echo_ok "✅ Shared $dir with $subnet"
}

# CLI handling
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Usage:"
    echo "  $0                          # Share default directory with everyone (*)"
    echo "  $0 /some/dir                # Share /some/dir with everyone (*)"
    echo "  $0 /some/dir 192.168.1.0/24 # Share /some/dir with subnet"
    exit 0
fi

# Execute
nfs_share "$1" "$2"
