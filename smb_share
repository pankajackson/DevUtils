#!/bin/bash

# ==============================================================================
# Script Name : smb_share
# Description : This script installs and configures Samba (SMB/CIFS) shares.
#               It allows creating public or private shares, managing users,
#               setting permissions, and automatically updating smb.conf.
#               It also provides a CLI to list all configured shares.
#
# Author      : Pankaj Jackson
# Version     : 1.0.0
# Date        : 2026-03-17
# License     : MIT License
# ==============================================================================
#
# Usage:
#   ./smb_share /path
#       → Create a PUBLIC share (guest access enabled)
#
#   ./smb_share /path <user>
#       → Create a PRIVATE share with user authentication
#
#   ./smb_share /path <user> <password>
#       → Create PRIVATE share and set password non-interactively
#
#   ./smb_share list
#   ./smb_share ls
#       → List all configured SMB shares with access details
#
# Examples:
#   ./smb_share /opt/storage/public
#   ./smb_share /opt/storage/private/test pankaj
#   ./smb_share /opt/storage/private/test pankaj mypassword
#   ./smb_share list
#
# Arguments:
#   /path       - Absolute path of directory to share
#   user        - (Optional) Username for private share
#   password    - (Optional) Password for SMB user (non-interactive)
#
# Dependencies:
#   - samba
#   - smbclient
#
# Notes:
#   - Requires sudo/root privileges for installation and configuration
#   - Automatically installs Samba if not present
#   - Creates system user (nologin) for SMB authentication if needed
#   - Ensures idempotent share creation (no duplicate entries)
#   - Applies:
#       • 777 permissions for public shares
#       • 770 permissions for private shares
#   - Updates /etc/samba/smb.conf safely
#   - Restarts Samba service automatically after changes
#
# Limitations:
#   - Designed for single-node/local setups (not clustered Samba)
#   - Does not validate complex smb.conf customizations
#
# ==============================================================================


GREEN="\e[32m"
RED="\e[31m"
RESET="\e[0m"

SMB_CONF="/etc/samba/smb.conf"

echo_ok() { echo -e "${GREEN}[OK]${RESET} $1"; }
echo_error() { echo -e "${RED}[ERROR]${RESET} $1"; }

# ---------------- VALIDATION ----------------

is_valid_path() {
    [[ "$1" == /* && "$1" != "" ]]
}

user_exists() {
    sudo pdbedit -L | cut -d: -f1 | grep -qx "$1"
}

share_exists() {
    grep -q "^\[$1\]" "$SMB_CONF"
}

get_share_block() {
    awk "/^\[$1\]/,/^$/" "$SMB_CONF"
}

# ---------------- INSTALL ----------------

install_samba() {
    if ! dpkg -l | grep -q samba; then
        sudo apt update && sudo apt install -y samba smbclient
        echo_ok "Samba installed"
    else
        echo_ok "Samba already installed"
    fi
}

# ---------------- USER ----------------

ensure_user() {
    local user="$1"
    local pass="$2"

    if user_exists "$user"; then
        echo "[INFO] Skipping user creation: $user already exists"
        return
    fi

    echo "[INFO] Creating user: $user"
    sudo useradd -M -s /sbin/nologin "$user" 2>/dev/null

    local attempts=0
    local max_attempts=3

    while [[ $attempts -lt $max_attempts ]]; do
        if [[ -z "$pass" ]]; then
            echo "[INFO] Set SMB password for $user (attempt $((attempts+1))/$max_attempts)"
            sudo smbpasswd -a "$user"
            rc=$?
        else
            echo "[INFO] Setting password via CLI"
            echo -e "$pass\n$pass" | sudo smbpasswd -a -s "$user"
            rc=$?
        fi

        if [[ $rc -eq 0 ]]; then
            echo_ok "User created: $user"
            return
        fi

        echo_error "Password setup failed"
        ((attempts++))
        pass=""
    done

    echo_error "Failed to set password after $max_attempts attempts"
    exit 1
}

# ---------------- DIRECTORY ----------------

setup_directory() {
    local dir="$1"
    local user="$2"

    sudo mkdir -p "$dir"

    if [[ -n "$user" ]]; then
        sudo chown -R "$user":"$user" "$dir"
        sudo chmod -R 770 "$dir"
    else
        sudo chmod -R 777 "$dir"
    fi

    echo_ok "Directory ready: $dir"
}

# ---------------- SHARE ----------------

user_in_share() {
    local name="$1"
    local user="$2"

    get_share_block "$name" | grep -q "valid users" && \
    get_share_block "$name" | grep -qw "$user"
}

update_or_create_share() {
    local dir="$1"
    local user="$2"
    local name
    name=$(basename "$dir")

    if share_exists "$name"; then
        echo "[INFO] Share exists: $name"

        if [[ -n "$user" ]]; then
            if user_in_share "$name" "$user"; then
                echo_ok "User already has access"
            else
                echo "[INFO] Adding user to share"

                if get_share_block "$name" | grep -q "valid users"; then
                    sudo sed -i "/^\[$name\]/,/^$/ s/valid users =.*/&,$user/" "$SMB_CONF"
                else
                    sudo sed -i "/^\[$name\]/a \   valid users = $user" "$SMB_CONF"
                fi

                echo_ok "User added"
            fi
        else
            echo "[INFO] Public mode requested — leaving existing config unchanged"
        fi

        return
    fi

    echo "[INFO] Creating new share: $name"

    sudo bash -c "cat >> $SMB_CONF" <<EOF

[$name]
   path = $dir
   browseable = yes
   writable = yes
EOF

    if [[ -z "$user" ]]; then
        echo "   guest ok = yes" | sudo tee -a "$SMB_CONF" >/dev/null
    else
        echo "   guest ok = no" | sudo tee -a "$SMB_CONF" >/dev/null
        echo "   valid users = $user" | sudo tee -a "$SMB_CONF" >/dev/null
    fi

    echo_ok "Share created"
}

# ---------------- GLOBAL ----------------

ensure_global_config() {
    if ! grep -q "server min protocol" "$SMB_CONF"; then
        sudo sed -i '/\[global\]/a \
   server min protocol = SMB2\n   map to guest = Bad User' "$SMB_CONF"
    fi
}

# ---------------- SERVICE ----------------

restart_samba() {
    sudo systemctl restart smbd
    sudo systemctl enable smbd >/dev/null 2>&1
    echo_ok "Samba restarted"
}

# ---------------- OUTPUT ----------------

print_share_details() {
    local share="$1"
    local ip="$2"

    echo ""
    echo "Share: $share"

    if get_share_block "$share" | grep -q "guest ok = yes"; then
        echo "Access:"
        echo "  smbclient //$ip/$share -N"
    else
        echo "Access:"
        echo "  smbclient //$ip/$share -U <user>"
    fi

    echo ""
    echo "Mount (Linux):"
    echo "  sudo mount -t cifs //$ip/$share /mnt -o username=<user>"

    echo ""
    echo "Windows:"
    echo "  \\\\$ip\\$share"
}

list_shares() {
    local ip
    ip=$(hostname -I | awk '{print $1}')

    echo ""
    echo "========== SMB SHARES =========="

    grep "^\[" "$SMB_CONF" | tr -d '[]' | while read -r share; do
        [[ "$share" == "global" ]] && continue
        print_share_details "$share" "$ip"
    done

    echo ""
    echo "================================"
}

# ---------------- MAIN ----------------

smb_share() {
    local dir="$1"
    local user="$2"
    local pass="$3"

    if ! is_valid_path "$dir"; then
        echo_error "Invalid path"
        exit 1
    fi

    install_samba

    if [[ -n "$user" ]]; then
        ensure_user "$user" "$pass"
    fi

    setup_directory "$dir" "$user"
    ensure_global_config
    update_or_create_share "$dir" "$user"
    restart_samba

    IP=$(hostname -I | awk '{print $1}')

    echo_ok "✅ SMB Share ready"
    echo "Path: //$IP/$(basename "$dir")"

    if [[ -n "$user" ]]; then
        echo "User: $user"
    else
        echo "Access: Public"
    fi

    echo ""
    echo "========== SMB SHARE =========="
    print_share_details "$(basename "$dir")" "$IP"
    echo ""
    echo "================================"
}

# ---------------- CLI ----------------

if [[ -z "$1" ]]; then
    echo "Usage:"
    echo "  $0 /path [user] [password]"
    echo "  $0 list | ls"
    exit 1
fi

if [[ "$1" == "list" || "$1" == "ls" ]]; then
    list_shares
    exit 0
fi

smb_share "$1" "$2" "$3"
