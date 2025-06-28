#!/usr/bin/env python3
import os
import argparse
import subprocess
import getpass
import threading
import time
import tempfile


def require_sudo():
    """Prompt for sudo password once"""
    print("[INFO] Requesting sudo access...")
    subprocess.run(["sudo", "-v"], check=True)


def keep_sudo_alive():
    """Keep sudo session alive in the background"""

    def refresher():
        while True:
            try:
                subprocess.run(["sudo", "-n", "-v"], stderr=subprocess.DEVNULL)
            except Exception:
                pass
            time.sleep(60)

    thread = threading.Thread(target=refresher, daemon=True)
    thread.start()


def install_docker():
    subprocess.run(["sudo", "apt-get", "update", "-qq"], check=True)
    subprocess.run(["sudo", "apt-get", "install", "-y", "docker.io"], check=True)
    subprocess.run(["sudo", "systemctl", "enable", "--now", "docker"], check=True)

    user = getpass.getuser()
    print(f"[INFO] Adding user '{user}' to docker group...")
    subprocess.run(["sudo", "usermod", "-aG", "docker", user], check=True)

    print("[INFO] Please log out and log back in for group changes to take effect.")


def init_swarm(advertise_ip):
    install_docker()
    subprocess.run(
        ["sudo", "docker", "swarm", "init", "--advertise-addr", advertise_ip],
        check=True,
    )
    print("[INFO] Swarm initialized.")


def get_join_token(manager_ip, role, ssh_user):
    control_socket = os.path.join(tempfile.gettempdir(), f"swarmer_{manager_ip}.sock")
    ssh_base = [
        "ssh",
        "-o",
        "ControlMaster=auto",
        "-o",
        f"ControlPath={control_socket}",
        "-o",
        "ControlPersist=300",
        f"{ssh_user}@{manager_ip}",
    ]

    print(f"[INFO] Connecting to {ssh_user}@{manager_ip} via SSH...")
    return subprocess.check_output(
        ssh_base + [f"docker swarm join-token -q {role}"],
        text=True,
    ).strip()


def join_swarm(manager_ip, role, ssh_user):
    install_docker()
    token = get_join_token(manager_ip, role, ssh_user)
    subprocess.run(
        ["sudo", "docker", "swarm", "join", "--token", token, f"{manager_ip}:2377"],
        check=True,
    )
    print(f"[INFO] Joined the swarm as a {role}.")


def promote_node(hostname):
    subprocess.run(["sudo", "docker", "node", "promote", hostname], check=True)
    print(f"[INFO] Node '{hostname}' promoted to manager.")


def status():
    print("[INFO] Swarm status:")
    subprocess.run(["docker", "info"], check=False)
    subprocess.run(["docker", "node", "ls"], check=False)


def ask_ssh_user():
    default_user = os.getenv("SWARMER_SSH_USER", getpass.getuser())
    entered = input(f"[?] Enter SSH username [{default_user}]: ").strip()
    return entered if entered else default_user


def main():
    require_sudo()
    keep_sudo_alive()

    parser = argparse.ArgumentParser(description="Swarmer - Docker Swarm manager CLI")
    subparsers = parser.add_subparsers(dest="command")

    # init
    p_init = subparsers.add_parser("init", help="Initialize swarm")
    p_init.add_argument("advertise_ip", help="IP to advertise")

    # join
    p_join = subparsers.add_parser("join", help="Join swarm")
    p_join.add_argument("manager_ip", help="IP of existing swarm manager")
    p_join.add_argument(
        "--role", default="worker", choices=["worker", "manager"], help="Node role"
    )

    # promote
    p_promote = subparsers.add_parser("promote", help="Promote node to manager")
    p_promote.add_argument("hostname", help="Hostname of node to promote")

    # status
    subparsers.add_parser("status", help="Show swarm status")

    args = parser.parse_args()

    if args.command == "init":
        init_swarm(args.advertise_ip)
    elif args.command == "join":
        ssh_user = ask_ssh_user()
        join_swarm(args.manager_ip, args.role, ssh_user)
    elif args.command == "promote":
        promote_node(args.hostname)
    elif args.command == "status":
        status()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
