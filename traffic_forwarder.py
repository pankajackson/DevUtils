#!/usr/bin/env python3

import subprocess
import socket
import ipaddress
import netifaces
import sys


def get_all_local_ips():
    ips = {}
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        inet_addrs = addrs.get(netifaces.AF_INET, [])
        for addr in inet_addrs:
            ip = addr["addr"]
            ips[ip] = iface
    return ips


def get_default_interface():
    try:
        gw = netifaces.gateways().get("default")
        if gw and netifaces.AF_INET in gw:
            return gw[netifaces.AF_INET][1]
    except Exception:
        pass
    return None


def iptables_rule_exists(table, rule):
    result = subprocess.run(
        f"sudo iptables -t {table} -C {rule}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def add_iptables_rule(table, rule):
    if not iptables_rule_exists(table, rule):
        print(f"[+] Adding rule: iptables -t {table} -A {rule}")
        subprocess.run(f"sudo iptables -t {table} -A {rule}", shell=True, check=True)
    else:
        print(f"[✓] Rule already exists: {rule}")


def remove_iptables_rule(table, rule):
    if iptables_rule_exists(table, rule):
        print(f"[-] Removing rule: iptables -t {table} -D {rule}")
        subprocess.run(f"sudo iptables -t {table} -D {rule}", shell=True, check=True)
    else:
        print(f"[!] Rule does not exist: {rule}")


def main():
    all_ips = get_all_local_ips()
    default_iface = get_default_interface()

    print("\n[INFO] Available Interfaces and IPs:")
    for ip, iface in all_ips.items():
        print(f"  {ip:<15}  =>  {iface}")

    wan_ip = (
        input(f"\nEnter WAN (external-facing) IP [{list(all_ips.keys())[0]}]: ").strip()
        or list(all_ips.keys())[0]
    )
    if wan_ip not in all_ips:
        print("[ERROR] Invalid WAN IP. Choose from the list above.")
        sys.exit(1)

    iface = all_ips[wan_ip]
    dest_ip = input("Enter destination internal IP (e.g., 10.0.0.100): ").strip()
    try:
        ipaddress.ip_address(dest_ip)
    except ValueError:
        print("[ERROR] Invalid destination IP")
        sys.exit(1)

    sport = input("Enter source (external) port: ").strip()
    if not sport.isdigit():
        print("[ERROR] Source port must be numeric.")
        sys.exit(1)

    dport = input(f"Enter destination port [{sport}]: ").strip() or sport
    if not dport.isdigit():
        print("[ERROR] Destination port must be numeric.")
        sys.exit(1)

    proto = input("Protocol [tcp/udp]: ").strip().lower() or "tcp"
    if proto not in ["tcp", "udp"]:
        print("[ERROR] Protocol must be tcp or udp.")
        sys.exit(1)

    enable = (input("Enable forwarding? [y/N]: ").strip().lower() or "y") == "y"

    rule_nat = f"PREROUTING -d {wan_ip} -p {proto} --dport {sport} -j DNAT --to-destination {dest_ip}:{dport}"
    rule_fwd = f"FORWARD -p {proto} -d {dest_ip} --dport {dport} -j ACCEPT"

    if enable:
        add_iptables_rule("nat", rule_nat)
        add_iptables_rule("filter", rule_fwd)
    else:
        remove_iptables_rule("nat", rule_nat)
        remove_iptables_rule("filter", rule_fwd)

    print("\n[DONE] Operation complete.\n")


if __name__ == "__main__":
    main()
