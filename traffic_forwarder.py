#!/usr/bin/env python3

import subprocess
import ipaddress
import netifaces
import sys
import re


def get_all_local_ips():
    """Get all IPv4 addresses mapped to their interface names"""
    ips = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        inet_addrs = addrs.get(netifaces.AF_INET, [])
        for addr in inet_addrs:
            ip = addr["addr"]
            ips.append((ip, iface))
    return ips


def choose_default_index(ips):
    """Pick a default IP index based on interface priority"""
    for i, (_, iface) in enumerate(ips):
        if re.match(r"^en|^eth", iface):
            return i
    for i, (_, iface) in enumerate(ips):
        if re.match(r"^wl", iface):
            return i
    return 0


def prompt_ip_choice(ips, default_index):
    print("\n[INFO] Choose interface and IP for incoming traffic:")
    for i, (ip, iface) in enumerate(ips):
        default_tag = " (default)" if i == default_index else ""
        print(f"  [{i}] {ip:<15} => {iface}{default_tag}")

    while True:
        try:
            choice = input(f"\nChoose WAN IP by index [{default_index}]: ").strip()
            choice = int(choice) if choice else default_index
            if 0 <= choice < len(ips):
                return ips[choice]
            else:
                print(f"[ERROR] Please enter a valid number between 0 and {len(ips)-1}")
        except ValueError:
            print("[ERROR] Please enter a valid number")


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
    if not all_ips:
        print("[ERROR] No usable IPs found on this machine.")
        sys.exit(1)

    default_index = choose_default_index(all_ips)
    wan_ip, iface = prompt_ip_choice(all_ips, default_index)

    dest_ip = input(
        "[INFO] Enter destination IP for outgoing traffic [10.11.0.200]: "
    ).strip()
    try:
        ipaddress.ip_address(dest_ip)
    except ValueError:
        print("[ERROR] Invalid destination IP")
        sys.exit(1)

    sport = input("[INFO] Enter source port for incoming traffic: ").strip()
    if not sport.isdigit():
        print("[ERROR] Source port must be numeric.")
        sys.exit(1)

    dport = (
        input(f"[INFO] Enter destination port for outgoing traffic [{sport}]: ").strip()
        or sport
    )
    if not dport.isdigit():
        print("[ERROR] Destination port must be numeric.")
        sys.exit(1)

    proto = input("[INFO] Enter protocol for traffic forwarding [tcp/udp] (default: tcp): ").strip().lower() or "tcp"
    if proto not in ["tcp", "udp"]:
        print("[ERROR] Protocol must be tcp or udp.")
        sys.exit(1)

    enable = (input("[INFO] Apply traffic forwarding rule now? [y/N] (default: y): ").strip().lower() or "y") == "y"

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
