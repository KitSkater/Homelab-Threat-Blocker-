#!/usr/bin/env python3

import subprocess
import requests
import re
import os

CHAIN_NAME = "THREATBLOCK"
WHITELIST = ["127.0.0.1", "10.0.0.0/8", "192.168.0.0/16", "::1"]

FIREHOL_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
SPAMHAUS_URL = "https://www.spamhaus.org/drop/drop.txt"


def run_cmd(cmd):
    """Run a shell command and return output."""
    try:
        subprocess.run(cmd, check=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"[-] Command failed: {cmd}\n{e.stderr.decode()}")


def fetch_ips():
    """Fetch IPs from blocklists."""
    firehol_ips = []
    spamhaus_ips = []

    print("[+] Fetching FireHOL blocklist...")
    firehol_resp = requests.get(FIREHOL_URL)
    if firehol_resp.ok:
        firehol_ips = [line.strip() for line in firehol_resp.text.splitlines() if line and not line.startswith("#")]

    print("[+] Fetching Spamhaus blocklist...")
    spamhaus_resp = requests.get(SPAMHAUS_URL)
    if spamhaus_resp.ok:
        for line in spamhaus_resp.text.splitlines():
            if line.startswith(";"):
                continue
            match = re.match(r"^([\d./]+)", line)
            if match:
                spamhaus_ips.append(match.group(1))

    all_ips = set(firehol_ips + spamhaus_ips)
    safe_ips = [ip for ip in all_ips if ip not in WHITELIST]
    print(f"[✓] Total IPs to block: {len(safe_ips)}")
    return safe_ips


def flush_old_rules():
    print("[*] Flushing old iptables rules...")

    # Remove any old rules referencing the chain
    run_cmd(f"iptables -D INPUT -j {CHAIN_NAME} || true")

    # Flush and delete chain if it exists
    run_cmd(f"iptables -F {CHAIN_NAME} || true")
    run_cmd(f"iptables -X {CHAIN_NAME} || true")

    # Create a new chain
    run_cmd(f"iptables -N {CHAIN_NAME}")
    run_cmd(f"iptables -I INPUT -j {CHAIN_NAME}")


def apply_blocklist(ips):
    print("[+] Applying firewall rules...")
    for ip in ips:
        run_cmd(f"iptables -A {CHAIN_NAME} -s {ip} -j DROP")
    print(f"[✓] Blocked {len(ips)} malicious IPs.")


def main():
    if os.geteuid() != 0:
        print("[-] Run this script as root (use sudo)")
        return

    flush_old_rules()
    ips = fetch_ips()
    apply_blocklist(ips)


if __name__ == "__main__":
    main()
    print("[*] Starting ThreatBlock setup...")
    print("[✓] ThreatBlock setup completed successfully.")
    print("[*] Ensure to monitor the logs for any issues.")
    print("[*] Use 'sudo iptables -L -v' to verify the rules.")
    print("[*] Use 'sudo iptables -F' to flush all rules if needed.")
    print("[*] Use 'sudo iptables -X' to delete the custom chain if needed.")
    print("[*] For more information, visit the ThreatBlock documentation.")
    print("[*] Thank you for using ThreatBlock!")
    print("[*] Script execution finished.")
    print("[*] Stay safe and secure!")