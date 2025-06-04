import subprocess
import requests # type: ignore
import re

# Constants
WHITELIST = [
    "127.0.0.1",
    "192.168.",  # LAN
    "10.",
    "172.16."
]
RULE_PREFIX = "HomelabThreatBlock"
BLOCK_FEEDS = {
    "FireHOL": "https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset",
    "Spamhaus": "https://www.spamhaus.org/drop/drop.txt"
}

def is_whitelisted(ip):
    return any(ip.startswith(prefix) for prefix in WHITELIST)

def get_ips_from_feed(name, url):
    print(f"[+] Downloading {name}...")
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
    except Exception as e:
        print(f"[!] Failed to fetch {name}: {e}")
        return []
    
    raw = r.text
    ips = set()

    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("#") or not line:
            continue
        match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})(?:/\d+)?", line)
        if match:
            ip = match.group(1)
            if not is_whitelisted(ip):
                ips.add(ip)
    print(f"  -> {len(ips)} IPs collected from {name}")
    return list(ips)

def remove_old_rules():
    print("[+] Removing old firewall rules...")
    cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={RULE_PREFIX}']
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def add_firewall_rule(ip):
    cmd = [
        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
        f'name={RULE_PREFIX}',
        'dir=in',
        'action=block',
        'remoteip=' + ip,
        'protocol=any',
        'enable=yes'
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    all_ips = set()
    for name, url in BLOCK_FEEDS.items():
        ips = get_ips_from_feed(name, url)
        all_ips.update(ips)

    if not all_ips:
        print("[!] No IPs to block. Exiting.")
        return

    remove_old_rules()
    print(f"[+] Adding {len(all_ips)} firewall rules...")
    for ip in all_ips:
        add_firewall_rule(ip)

    print(f"[✓] Done. {len(all_ips)} malicious IPs blocked.")

if __name__ == "__main__":
    main()
