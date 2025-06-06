# 🛡️ Homelab-Threat-Blocker

A lightweight, Python-based firewall hardening tool for **Windows and Linux**, designed to protect your **homelab or personal network** by blocking known malicious IP addresses using your system’s built-in firewall tools.

---

## 🔍 How It Works

- Downloads updated blocklists from trusted open sources:
  - [FireHOL Level 1](https://github.com/firehol/blocklist-ipsets)
  - [Spamhaus DROP](https://www.spamhaus.org/drop/)
- Skips safe IPs (LAN, localhost, VPN ranges)
- Clears previously-added rules to avoid duplication
- Applies new `DROP` rules:
  - ✅ On Windows: uses `netsh advfirewall`
  - ✅ On Linux: uses `iptables` (nftables version coming soon)
- Rule names are prefixed with `HomelabThreatBlock` for clean management

---

## 🚀 Features

- 🔒 Blocks thousands of known malicious IPs
- ♻️ Automatically removes outdated rules
- 🌐 No third-party dependencies; uses built-in system firewalls
- 🧠 Skips private and internal IPs with a whitelist
- ⚙️ Designed for easy automation (Task Scheduler or cron)

---

## ⚠️ Ethical Use Notice

> This tool is for **defensive, ethical use only** on **systems you own or manage.**

- ❗ Never use it to interfere with or monitor external systems
- ❗ Do not alter feed sources to block legitimate traffic
- ✅ This script does **not scan, probe, or attack** — it’s **100% local and passive**
- 🔍 Always review changes to your firewall before and after applying

---

## 🧰 Requirements

| System     | Requirements                          |
|------------|----------------------------------------|
| Windows    | Python 3.x, Windows 10/11, Admin rights |
| Linux      | Python 3.x, `iptables`, `sudo` access   |

---

## 📦 Setup & Usage

1. **Clone the repo**:
   ```bash
   git clone https://github.com/YOUR-USERNAME/homelab-threat-blocker.git
   cd homelab-threat-blocker
2 Run the script:

Windows (elevated Command Prompt or PowerShell):

bash

python firewall_updater_windows.py
Linux:

bash

sudo python3 firewall_updater_linux.py

🔁 Automate the Updates
🪟 Windows (Task Scheduler)
Create a new task → “Run with highest privileges”

Trigger → Choose daily/weekly

Action → Start a program:

Program: python

Arguments: C:\Path\To\firewall_updater_windows.py

🐧 Linux (cron)
bash

sudo crontab -e
Add:
swift

@daily /usr/bin/python3 /path/to/firewall_updater_linux.py
🛡️ Example Output

[+] Downloading FireHOL...
  → 9756 IPs collected from FireHOL
[+] Downloading Spamhaus...
  → 1021 IPs collected from Spamhaus
[+] Removing old firewall rules...
[+] Adding 10,777 firewall rules...
[✓] Done. 10,777 malicious IPs blocked.

🧾 License
This project is licensed under the MIT License.
You are free to use, modify, and share — just stay ethical and credit the original author.

✨ Future Plans
Add support for AbuseIPDB and custom feeds

Export blocked IPs to CSV/JSON

Optional GUI or web dashboard

nftables support for modern Linux systems


