# Homelab-Threat-Blocker-Windows-
A lightweight, Python-based firewall hardening tool for Windows that protects your homelab or personal network by blocking connections from known malicious IP addresses using the built-in Windows Defender Firewall.

🔍 How It Works
Downloads updated IP blocklists from trusted open sources:
FireHOL Level 1
Spamhaus DROP

Skips trusted IPs (LAN, localhost, VPN ranges)

Removes old threat-blocking rules (created by previous runs)

Adds new inbound block rules to Windows Firewall for each bad IP

🧱 Rules are named with a clear prefix: HomelabThreatBlock, so they can be managed or deleted cleanly.

🚀 Features
🔒 Blocks connections from thousands of known malicious IPs

♻️ Cleans up old rules before each update to prevent firewall bloat

🌐 Uses netsh advfirewall — no third-party dependencies

🧠 Skips private/trusted IPs using a built-in whitelist

⚡ Simple enough to automate with Windows Task Scheduler

⚠️ Ethical & Safety Notice

❗ This tool is intended for personal or homelab use only on systems you control.

Never use it to interfere with or monitor systems you do not own.

Do not modify IP feeds to block or target legitimate services.

Review all changes made to your firewall after running.

This tool does not scan, probe, attack, or interact with any external systems — it is purely defensive and local.

🧰 Requirements
Python 3.x
Windows 10/11
Admin privileges

📦 Setup
Clone the repository or download the ZIP:
bash
Copy
Edit
git clone https://github.com/YOUR-USERNAME/homelab-threat-blocker.git
cd homelab-threat-blocker
Run the script as administrator:
bash
Copy
Edit
python firewall_updater_windows.py
🔐 You must run from an elevated Command Prompt or PowerShell.

🔁 Automate with Task Scheduler
You can schedule this script to run daily or weekly:

Open Task Scheduler

Create new task → "Run with highest privileges"

Trigger → Choose frequency

Action → Start a program:

Program: python

Arguments: C:\Path\To\firewall_updater_windows.py

🛡️ Example Output
css
Copy
Edit
[+] Downloading FireHOL...
  -> 9756 IPs collected from FireHOL
[+] Downloading Spamhaus...
  -> 1021 IPs collected from Spamhaus
[+] Removing old firewall rules...
[+] Adding 10777 firewall rules...
[✓] Done. 10777 malicious IPs blocked.

🧾 License
MIT License. You are free to use, modify, and share this code — just keep it ethical and credit the original author.

✨ Future Ideas
Add AbuseIPDB or custom feed support

Export blocked IPs to JSON or CSV

GUI or web dashboard

Outbound connection blocker mode
