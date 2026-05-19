# 🌐 LanScope

```
██╗      █████╗ ███╗   ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
██║     ██╔══██╗████╗  ██║██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
██║     ███████║██╔██╗ ██║███████╗██║     ██║   ██║██████╔╝█████╗  
██║     ██╔══██║██║╚██╗██║╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝  
███████╗██║  ██║██║ ╚████║███████║╚██████╗╚██████╔╝██║     ███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
```

> Fast multithreaded LAN reconnaissance tool for authorized network analysis.

---

## ⚡ Overview

```diff
+ Multithreaded device discovery across local subnets
+ OS fingerprinting via TTL + TCP Window Size analysis
+ Banner grabbing: SSH version, HTTP Server header, FTP/SMTP greeting
+ Vulnerability hints for risky open ports (Telnet, RDP, SMB...)
+ Export results as TXT / JSON / CSV
+ Auto multi-interface detection
```

---

## 🚀 Features

| Feature | Description |
|---|---|
| ⚡ Multithreaded Engine | Up to 128 parallel workers |
| 🌐 LAN Discovery | Full /24 subnet sweep |
| 🧠 Hostname Resolution | Reverse DNS lookup |
| 🧲 MAC Detection | ARP cache + arping fallback |
| 🔌 Port Scanner | 16 common ports, custom port support |
| 🖥️ OS Fingerprinting | TTL + TCP Window Size combined |
| 🏷️ Banner Grabbing | SSH, HTTP, FTP, SMTP, MySQL |
| ⚠️ Vuln Hints | Telnet/RDP/SMB/VNC risk flags |
| 📊 Live Progress | Real-time progress bar + device feed |
| 💾 Export | TXT / JSON / CSV output |

---

## 🧪 Usage

```bash
# Basic scan
python3 lanscope.py

# Custom timeout & workers
python3 LAN-Scanner.py -t 0.3 -w 128

# Scan specific subnet
python3 LAN-Scanner.py -s 10.0.0.0/24

# Add extra ports
python3 LAN-Scanner.py -p 8888 9090 4444

# Export to JSON
python3 LAN-Scanner.py -o results.json -f json

# Export to CSV, skip banner grabbing
python3 LAN-Scanner.py --no-banner -o results.csv -f csv
```

### Arguments

```
-t, --timeout     Port connection timeout in seconds   (default: 0.4)
-w, --workers     Number of parallel threads           (default: 64)
-p, --ports       Additional ports to scan             (e.g: -p 8888 9090)
-s, --subnet      Manual subnet override               (e.g: 192.168.1.0/24)
-o, --output      Output file path                     (e.g: -o scan.json)
-f, --format      Output format: txt | json | csv      (default: txt)
    --no-banner   Disable banner grabbing (faster)
```

---

## 📡 Output Example

```
[01] 192.168.1.1    📶 Router (TTL+Win)
 ├─ hostname : gateway.local
 ├─ mac      : AA:BB:CC:11:22:33
 ├─ TTL: 64  │  TCP Win: 65535
 │  🔓 📂 21/FTP   » 220 vsftpd 3.0.3
 │  🔓 🔐 22/SSH   » SSH-2.0-OpenSSH_8.9
 │  🔓 🕸️  80/HTTP  » HTTP/1.1 200 OK
 │
 │  ⚠  [HIGH] FTP açık — plaintext kimlik doğrulama (:21)
 └──

[02] 192.168.1.42   🖥️ Windows PC (RDP)
 ├─ hostname : DESKTOP-AX12
 ├─ mac      : AA:BB:CC:DD:EE:FF
 ├─ TTL: 128 │  TCP Win: 65535
 │  🔓 🖥️  3389/RDP
 │  🔓 🗂️  445/SMB
 │
 │  ⚠  [HIGH] RDP açık — BlueKeep riski (:3389)
 │  ⚠  [HIGH] SMB açık — EternalBlue riski (:445)
 └──
```

---

## 🧬 OS Fingerprinting Logic

LanScope uses a combined approach for OS detection:

```
TTL > 100  +  Window = 65535  →  🪟 Windows
TTL 50-70  +  Window = 5840   →  🐧 Linux
TTL 50-70  +  Window = 65535  →  🍎 macOS
TTL > 200                     →  🔧 Network Device (Cisco/HP)
Port 3389 open                →  🖥️ Windows PC (RDP)
Port 445/139 open             →  🪟 Windows (SMB)
```

---

## ⚠️ Vulnerability Hints

| Port | Service | Risk Level | Description |
|------|---------|-----------|-------------|
| 23   | Telnet  | 🔴 CRITICAL | Cleartext protocol, MITM risk |
| 21   | FTP     | 🟠 HIGH     | Plaintext auth, anon access possible |
| 3389 | RDP     | 🟠 HIGH     | Brute-force + BlueKeep (CVE-2019-0708) |
| 5900 | VNC     | 🟠 HIGH     | Weak/no auth risk |
| 445  | SMB     | 🟠 HIGH     | EternalBlue / MS17-010 |
| 139  | NetBIOS | 🟡 MEDIUM   | Information disclosure |
| 3306 | MySQL   | 🟡 MEDIUM   | Should not be internet-facing |
| 25   | SMTP    | 🟢 LOW      | Check for open relay |
| 8080 | HTTP-ALT| 🟢 LOW      | Admin panel exposure |

---

## 💾 Export Formats

**JSON** — machine-readable, includes banners and vuln data:
```json
{
  "scan_time": "2026-05-18T14:32:00",
  "subnet": "192.168.1.0/24",
  "elapsed": 12.4,
  "devices": [
    {
      "ip": "192.168.1.1",
      "os": "📶 Router",
      "ttl": 64,
      "tcp_window": 65535,
      "ports": [{"port": 22, "name": "SSH", "banner": "SSH-2.0-OpenSSH_8.9"}],
      "vulns": []
    }
  ]
}
```

**CSV** — spreadsheet-friendly, one row per device.

**TXT** — human-readable plaintext log.

---

## 🔧 Requirements

```bash
# Python 3.8+
# No external dependencies — stdlib only

# Optional: arping for better MAC detection (Linux)
sudo apt install arping

# TCP Window fingerprinting requires root
sudo python3 lanscope.py
```

---

## ⚠️ Disclaimer

```diff
- Unauthorized scanning of networks you do not own is illegal.
- This tool is intended for educational and authorized use only.
+ Use only in environments you have explicit permission to test.
+ The author is not responsible for any misuse of this tool.
```

---

## 👤 Author

```
Original project developed by the author.
by: LaxenT (lat)
```
