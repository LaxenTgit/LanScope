import os
import time
import json
import csv
import socket
import subprocess
import struct
import threading
import argparse
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

# ── ANSI renk kodları ─────────────────────────────────────────────────────────
R   = "\033[38;5;196m"
G   = "\033[38;5;82m"
Y   = "\033[38;5;226m"
C   = "\033[38;5;51m"
M   = "\033[38;5;201m"
DG  = "\033[38;5;238m"
GR  = "\033[38;5;245m"
W   = "\033[97m"
B   = "\033[1m"
DIM = "\033[2m"
RST = "\033[0m"

lock = threading.Lock()

# ── terminal genişliği ────────────────────────────────────────────────────────
def tw():
    try:
        return os.get_terminal_size().columns
    except:
        return 80

def clear_line():
    print(f"\r{' ' * tw()}\r", end="", flush=True)

# ── banner ────────────────────────────────────────────────────────────────────
def banner(args):
    os.system("clear")
    width = tw()
    now   = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    top   = f"{DG}{'─' * width}{RST}"
    print(top)
    print(f"{B}{C}  ◈  NET RECON  ◈{RST}")
    print(f"{DG}  scanner by laxent🔎  {GR}{now}{RST}")
    print(f"{DG}  FUCK I FUCKİNG LOVE EMİRA TOO MUCH  {GR}{now}{RST}")
    print(f"{DG}  workers={args.workers}  timeout={args.timeout}s  ports={'custom' if args.ports else 'default'}  export={args.format}{RST}")
    print(top)
    print()

# ── spinner ───────────────────────────────────────────────────────────────────
SPIN_FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

class Spinner:
    def __init__(self, msg=""):
        self.msg   = msg
        self._stop = threading.Event()
        self._t    = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        i = 0
        while not self._stop.is_set():
            frame = SPIN_FRAMES[i % len(SPIN_FRAMES)]
            print(f"\r  {C}{frame}{RST}  {DIM}{self.msg}{RST}", end="", flush=True)
            time.sleep(0.08)
            i += 1

    def start(self):
        self._t.start()
        return self

    def stop(self, final_msg=None):
        self._stop.set()
        self._t.join()
        clear_line()
        if final_msg:
            print(final_msg)

# ── yerel IP tespiti: tüm interface'leri tara ─────────────────────────────────
def get_local_info(prefer_subnet=None):
    candidates = []
    try:
        import re
        out = subprocess.check_output(
            ["ip", "-4", "addr", "show"], stderr=subprocess.DEVNULL
        ).decode()
        for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", out):
            ip, prefix = m.group(1), int(m.group(2))
            if not ip.startswith("127."):
                net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                candidates.append((ip, str(net)))
    except:
        pass

    if not candidates:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            parts = ip.split(".")
            candidates.append((ip, f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"))
        except:
            candidates.append(("127.0.0.1", "127.0.0.0/8"))
        finally:
            s.close()

    if prefer_subnet:
        for ip, subnet in candidates:
            if subnet == prefer_subnet:
                return ip, subnet

    return candidates[0] if candidates else ("127.0.0.1", "127.0.0.0/8")

# ── hostname ──────────────────────────────────────────────────────────────────
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

# ── MAC: ARP cache → arping fallback ─────────────────────────────────────────
def get_mac(ip):
    def parse_arp(ip):
        try:
            out = subprocess.check_output(["arp", "-n", ip], stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[0] == ip:
                    mac = parts[2]
                    if ":" in mac or "-" in mac:
                        return mac.upper()
        except:
            pass
        return None

    mac = parse_arp(ip)
    if mac:
        return mac
    try:
        subprocess.run(
            ["arping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
        )
        return parse_arp(ip)
    except:
        pass
    return None

# ── TTL fingerprinting ────────────────────────────────────────────────────────
def get_ttl(ip, timeout=1):
    try:
        out = subprocess.check_output(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            stderr=subprocess.DEVNULL
        ).decode()
        for token in out.split():
            if token.lower().startswith("ttl="):
                return int(token.split("=")[1])
    except:
        pass
    return None

def ttl_os_hint(ttl):
    if ttl is None:
        return None
    if ttl > 200:
        return "🔧 Network Device (Cisco/HP)"
    if ttl > 100:
        return "🪟 Windows"
    if ttl > 50:
        return "🐧 Linux / 🍎 macOS"
    return "❓ Low TTL"

# ── TCP Window Size fingerprinting ───────────────────────────────────────────
def tcp_window_hint(ip, port=80, timeout=1):
    """
    Raw socket ile SYN-ACK'tan TCP window size okur.
    Root yetkisi gerektirir; başarısız olursa None döner.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.settimeout(timeout)

        def checksum(data):
            s = 0
            for i in range(0, len(data), 2):
                if i + 1 < len(data):
                    s += (data[i] << 8) + data[i + 1]
                else:
                    s += data[i] << 8
            s = (s >> 16) + (s & 0xFFFF)
            s += s >> 16
            return ~s & 0xFFFF

        ip_saddr   = socket.inet_aton("0.0.0.0")
        ip_daddr   = socket.inet_aton(ip)
        ip_header  = struct.pack(
            "!BBHHHBBH4s4s",
            0x45, 0, 0, 54321, 0, 64, socket.IPPROTO_TCP, 0, ip_saddr, ip_daddr
        )

        tcp_src    = 12345
        tcp_dst    = port
        tcp_offset = (5 << 4)
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            tcp_src, tcp_dst, 0, 0, tcp_offset, 0x002,
            socket.htons(5840), 0, 0
        )
        psh = struct.pack("!4s4sBBH", ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header))
        chk = checksum(psh + tcp_header)
        tcp_header = struct.pack(
            "!HHLLBBHHH",
            tcp_src, tcp_dst, 0, 0, tcp_offset, 0x002,
            socket.htons(5840), chk, 0
        )

        s.sendto(ip_header + tcp_header, (ip, 0))
        data, _ = s.recvfrom(1024)
        s.close()

        ip_hdr_len = (data[0] & 0xF) * 4
        tcp_data   = data[ip_hdr_len:]
        if len(tcp_data) >= 16:
            return struct.unpack("!H", tcp_data[14:16])[0]
    except:
        pass
    return None

def window_os_hint(window):
    if window is None:
        return None
    if window == 65535:
        return "🪟 Windows / 🍎 macOS"
    if window in (5840, 14600, 29200):
        return "🐧 Linux"
    if window == 8192:
        return "🪟 Windows (old)"
    return None

# ── port listesi ──────────────────────────────────────────────────────────────
DEFAULT_PORTS = {
    21:   ("FTP",       "📂"),
    22:   ("SSH",       "🔐"),
    23:   ("Telnet",    "📡"),
    25:   ("SMTP",      "📧"),
    53:   ("DNS",       "🌐"),
    80:   ("HTTP",      "🕸️ "),
    110:  ("POP3",      "📬"),
    139:  ("SMB",       "🗂️ "),
    143:  ("IMAP",      "📨"),
    443:  ("HTTPS",     "🔒"),
    445:  ("SMB",       "🗂️ "),
    3306: ("MySQL",     "🗄️ "),
    3389: ("RDP",       "🖥️ "),
    5900: ("VNC",       "👁️ "),
    8080: ("HTTP-ALT",  "🌍"),
    8443: ("HTTPS-ALT", "🔏"),
}

def build_port_map(extra_ports=None):
    port_map = dict(DEFAULT_PORTS)
    if extra_ports:
        for p in extra_ports:
            if p not in port_map:
                port_map[p] = ("CUSTOM", "🔌")
    return port_map

def scan_ports(ip, port_map, timeout=0.4):
    open_ports = []
    for port, (name, emoji) in port_map.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append((port, name, emoji))
    return open_ports

# ── banner grabbing ───────────────────────────────────────────────────────────
BANNER_PROBES = {
    21:   b"",
    22:   b"",
    23:   b"",
    25:   b"",
    80:   b"HEAD / HTTP/1.0\r\n\r\n",
    110:  b"",
    143:  b"",
    3306: b"",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
}

def grab_banner(ip, port, timeout=2.0):
    if port not in BANNER_PROBES:
        return None
    probe = BANNER_PROBES[port]
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if probe:
                s.sendall(probe)
            data = s.recv(256)
            line = data.decode("utf-8", errors="ignore").strip().splitlines()
            return line[0][:80] if line else None
    except:
        return None

# ── vulnerability hints ───────────────────────────────────────────────────────
VULN_HINTS = {
    23:   ("CRITICAL", "Telnet açık — şifresiz protokol, MITM riski"),
    21:   ("HIGH",     "FTP açık — plaintext kimlik doğrulama, anonim erişim olabilir"),
    3389: ("HIGH",     "RDP açık — brute-force ve BlueKeep (CVE-2019-0708) riski"),
    5900: ("HIGH",     "VNC açık — zayıf auth veya no-auth riski"),
    445:  ("HIGH",     "SMB açık — EternalBlue / MS17-010 riski"),
    139:  ("MEDIUM",   "NetBIOS açık — bilgi sızıntısı riski"),
    3306: ("MEDIUM",   "MySQL açık — internete maruz kalmamalı"),
    25:   ("LOW",      "SMTP açık — open relay kontrolü yapılmalı"),
    8080: ("LOW",      "HTTP-ALT açık — yönetim paneli olabilir"),
}

RISK_COLOR = {"CRITICAL": R, "HIGH": Y, "MEDIUM": M, "LOW": GR}

def get_vulns(open_ports):
    return [
        (level, msg, port)
        for port, _, _ in open_ports
        if port in VULN_HINTS
        for level, msg in [VULN_HINTS[port]]
    ]

# ── ping ──────────────────────────────────────────────────────────────────────
def ping(ip, timeout=1):
    try:
        return subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        ).returncode == 0
    except:
        return False

# ── OS tahmini: TTL + TCP window + port + hostname ───────────────────────────
def guess_os(open_ports, hostname, ttl, window):
    port_nums = [p for p, _, _ in open_ports]

    if 3389 in port_nums:
        return "🖥️  Windows PC (RDP)"
    if 5900 in port_nums:
        return "🖥️  Desktop (VNC)"

    if ttl and window:
        if ttl > 100 and window == 65535:
            return "🪟 Windows (TTL+Win)"
        if 50 < ttl <= 70 and window in (5840, 14600, 29200):
            return "🐧 Linux (TTL+Win)"
        if 50 < ttl <= 70 and window == 65535:
            return "🍎 macOS (TTL+Win)"

    if 22 in port_nums and 80 in port_nums:
        return ttl_os_hint(ttl) or "🐧 Linux Server"
    if 22 in port_nums:
        return ttl_os_hint(ttl) or "🐧 Linux/Unix"
    if 445 in port_nums or 139 in port_nums:
        return "🪟 Windows (SMB)"
    if 80 in port_nums or 443 in port_nums:
        return "📡 Web Device"

    if hostname:
        hn = hostname.lower()
        if "router" in hn or "gateway" in hn:
            return "📶 Router"
        if "android" in hn:
            return "📱 Android"
        if any(x in hn for x in ("iphone", "ipad", "apple")):
            return "🍎 Apple Device"

    return ttl_os_hint(ttl) or window_os_hint(window) or "❓ Unknown"

# ── tek host taraması ─────────────────────────────────────────────────────────
def scan_host(ip, my_ip, port_map, timeout, grab_banners=True):
    if not ping(ip):
        return None

    hostname = resolve_hostname(ip)
    mac      = get_mac(ip)
    ttl      = get_ttl(ip)
    ports    = scan_ports(ip, port_map, timeout=timeout)
    window   = tcp_window_hint(ip) if ports else None
    os_type  = guess_os(ports, hostname, ttl, window)
    vulns    = get_vulns(ports)
    banners  = {}

    if grab_banners:
        for port, _, _ in ports:
            b = grab_banner(ip, port)
            if b:
                banners[port] = b

    return {
        "ip":       ip,
        "hostname": hostname or "—",
        "mac":      mac or "—",
        "ports":    ports,
        "banners":  banners,
        "type":     os_type,
        "ttl":      ttl,
        "window":   window,
        "vulns":    vulns,
        "is_me":    (ip == my_ip),
    }

# ── cihaz kartı ───────────────────────────────────────────────────────────────
def print_device(dev, idx):
    sep     = f"{DG}  {'·' * (tw() - 4)}{RST}"
    me      = f"  {Y}◀ BU CİHAZ{RST}" if dev["is_me"] else ""
    ttl_str = str(dev["ttl"]) if dev["ttl"] else "—"
    win_str = str(dev["window"]) if dev["window"] else "—"

    print(sep)
    print(f"  {B}{G}[{idx:02d}]{RST}  {B}{W}{dev['ip']}{RST}{me}")
    print(f"  {DG}┌{RST}  🏷️  {GR}{dev['hostname']}{RST}")
    print(f"  {DG}├{RST}  🔌  {GR}{dev['mac']}{RST}")
    print(f"  {DG}├{RST}  ⏱️  TTL: {C}{ttl_str}{RST}  │  TCP Win: {C}{win_str}{RST}")
    print(f"  {DG}├{RST}  {dev['type']}")

    for port, name, emoji in dev["ports"]:
        banner_txt = dev["banners"].get(port, "")
        b_str = f"  {DIM}» {banner_txt[:60]}{RST}" if banner_txt else ""
        print(f"  {DG}│{RST}  🔓  {emoji} {C}{port}{RST}/{GR}{name}{RST}{b_str}")

    if dev["vulns"]:
        print(f"  {DG}│{RST}")
        for level, msg, port in dev["vulns"]:
            col = RISK_COLOR.get(level, GR)
            print(f"  {DG}│{RST}  {col}⚠  [{level}] {msg} (:{port}){RST}")

    if not dev["ports"]:
        print(f"  {DG}└{RST}  🔒  {DG}Açık port bulunamadı{RST}")
    else:
        print(f"  {DG}└{'─' * 2}{RST}")
    print()

# ── özet ──────────────────────────────────────────────────────────────────────
def print_summary(devices, elapsed, subnet):
    w = tw()
    print(f"{DG}{'═' * w}{RST}")
    print(f"\n  {B}{Y}!!  TARAMA TAMAMLANDI{RST}\n")
    print(f"  {DG}Subnet:  {RST}{C}{subnet}{RST}")
    print(f"  {DG}Süre:    {RST}{C}{elapsed:.1f}s{RST}")
    print(f"  {DG}Bulunan: {RST}{G}{B}{len(devices)} cihaz{RST}")

    all_ports = [p for d in devices for p in d["ports"]]
    if all_ports:
        print(f"\n  {B}Açık servisler:{RST}")
        for name, cnt in Counter(n for _, n, _ in all_ports).most_common():
            print(f"  {DG}  {name:<12}{RST} {G}{'█' * cnt}{RST} {DIM}{cnt}{RST}")

    all_vulns = [v for d in devices for v in d["vulns"]]
    if all_vulns:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        print(f"\n  {B}Risk özeti:{RST}")
        for level, msg, port in sorted(all_vulns, key=lambda x: order.index(x[0])):
            col = RISK_COLOR.get(level, GR)
            print(f"  {col}  ⚠  [{level}] {msg}{RST}")

    print(f"\n{DG}{'═' * w}{RST}\n")

# ── export ────────────────────────────────────────────────────────────────────
def export_results(devices, elapsed, subnet, path, fmt):
    try:
        if fmt == "json":
            data = {
                "scan_time": datetime.now().isoformat(),
                "subnet":    subnet,
                "elapsed":   round(elapsed, 2),
                "devices": [{
                    "ip": d["ip"], "hostname": d["hostname"], "mac": d["mac"],
                    "os": d["type"], "ttl": d["ttl"], "tcp_window": d["window"],
                    "ports": [{"port": p, "name": n, "banner": d["banners"].get(p)} for p, n, _ in d["ports"]],
                    "vulns": [{"level": lv, "msg": msg, "port": po} for lv, msg, po in d["vulns"]],
                } for d in devices]
            }
            with open(path, "w") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        elif fmt == "csv":
            with open(path, "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["ip","hostname","mac","os","ttl","tcp_window","open_ports","vulns"])
                for d in devices:
                    w.writerow([
                        d["ip"], d["hostname"], d["mac"], d["type"], d["ttl"], d["window"],
                        "|".join(f"{p}/{n}" for p,n,_ in d["ports"]),
                        "|".join(f"[{lv}]{msg}" for lv,msg,_ in d["vulns"]),
                    ])

        else:
            with open(path, "w") as f:
                f.write(f"NET RECON — {datetime.now()}\n")
                f.write(f"Subnet: {subnet} | Süre: {elapsed:.1f}s | Bulunan: {len(devices)}\n\n")
                for d in devices:
                    f.write(f"{d['ip']}\t{d['hostname']}\t{d['mac']}\t{d['type']}\tTTL:{d['ttl']}\n")
                    for p, n, _ in d["ports"]:
                        b = d["banners"].get(p, "")
                        f.write(f"  → {p}/{n}" + (f"  [{b}]" if b else "") + "\n")
                    for lv, msg, po in d["vulns"]:
                        f.write(f"  ⚠ [{lv}] {msg} (:{po})\n")
                    f.write("\n")
        return True
    except Exception as e:
        print(f"  {R}Export hatası: {e}{RST}\n")
        return False

# ── argparse ──────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="NET RECON — by laxent")
    p.add_argument("-t", "--timeout",  type=float, default=0.4,   help="Port timeout (s, default: 0.4)")
    p.add_argument("-w", "--workers",  type=int,   default=64,    help="Thread sayısı (default: 64)")
    p.add_argument("-p", "--ports",    type=int, nargs="+",       help="Ekstra portlar (-p 8888 9090)")
    p.add_argument("-s", "--subnet",   type=str, default=None,    help="Manuel subnet (192.168.1.0/24)")
    p.add_argument("-o", "--output",   type=str, default=None,    help="Çıktı dosyası (-o out.json)")
    p.add_argument("-f", "--format",   type=str, default="txt",
                   choices=["txt","json","csv"],                   help="Çıktı formatı (default: txt)")
    p.add_argument("--no-banner",      action="store_true",       help="Banner grabbing kapalı")
    return p.parse_args()

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    banner(args)

    sp = Spinner("Yerel ağ bilgileri alınıyor...").start()
    time.sleep(0.5)
    my_ip, auto_subnet = get_local_info(args.subnet)
    subnet = args.subnet or auto_subnet
    sp.stop(f"  {G}✔{RST}  {C}{my_ip}{RST}  →  {Y}{subnet}{RST}\n")

    try:
        hosts = [str(h) for h in ipaddress.IPv4Network(subnet, strict=False).hosts()]
    except ValueError as e:
        print(f"  {R}Geçersiz subnet: {e}{RST}\n")
        return

    port_map = build_port_map(args.ports)
    grab     = not args.no_banner

    print(f"  {DIM}{len(hosts)} adres  |  {len(port_map)} port  |  {args.workers} worker  |  "
          f"timeout {args.timeout}s  |  banner {'ON' if grab else 'OFF'}{RST}\n")
    time.sleep(0.3)
    print(f"  {C}Tarama başlıyor...{RST}\n")

    start_time = time.time()
    devices    = []
    completed  = 0
    bar_width  = tw() - 20

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {
            ex.submit(scan_host, ip, my_ip, port_map, args.timeout, grab): ip
            for ip in hosts
        }
        for future in as_completed(futures):
            completed += 1
            ip  = futures[future]
            pct = completed / len(hosts)
            done = int(pct * bar_width)
            bar  = f"{G}{'━' * done}{DG}{'╌' * (bar_width - done)}{RST}"
            print(f"\r  {bar} {Y}{int(pct*100):3d}%{RST}  {DG}{ip}{RST}   ", end="", flush=True)

            result = future.result()
            if result:
                with lock:
                    devices.append(result)
                clear_line()
                vf = f"  {R}⚠{RST}" if result["vulns"] else ""
                print(f"  {G}⬡{RST}  {B}{result['ip']:<15}{RST}  {result['type']}{vf}  {G}+{RST}")

    elapsed = time.time() - start_time
    clear_line()
    print(f"\n  {G}✔{RST}  Tamamlandı🔎  {DIM}({elapsed:.1f}s){RST}\n")
    time.sleep(0.3)

    if not devices:
        print(f"  {R}Cihaz bulunamadı.{RST}\n")
        return

    devices.sort(key=lambda d: (not d["is_me"], list(map(int, d["ip"].split(".")))))

    print(f"\n  {B}{W}── CİHAZ DETAYLARI ──{RST}\n")
    for i, dev in enumerate(devices, 1):
        print_device(dev, i)

    print_summary(devices, elapsed, subnet)

    if args.output:
        if export_results(devices, elapsed, subnet, args.output, args.format):
            print(f"  {G}✔{RST}  {args.format.upper()} kaydedildi: {C}{args.output}{RST}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Y}⚠{RST}  Durduruldu.\n")
