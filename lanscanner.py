import os
import time
import socket
import subprocess
import struct
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ── ANSI renk kodları ─────────────────────────────────────────────────────────
R  = "\033[38;5;196m"
G  = "\033[38;5;82m"
Y  = "\033[38;5;226m"
C  = "\033[38;5;51m"
M  = "\033[38;5;201m"
DG = "\033[38;5;238m"
GR = "\033[38;5;245m"
W  = "\033[97m"
B  = "\033[1m"
DIM = "\033[2m"
RST = "\033[0m"

FOUND = []
lock  = threading.Lock()

# safamfoenfkdf
def tw():
    try:
        return os.get_terminal_size().columns
    except:
        return 80

# 
def clear_line():
    print(f"\r{' ' * tw()}\r", end="", flush=True)

# banner
def banner():
    os.system("clear")
    width = tw()
    now   = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

    top = f"{DG}{'─' * width}{RST}"
    print(top)
    title = f"{B}{C}  ◈  NET RECON  ◈{RST}"
    print(title)
    print(f"{DG}  scanner by laxent🔎  {GR}{now}{RST}")
    print(top)
    print()

# spinner
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

# yeerl ip ve subnet testi
def get_local_info():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()

    parts = ip.split(".")
    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ip, subnet

# ----  hostname çözümle
def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

#MAC adresi al (Linux: arp) 
def get_mac(ip):
    try:
        out = subprocess.check_output(
            ["arp", "-n", ip],
            stderr=subprocess.DEVNULL
        ).decode()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == ip:
                mac = parts[2]
                if ":" in mac or "-" in mac:
                    return mac.upper()
    except:
        pass
    return None

# temel port taraması
COMMON_PORTS = {
    21:  ("FTP",     "📂"),
    22:  ("SSH",     "🔐"),
    23:  ("Telnet",  "📡"),
    25:  ("SMTP",    "📧"),
    53:  ("DNS",     "🌐"),
    80:  ("HTTP",    "🕸️ "),
    110: ("POP3",    "📬"),
    139: ("SMB",     "🗂️ "),
    143: ("IMAP",    "📨"),
    443: ("HTTPS",   "🔒"),
    445: ("SMB",     "🗂️ "),
    3306:("MySQL",   "🗄️ "),
    3389:("RDP",     "🖥️ "),
    5900:("VNC",     "👁️ "),
    8080:("HTTP-ALT","🌍"),
    8443:("HTTPS-ALT","🔏"),
}

def scan_ports(ip, timeout=0.4):
    open_ports = []
    for port, (name, emoji) in COMMON_PORTS.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append((port, name, emoji))
            s.close()
        except:
            pass
    return open_ports

# paket gönderimi (ping)
def ping(ip, timeout=1):
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except:
        return False

# cihaz tipi tahmin etme (%100 değil)
def guess_device(open_ports, hostname):
    port_nums = [p for p, _, _ in open_ports]
    if 3389 in port_nums:
        return "🖥️  Windows PC"
    if 5900 in port_nums:
        return "🖥️  Desktop (VNC)"
    if 22 in port_nums and 80 in port_nums:
        return "🐧 Linux Server"
    if 22 in port_nums:
        return "🐧 Linux/Unix"
    if 445 in port_nums or 139 in port_nums:
        return "🪟 Windows Device"
    if 80 in port_nums or 443 in port_nums:
        return "📡 Web Device"
    if hostname and ("router" in hostname.lower() or "gateway" in hostname.lower()):
        return "📶 Router"
    if hostname and "android" in hostname.lower():
        return "📱 Android"
    if hostname and ("iphone" in hostname.lower() or "ipad" in hostname.lower() or "apple" in hostname.lower()):
        return "🍎 Apple Device"
    return "❓ Unknown"

# tek IP taraması
def scan_host(ip, my_ip):
    if not ping(ip):
        return None

    hostname  = resolve_hostname(ip)
    mac       = get_mac(ip)
    ports     = scan_ports(ip)
    dev_type  = guess_device(ports, hostname)
    is_me     = (ip == my_ip)

    return {
        "ip":       ip,
        "hostname": hostname or "—",
        "mac":      mac or "—",
        "ports":    ports,
        "type":     dev_type,
        "is_me":    is_me,
    }

# cihaz kartı yazdır
def print_device(dev, idx):
    sep  = f"{DG}  {'·' * (tw() - 4)}{RST}"
    me   = f"  {Y}◀ BU CİHAZ{RST}" if dev["is_me"] else ""

    print(sep)
    print(f"  {B}{G}[{idx:02d}]{RST}  {B}{W}{dev['ip']}{RST}{me}")
    print(f"  {DG}┌{RST}  🏷️  {GR}{dev['hostname']}{RST}")
    print(f"  {DG}├{RST}  🔌  {GR}{dev['mac']}{RST}")
    print(f"  {DG}├{RST}  {dev['type']}")

    if dev["ports"]:
        port_strs = []
        for port, name, emoji in dev["ports"]:
            port_strs.append(f"{emoji} {C}{port}{RST}/{GR}{name}{RST}")
        print(f"  {DG}└{RST}  🔓  " + "  ".join(port_strs))
    else:
        print(f"  {DG}└{RST}  🔒  {DG}Açık port bulunamadı{RST}")

    print()

# loglama 
def print_summary(devices, elapsed, subnet):
    w = tw()
    print(f"{DG}{'═' * w}{RST}")
    print(f"\n  {B}{Y}!!  TARAMA TAMAMLANDI{RST}\n")
    print(f"  {DG}Subnet:   {RST}{C}{subnet}{RST}")
    print(f"  {DG}Süre:     {RST}{C}{elapsed:.1f}s{RST}")
    print(f"  {DG}Bulunan:  {RST}{G}{B}{len(devices)} cihaz{RST}")

    all_ports = []
    for d in devices:
        all_ports.extend(d["ports"])

    if all_ports:
        print(f"\n  {B}Açık servisler:{RST}")
        from collections import Counter
        counts = Counter(name for _, name, _ in all_ports)
        for name, cnt in counts.most_common():
            bar = "█" * cnt
            print(f"  {DG}  {name:<10}{RST} {G}{bar}{RST} {DIM}{cnt}{RST}")

    print(f"\n{DG}{'═' * w}{RST}\n")

# main.py
def main():
    banner()

    sp = Spinner("Yerel ağ bilgileri alınıyor...").start()
    time.sleep(0.6)
    my_ip, subnet = get_local_info()
    sp.stop(f"  {G}✔{RST}  Ağ tespit edildi  {C}{my_ip}{RST}  →  {Y}{subnet}{RST}\n")

    hosts = [str(h) for h in __import__("ipaddress").IPv4Network(subnet, strict=False).hosts()]

    print(f"  {DIM}Toplam {len(hosts)} adres taranacak /\ paralel mod [+]{RST}\n")
    time.sleep(0.4)

    # tarama emin olmak için 
    found_count = 0
    start_time  = time.time()

    print(f"  {C}Ping taraması başlıyor...{RST}\n")

    completed = 0
    bar_width  = tw() - 20

    devices = []

    with ThreadPoolExecutor(max_workers=64) as ex:
        futures = {ex.submit(scan_host, ip, my_ip): ip for ip in hosts}

        for future in as_completed(futures):
            completed += 1
            ip = futures[future]

            # ileeme
            pct  = completed / len(hosts)
            done = int(pct * bar_width)
            bar  = f"{G}{'━' * done}{DG}{'╌' * (bar_width - done)}{RST}"
            pct_str = f"{int(pct*100):3d}%"
            print(f"\r  {bar} {Y}{pct_str}{RST}  {DG}{ip}{RST}   ", end="", flush=True)

            result = future.result()
            if result:
                with lock:
                    devices.append(result)
                    found_count += 1
                clear_line()
                print(f"  {G}⬡{RST}  {B}{result['ip']:<15}{RST}  {result['type']}  {G}+{RST}")

    elapsed = time.time() - start_time
    clear_line()

    print(f"\n  {G}✔{RST}  Tarama tamamlandı🔎  {DIM}({elapsed:.1f}s){RST}\n")
    time.sleep(0.3)

    if not devices:
        print(f"  {R}Hiçbir cihaz bulunamadı.🔎{RST}\n")
        return

    # kendi ip adressin
    devices.sort(key=lambda d: (not d["is_me"], d["ip"]))

    print(f"\n  {B}{W}── CİHAZ DETAYLARI (sonuclar) ──{RST}\n")
    for i, dev in enumerate(devices, 1):
        print_device(dev, i)

    print_summary(devices, elapsed, subnet)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Y}⚠{RST}  Tarama kullanıcı tarafından durduruldu.\n")

# BUARDA KODU ÇALIŞTIRMAK İÇİN SUDO GEREKLİ YOKSA EKSİK TARAMA YAPAR.!!
