import os
import time
import socket
import subprocess
import threading
import json
import csv
import argparse
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import IPv4Network

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

lock = threading.Lock()

def tw():
    try:
        return os.get_terminal_size().columns
    except:
        return 80

def clear_line():
    print(f"\r{' ' * tw()}\r", end="", flush=True)

def banner():
    os.system("clear")
    width = tw()
    now = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    top = f"{DG}{'─' * width}{RST}"
    print(top)
    print(f"{B}{C}  ◈  NET RECON  ◈{RST}")
    print(f"{DG}  scanner by laxent  {GR}{now}{RST}")
    print(top)
    print()

SPIN_FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

class Spinner:
    def __init__(self, msg=""):
        self.msg = msg
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

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

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None

def get_mac(ip):
    system = os.name
    try:
        if system == "nt":
            out = subprocess.check_output(["arp", "-a", ip], stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == ip:
                    mac = parts[1]
                    if "-" in mac or ":" in mac:
                        return mac.upper()
        else:
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

COMMON_PORTS = {
    21:  ("FTP",     "FTP"),
    22:  ("SSH",     "SSH"),
    23:  ("Telnet",  "TEL"),
    25:  ("SMTP",    "SMTP"),
    53:  ("DNS",     "DNS"),
    80:  ("HTTP",    "HTTP"),
    110: ("POP3",    "POP3"),
    139: ("SMB",     "SMB"),
    143: ("IMAP",    "IMAP"),
    443: ("HTTPS",   "HTTPS"),
    445: ("SMB",     "SMB"),
    3306:("MySQL",   "SQL"),
    3389:("RDP",     "RDP"),
    5900:("VNC",     "VNC"),
    8080:("HTTP-ALT","HTTP2"),
    8443:("HTTPS-ALT","HTTPS2"),
}

def grab_banner(ip, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        # Many services (SSH, FTP, SMTP) send banner immediately on connect
        try:
            banner_data = s.recv(1024).decode("utf-8", errors="ignore").strip()
        except socket.timeout:
            banner_data = ""
        # If passive recv got nothing, nudge with CRLF (HTTP etc.)
        if not banner_data:
            s.send(b"\r\n")
            try:
                banner_data = s.recv(1024).decode("utf-8", errors="ignore").strip()
            except socket.timeout:
                banner_data = ""
        s.close()
        return banner_data[:200] if banner_data else None
    except:
        return None

def scan_ports(ip, timeout=0.4):
    open_ports = []
    for port, (name, label) in COMMON_PORTS.items():
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                banner = grab_banner(ip, port)
                open_ports.append((port, name, label, banner))
        except:
            pass
        finally:
            if s:
                s.close()
    return open_ports

def tcp_probe(ip, port=80, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        s.close()
        return result == 0
    except:
        return False

def ping(ip, timeout=1):
    system = os.name
    try:
        if system == "nt":
            result = subprocess.run(
                ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", str(timeout), ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except:
        return False

def guess_device(open_ports, hostname):
    port_nums = [p for p, _, _, _ in open_ports]
    if 3389 in port_nums:
        return "[WIN-PC] Windows PC"
    if 5900 in port_nums:
        return "[VNC] Desktop (VNC)"
    if 22 in port_nums and 80 in port_nums:
        return "[LNX] Linux Server"
    if 22 in port_nums:
        return "[LNX] Linux/Unix"
    if 445 in port_nums or 139 in port_nums:
        return "[WIN] Windows Device"
    if 80 in port_nums or 443 in port_nums:
        return "[WEB] Web Device"
    if hostname and ("router" in hostname.lower() or "gateway" in hostname.lower()):
        return "[NET] Router"
    if hostname and "android" in hostname.lower():
        return "[MOB] Android"
    if hostname and ("iphone" in hostname.lower() or "ipad" in hostname.lower() or "apple" in hostname.lower()):
        return "[APL] Apple Device"
    return "[???] Unknown"

def scan_host(ip, my_ip, use_tcp_probe=False):
    alive = ping(ip)
    if not alive and use_tcp_probe:
        alive = tcp_probe(ip)
    if not alive:
        return None
    hostname = resolve_hostname(ip)
    mac = get_mac(ip)
    ports = scan_ports(ip)
    dev_type = guess_device(ports, hostname)
    is_me = (ip == my_ip)
    return {
        "ip":       ip,
        "hostname": hostname or "—",
        "mac":      mac or "—",
        "ports":    ports,
        "type":     dev_type,
        "is_me":    is_me,
    }

def print_device(dev, idx):
    sep = f"{DG}  {'·' * (tw() - 4)}{RST}"
    me = f"  {Y}< BU CIHAZ{RST}" if dev["is_me"] else ""
    print(sep)
    print(f"  {B}{G}[{idx:02d}]{RST}  {B}{W}{dev['ip']}{RST}{me}")
    print(f"  {DG}+--{RST}  hostname: {GR}{dev['hostname']}{RST}")
    print(f"  {DG}+--{RST}  mac:      {GR}{dev['mac']}{RST}")
    print(f"  {DG}+--{RST}  type:     {dev['type']}")
    if dev["ports"]:
        port_strs = []
        for port, name, label, banner in dev["ports"]:
            banner_info = f" {DIM}[{banner[:60]}]{RST}" if banner else ""
            port_strs.append(f"{C}{port}{RST}/{GR}{name}{RST}{banner_info}")
        print(f"  {DG}+--{RST}  ports:    " + "  ".join(port_strs))
    else:
        print(f"  {DG}+--{RST}  ports:    {DG}No open ports found{RST}")
    print()

def print_summary(devices, elapsed, subnet):
    w = tw()
    print(f"{DG}{'=' * w}{RST}")
    print(f"\n  {B}{Y}SCAN COMPLETE{RST}\n")
    print(f"  {DG}Subnet:  {RST}{C}{subnet}{RST}")
    print(f"  {DG}Time:    {RST}{C}{elapsed:.1f}s{RST}")
    print(f"  {DG}Found:   {RST}{G}{B}{len(devices)} devices{RST}")
    all_ports = []
    for d in devices:
        all_ports.extend(d["ports"])
    if all_ports:
        print(f"\n  {B}Open services:{RST}")
        from collections import Counter
        counts = Counter(name for _, name, _, _ in all_ports)
        for name, cnt in counts.most_common():
            bar = "#" * cnt
            print(f"  {DG}  {name:<12}{RST} {G}{bar}{RST} {DIM}{cnt}{RST}")
    print(f"\n{DG}{'=' * w}{RST}\n")

def save_json(devices, filename):
    clean = []
    for d in devices:
        clean.append({
            "ip": d["ip"],
            "hostname": d["hostname"],
            "mac": d["mac"],
            "type": d["type"],
            "is_me": d["is_me"],
            "ports": [
                {"port": p, "service": n, "banner": b}
                for p, n, _, b in d["ports"]
            ]
        })
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=2, ensure_ascii=False)

def save_csv(devices, filename):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Hostname", "MAC", "Type", "Is_Me", "Port", "Service", "Banner"])
        for d in devices:
            if d["ports"]:
                for p, n, _, b in d["ports"]:
                    writer.writerow([d["ip"], d["hostname"], d["mac"], d["type"], d["is_me"], p, n, b or ""])
            else:
                writer.writerow([d["ip"], d["hostname"], d["mac"], d["type"], d["is_me"], "", "", ""])

def main():
    parser = argparse.ArgumentParser(description="Net Recon - Network Scanner")
    parser.add_argument("--subnet", help="Target subnet (e.g. 192.168.1.0/24)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Ping timeout (seconds)")
    parser.add_argument("--workers", type=int, default=64, help="Parallel worker count")
    parser.add_argument("--tcp-probe", action="store_true", help="TCP probe for non-ping hosts")
    parser.add_argument("--json", help="Save results to JSON")
    parser.add_argument("--csv", help="Save results to CSV")
    args = parser.parse_args()

    banner()

    sp = Spinner("Getting local network info...").start()
    time.sleep(0.6)
    my_ip, auto_subnet = get_local_info()
    subnet = args.subnet or auto_subnet
    sp.stop(f"  {G}OK{RST}  Network detected  {C}{my_ip}{RST}  ->  {Y}{subnet}{RST}\n")

    hosts = [str(h) for h in IPv4Network(subnet, strict=False).hosts()]
    print(f"  {DIM}Scanning {len(hosts)} addresses / parallel mode{RST}\n")
    time.sleep(0.4)

    start_time = time.time()
    print(f"  {C}Starting ping scan...{RST}\n")

    completed = 0
    bar_width = tw() - 20
    devices = []

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {ex.submit(scan_host, ip, my_ip, args.tcp_probe): ip for ip in hosts}
        for future in as_completed(futures):
            completed += 1
            ip = futures[future]
            pct = completed / len(hosts)
            done = int(pct * bar_width)
            bar = f"{G}{'=' * done}{DG}{'-' * (bar_width - done)}{RST}"
            pct_str = f"{int(pct*100):3d}%"
            print(f"\r  {bar} {Y}{pct_str}{RST}  {DG}{ip}{RST}   ", end="", flush=True)
            result = future.result()
            if result:
                with lock:
                    devices.append(result)
                clear_line()
                print(f"  {G}+{RST}  {B}{result['ip']:<15}{RST}  {result['type']}  {G}FOUND{RST}")

    elapsed = time.time() - start_time
    clear_line()
    print(f"\n  {G}OK{RST}  Scan complete  {DIM}({elapsed:.1f}s){RST}\n")
    time.sleep(0.3)

    if not devices:
        print(f"  {R}No devices found.{RST}\n")
        return

    devices.sort(key=lambda d: (not d["is_me"], d["ip"]))

    print(f"\n  {B}{W}-- DEVICE DETAILS --{RST}\n")
    for i, dev in enumerate(devices, 1):
        print_device(dev, i)

    print_summary(devices, elapsed, subnet)

    if args.json:
        save_json(devices, args.json)
        print(f"  {G}OK{RST}  JSON saved: {C}{args.json}{RST}\n")

    if args.csv:
        save_csv(devices, args.csv)
        print(f"  {G}OK{RST}  CSV saved: {C}{args.csv}{RST}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {Y}!{RST}  Scan stopped by user.\n")
