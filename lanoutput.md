```markdown
<h1 align="center">NET RECON</h1>

<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&size=20&pause=800&color=00FF9F&center=true&vCenter=true&width=600&lines=Network+Recon+Tool;LAN+Discovery+Scanner;Built+for+Cybersecurity+Labs" />
</p>

---

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-00ff9f?style=for-the-badge">
  <img src="https://img.shields.io/badge/Mode-Parallel_Scan-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Python-Tooling-yellow?style=for-the-badge">
  <img src="https://img.shields.io/badge/Network-192.168.1.0%2F24-red?style=for-the-badge">
</p>

---

## SYSTEM OVERVIEW

```

Scanner     : NET RECON
Timestamp   : 2026-05-02 07:19:10
Target Net  : 192.168.1.0/24
Source Host : 192.168.1.16
Mode        : Parallel Discovery
Duration    : 4.1s
Hosts Found : 4

```

---

## SCAN VISUALIZATION

```

[████████████████████████████████████████] 100% COMPLETE

```

---

## NETWORK MAP

| IP Address   | Hostname    | Type       | Status | Services          |
|--------------|-------------|------------|--------|------------------|
| 192.168.1.16 | kalilinux   | Local Host | Active | None             |
| 192.168.1.1  | unknown     | Gateway    | Active | DNS:53, HTTP:8080|
| 192.168.1.13 | blabla      | Node       | Active | HTTP:80          |
| 192.168.1.5  | honor-pad-8 | IoT Device | Idle   | None             |

---

## SERVICE MAP

```

DNS      █
HTTP     █
HTTP-ALT █

```

---

## DETAILED ANALYSIS

<details>
<summary>192.168.1.16 — Kali Linux (Local Host)</summary>

- Role: Scan origin  
- Hostname: kalilinux  
- Open Ports: None detected  
- Status: Stable  

</details>

<details>
<summary>192.168.1.1 — Gateway Device</summary>

- Services:
  - DNS (53)
  - HTTP (8080)  
- Role: Network gateway / management interface  

</details>

<details>
<summary>192.168.1.13 — HTTP Node</summary>

- Service:
  - HTTP (80)  
- Fingerprint: Unknown device signature  

</details>

<details>
<summary>192.168.1.5 — IoT Device</summary>

- Device: honor-pad-8  
- Open Ports: None detected  

</details>

---

## SUMMARY

- Network enumerated: 192.168.1.0/24  
- Active services detected: 3  
- Gateway identified: 1  
- IoT endpoint detected: 1  
- Scan mode: Parallel discovery  

---

## FOOTER

<p align="center">
  NET RECON • Cybersecurity Reconnaissance Utility
</p>
```

---
