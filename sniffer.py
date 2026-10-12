#!/usr/bin/env python3
"""
Usage:   sudo python3 detect.py [interface] [--block]
         --block drops sources that trigger a HIGH alert for 60 seconds with iptables.
Output:  suspicious.log
"""
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import sniff, get_if_addr, IP, TCP, UDP, ICMP, Raw

LOG = "suspicious.log"
WINDOW = 10            # seconds of history for rate-based rules
COOLDOWN = 30          # seconds before the same alert repeats
SCAN_PORTS = 15        # distinct ports in WINDOW -> port scan
BRUTE_TRIES = 8        # attempts at one login port in WINDOW
PING_FLOOD = 50        # pings in WINDOW
PING_SIZE = 200        # normal ping payload is ~56 bytes
BLOCK_SECONDS = 60
WHITELIST = {"192.168.80.1"}   # never blocked

BAD_FLAGS = {0x00: "NULL scan", 0x01: "FIN scan", 0x29: "Xmas scan",
             0x03: "SYN+FIN packet", 0x06: "SYN+RST packet"}
RISKY_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP", 445: "SMB", 3389: "RDP",
               4444: "Metasploit default", 6667: "IRC", 31337: "backdoor port"}
BRUTE_PORTS = {21, 22, 23}
SIGNATURES = {b"/etc/passwd": "directory traversal", b"union select": "SQL injection",
              b"<script": "cross-site scripting", b"cmd.exe": "command injection",
              b"sqlmap": "sqlmap scanner", b"nikto": "Nikto scanner"}

MY_IP = None
BLOCK = False
blocked = set()
last = {}
syns = defaultdict(deque)
pings = defaultdict(deque)


def log(msg):
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def alert(rule, src, why, level="HIGH"):
    now = time.time()
    if now - last.get((rule, src), 0) < COOLDOWN:
        return
    last[(rule, src)] = now
    log(f"[{level}] {rule} | src={src} | {why}")
    if BLOCK and level == "HIGH":
        block(src, rule)


def block(src, rule):
    if src in blocked or src in WHITELIST or src == MY_IP:
        return
    subprocess.run(["iptables", "-I", "INPUT", "-s", src, "-j", "DROP"])
    blocked.add(src)
    timer = threading.Timer(BLOCK_SECONDS, unblock, [src])
    timer.daemon = True
    timer.start()
    log(f"[ACTION] BLOCKED {src} for {BLOCK_SECONDS}s ({rule})")


def unblock(src):
    if src in blocked:
        subprocess.run(["iptables", "-D", "INPUT", "-s", src, "-j", "DROP"])
        blocked.discard(src)
        log(f"[ACTION] UNBLOCKED {src}")


def recent(dq, item, now):
    dq.append((now, item))
    while now - dq[0][0] > WINDOW:
        dq.popleft()
    return [i for _, i in dq]


def handle(pkt):
    if IP not in pkt:
        return
    src, now = pkt[IP].src, time.time()
    port = None   # destination port of a new connection, if this packet is one

    if TCP in pkt:
        flags, dport = int(pkt[TCP].flags), pkt[TCP].dport
        if flags in BAD_FLAGS:
            alert(BAD_FLAGS[flags], src, f"abnormal TCP flags sent to port {dport}")
        if flags & 0x12 == 0x02:   # SYN without ACK
            port = dport
            ports = recent(syns[src], port, now)
            if len(set(ports)) >= SCAN_PORTS:
                alert("Port scan", src, f"{len(set(ports))} ports in {WINDOW}s")
            if port in BRUTE_PORTS and ports.count(port) >= BRUTE_TRIES:
                alert(f"Brute force port {port}", src, f"{ports.count(port)} attempts in {WINDOW}s")

    elif UDP in pkt:
        port = pkt[UDP].dport

    elif ICMP in pkt and pkt[ICMP].type == 8:
        size = len(bytes(pkt[ICMP].payload))
        if size > PING_SIZE:
            alert("Oversized ping", src, f"{size} byte payload", "MEDIUM")
        count = len(recent(pings[src], None, now))
        if count >= PING_FLOOD:
            alert("Ping flood", src, f"{count} pings in {WINDOW}s")

    if port in RISKY_PORTS:
        alert(f"Risky port {port}", src, RISKY_PORTS[port], "MEDIUM")

    if Raw in pkt:
        data = bytes(pkt[Raw].load).lower()
        for sig, why in SIGNATURES.items():
            if sig in data:
                alert(f"Payload: {why}", src, f"matched {sig.decode()}")


def main():
    global MY_IP, BLOCK
    BLOCK = "--block" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    iface = args[0] if args else "ens33"
    MY_IP = get_if_addr(iface)
    print(f"Watching {iface} ({MY_IP}){' with blocking' if BLOCK else ''}. Ctrl+C to stop.")
    try:
        sniff(iface=iface, filter=f"dst host {MY_IP}", prn=handle, store=False)
    finally:
        for src in list(blocked):
            unblock(src)


if __name__ == "__main__":
    main()
