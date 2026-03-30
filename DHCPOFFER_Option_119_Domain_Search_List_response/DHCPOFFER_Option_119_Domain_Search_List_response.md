# systemd-networkd: DNS Search Domain Hijacking via DHCP Option 119

## 1. Summary

systemd-networkd unconditionally accepts and applies DNS search domains provided via DHCP Option 119 (Domain Search List, RFC 3397). A rogue DHCP server on the same Layer 2 segment can inject attacker-controlled domain search suffixes into the system resolver configuration. Once applied, all short/relative hostname lookups are appended with the attacker's domain suffixes, redirecting them to attacker-controlled infrastructure.

This differs from DNS server hijacking (Option 6) in that:
- The DNS server IP remains unchanged
- Only bare/short hostnames are affected (FQDNs are unaffected)
- DHCP monitoring tools that check for rogue DNS servers typically do not check for search domain changes

Verified on systemd-networkd 255 (Ubuntu 24.04). The malicious search domains appear in lease files, `networkctl status` output, and are fed to systemd-resolved.

## 2. Affected Software

| Software | Version Tested | Result |
|----------|---------------|--------|
| **systemd-networkd** | 255 (Ubuntu 24.04) | Malicious search domains stored in lease file, visible in `networkctl status`, fed to systemd-resolved |

All versions of systemd-networkd that implement RFC 3397 (Option 119) are expected to be affected.

## 3. Vulnerability Details

### 3.1 Attack Flow

1. Victim's systemd-networkd sends a broadcast DHCPREQUEST (e.g., during REBINDING or initial configuration)
2. Attacker on the same L2 segment responds with a forged DHCPACK containing:
   - Option 119 with attacker-controlled search domains (e.g., `corp.evil.com`, `evil.internal`)
   - Option 6 set to the **legitimate** DNS server IP (unchanged, to avoid detection)
3. systemd-networkd stores the search domains in its lease file
4. systemd-resolved receives the search domains and applies them to the system resolver
5. All short hostname lookups now append the attacker's domain suffixes

### 3.2 Distinction from CVE-2020-7461

CVE-2020-7461 is a heap buffer overflow in FreeBSD's dhclient when parsing Option 119 — a memory safety bug. This report describes a different issue: systemd-networkd correctly parses Option 119 per RFC 3397, but unconditionally trusts the search domains from an unauthenticated DHCP response.

### 3.3 Relation to CVE-2024-3661 (TunnelVision)

CVE-2024-3661 demonstrated DHCP Option 121 (Classless Static Routes) injection to bypass VPN tunnels. This is the same attack class — unauthenticated DHCP option injection — but targets a different option (119 vs 121), a different attack surface (DNS resolution vs routing), and achieves a different impact (search domain hijack vs VPN decloak).

## 4. Verified Results

### Test Environment

- Rogue DHCP server: Scapy (Python 3) on shared L2 segment (Docker bridge 10.100.0.0/24)
- Injected Option 119 domains: `corp.evil.com`, `evil.internal`
- Option 119 wire encoding (RFC 1035): `04636f7270046576696c03636f6d00046576696c08696e7465726e616c00`

### systemd-networkd 255 Output

```
$ networkctl status eth0
  Search Domains: legit.local
                  corp.evil.com
                  evil.internal
  DNS: 10.100.0.2
```

Lease file:
```
DOMAIN_SEARCH_LIST=corp.evil.com evil.internal
```

systemd-networkd accepted the Option 119 domains, stored them in the lease file, and fed them to the resolver. The DNS server IP (Option 6) remained legitimate.

### Cross-Client Verification

The same attack was also verified on:

| Client | Version | Result |
|--------|---------|--------|
| BusyBox udhcpc | 1.36.1 | `resolv.conf`: `search corp.evil.com evil.internal` |
| ISC dhclient | 4.4.3-P1 | `resolv.conf`: `search corp.evil.com. evil.internal.` |

## 5. Security Impact

- All short hostname lookups (`intranet`, `mail`, `wiki`, `git`) resolve via attacker-controlled domains
- The effect persists for the entire DHCP lease duration
- Every application relying on the system resolver is affected — browsers, CLI tools, APIs, service discovery
- The DNS server IP is unchanged, making this harder to detect than Option 6 hijacking

## 6. Suggested Mitigations

1. **Search domain change notification**: When DHCP-provided search domains change during lease renewal or rebinding, log a warning or notify the administrator
2. **Search domain pinning**: Provide a configuration option to lock search domains (e.g., via `Domains=` in `.network` files) and ignore DHCP-provided values when pinned
3. **Search domain validation**: Optionally validate that DHCP-provided search domains are within a configured set of trusted organizational domains
4. **Logging**: Ensure Option 119 processing is logged at a visible level for forensic analysis

## 7. Reproduction

### Steps

```bash
docker compose up -d

docker cp DHCPOFFER_Option_119_Domain_Search_List_response/rogue_dns_search.py \
    rogue-dhcp-server:/poc/

docker exec rogue-dhcp-server bash -c \
    'cd /poc && python3 rogue_dns_search.py 30 10.100.0.2 52' &
sleep 3

docker exec client-systemd bash -c \
    'mkdir -p /run/systemd/netif/links /run/systemd/netif/leases && \
     chmod -R 777 /run/systemd/netif && \
     systemd-networkd &' 
sleep 10

docker exec client-systemd networkctl status eth0
# Expected: Search Domains include corp.evil.com, evil.internal
```

### Files

| File | Description |
|------|-------------|
| `rogue_dns_search.py` | Scapy-based rogue DHCP server injecting Option 119 |
| `run_poc.sh` | Orchestration script |
| `logs/dhcp_client-systemd.log` | systemd-networkd client output |
| `logs/rogue_client-systemd.log` | Rogue server log for systemd test |
| `logs/opt119_client-systemd.pcap` | Packet capture |

## 8. References

- RFC 2131: Dynamic Host Configuration Protocol
- RFC 3397: Dynamic Host Configuration Protocol (DHCP) Domain Search Option
- RFC 1035: Domain Names — Implementation and Specification
- CVE-2020-7461: FreeBSD dhclient Option 119 heap overflow (different vulnerability class)
- CVE-2024-3661: TunnelVision — DHCP Option 121 routing injection (same attack class, different option)
