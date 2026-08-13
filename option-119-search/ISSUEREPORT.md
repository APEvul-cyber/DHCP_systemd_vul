# networkd applies DHCP Option 119 with no pin

RFC 3397 search domains from a rogue DHCPACK are stored and given to systemd-resolved. DNS server (Option 6) can stay legit.

This is unauthenticated DHCP, same class as CVE-2024-3661 (Option 121). A `Domains=` pin that ignores DHCP search would be the hardening.

PoC: `rogue_dns_search.py`.