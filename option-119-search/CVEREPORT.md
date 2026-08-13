# systemd-networkd applies DHCP Option 119 search domains from a rogue server

**Affected:** systemd-networkd + systemd-resolved (Option 119 / RFC 3397).  
**CWE:** CWE-345

A DHCPACK can carry Domain Search (Option 119) while Option 6 stays the real resolver. networkd stores the search list; resolved appends those suffixes to short names.

Same class as TunnelVision (CVE-2024-3661, Option 121): unauthenticated DHCP is a trust boundary. Clients apply it. Attackers on L2 use it. That is the CVE.

**Impact:** `intranet` / `vpn` / `mail` resolve under the attacker suffix. Monitoring that only watches Option 6 misses it.

## Reproduce

`rogue_dns_search.py` on the same L2 as the client.

**Actual:** search domains from the rogue ACK are used.  
**Expected:** ignore DHCP search unless pinned; or require `Domains=` that DHCP cannot override.

## Fix

Add a pin (`Domains=` / `UseDomains=no`) that DHCP cannot replace. Treat Option 119 like Option 121: untrusted on open L2.

## References

- RFC 3397
- CVE-2024-3661 (Option 121)
- https://github.com/APEvul-cyber/DHCP_systemd_vul/tree/main/option-119-search
