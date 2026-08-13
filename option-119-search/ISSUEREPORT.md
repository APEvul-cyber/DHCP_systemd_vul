# DHCP Option 119 must not silently override pinned search domains

Rogue DHCPACK with Option 119 (Option 6 left legit) makes systemd-resolved append attacker suffixes to short names.

Same trust failure as TunnelVision / Option 121.

## Reproduce

`rogue_dns_search.py`.

**Expected:** `UseDomains=no` or a pin that DHCP cannot replace.

https://github.com/APEvul-cyber/DHCP_systemd_vul/tree/main/option-119-search
