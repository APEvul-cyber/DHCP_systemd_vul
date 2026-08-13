# DHCP_systemd_vul

Option 119 search-domain injection is standard unauthenticated DHCP (same class as TunnelVision / Option 121). systemd-networkd applies it. There is no unique parser bug.

PoC kept under `option-119-search` for the lab. Not filed as a distinct CVE.