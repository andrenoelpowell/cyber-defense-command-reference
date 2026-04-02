  
## Wireshark Filters (One-Liners)

---
## Noise Reduction / Filtering Known Good

- exclude IPv6 traffic | `not ipv6`
- exclude TLS traffic | `not tls`
- exclude HTTPS port | `not tcp.port == 443`
- exclude SSDP | `not ssdp`
- exclude ARP | `not arp`
- exclude LLDP | `not lldp`
- exclude LLMNR | `not llmnr`
- exclude NetBIOS browser traffic | `not browser`
- exclude Dropbox LAN sync | `not db-lsp-disc`

- combined noise filter (lab baseline) | `!(ipv6 || tls || tcp.port==443 || ssdp || arp || lldp || llmnr || browser || db-lsp-disc)`  

## General

- filter by IP address | `ip.addr == 10.0.0.5`
- filter by source IP | `ip.src == 10.0.0.5`
- filter by destination IP | `ip.dst == 10.0.0.5`
- filter by subnet | `ip.addr == 10.0.0.0/24`

---

## Protocols

- HTTP traffic | `http`
- DNS traffic | `dns`
- ICMP (ping) | `icmp`
- TCP traffic | `tcp`
- UDP traffic | `udp`
- TLS traffic | `tls`

---

## Threat Hunting

- failed DNS queries (possible C2) | `dns.flags.rcode != 0`
- unusual ports (non-standard traffic) | `tcp.port not in {80 443 53}`
- large packets (possible exfil) | `frame.len > 1000`
- base64 indicator | `frame contains "=="`
- suspicious user-agent (curl/python) | `http.user_agent contains "curl" or http.user_agent contains "python"`
- detect DHCP starvation | dhcp.type == 1 + look for high rate requests + same src IP + rotating client MACs 

---

## Data Exfiltration

- large outbound traffic | `ip.dst != 10.0.0.0/24 && frame.len > 1000`
- netcat-like traffic | `tcp.port == 10000`

---

## ARP / Spoofing

- ARP traffic | `arp`
- duplicate ARP detection | `arp.duplicate-address-detected`
- gratuitous ARP | `arp.opcode == 2 && arp.src.proto_ipv4 == arp.dst.proto_ipv4`
- single MAC mapped to many IPs (manual pivot) | `arp.src.hw_mac == XX:XX:XX:XX:XX:XX`

---

## VLAN / Layer 2

- VLAN tagged traffic | `vlan`
- specific VLAN ID | `vlan.id == 530`
- double-tagged VLAN (VLAN hopping) | `vlan && vlan.inner_vlan_id`
- detect 802.1Q frames | `eth.type == 0x8100`

---

## TLS / Encryption

- TLS handshake | `tls.handshake`
- TLS SNI (domain) | `tls.handshake.extensions_server_name`
- JA3 fingerprint | `tls.handshake.ja3`
- certificate inspection | `tls.handshake.certificate`

---

## Payload Search

- search string in packets | `frame contains "password"`
- detect executable transfer (MZ header) | `frame contains "MZ"`
- base64 pattern match | `frame matches "[A-Za-z0-9+/=]{20,}"`

---

## Quick Combos

- possible DNS C2 | `dns && dns.flags.rcode != 0`
- possible data exfiltration | `frame.len > 1000 && tcp`
- possible ARP poisoning | `arp && arp.duplicate-address-detected`
- possible VLAN hopping | `vlan && vlan.inner_vlan_id`
