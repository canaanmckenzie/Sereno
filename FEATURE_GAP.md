# Sereno vs Little Snitch Feature Gap Analysis

## Current Status Legend
- **DONE** = Implemented and working
- **PARTIAL** = Partially implemented
- **TODO** = Not yet implemented
- **N/A** = Not applicable to Windows

---

## Core Firewall Functionality

| Feature | Little Snitch | Sereno | Status |
|---------|---------------|--------|--------|
| Outgoing TCP filtering | Yes | Yes (ALE layer) | **DONE** |
| Outgoing UDP monitoring | Yes | Yes (TLM layer) | **DONE** |
| Incoming connection filtering | Yes | No | **TODO** |
| Per-connection decision (ASK) | Yes | Yes | **DONE** |
| Protocol support (TCP/UDP/ICMP) | Yes | TCP/UDP (ICMP partial) | **PARTIAL** |

## Rule System

| Feature | Little Snitch | Sereno | Status |
|---------|---------------|--------|--------|
| Allow/Deny rules | Yes | Yes | **DONE** |
| Domain-based rules | Yes | Yes | **DONE** |
| IP address rules | Yes | Yes | **DONE** |
| Port/port range rules | Yes | Yes | **DONE** |
| Process path rules | Yes | Yes | **DONE** |
| Process name rules | Yes | Yes | **DONE** |
| Wildcard domain patterns | Yes | Yes | **DONE** |
| Regex patterns | Yes | Yes | **DONE** |
| Rule priority | Yes | No | **TODO** |
| Rule enabled/disabled toggle | Yes | Yes | **DONE** |
| Rule hit counter | Yes | Yes | **DONE** |
| Rule notes/descriptions | Yes | No | **TODO** |

## Rule Lifetime/Validity

| Feature | Little Snitch | Sereno | Status |
|---------|---------------|--------|--------|
| Permanent rules | Yes | Yes | **DONE** |
| Once (single use) | Yes | Yes | **DONE** |
| Until quit | Yes | Yes (UntilQuit) | **DONE** |
| Time-based (1h, 1d, 1w) | Yes | Yes | **DONE** |
| Until restart | Yes | No | **TODO** |
| Custom time duration | Yes | No (preset only) | **PARTIAL** |

## Process Identification & Security

| Feature | Little Snitch | Sereno | Status |
|---------|---------------|--------|--------|
| Code signature verification | Yes | Yes (Authenticode) | **DONE** |
| Signer name display | Yes | Yes | **DONE** |
| Unsigned binary warning | Yes | Yes (!! indicator) | **DONE** |
| Invalid signature warning | Yes | Yes (XX indicator) | **DONE** |
| Certificate chain validation | Yes | Yes (WinVerifyTrust) | **DONE** |
| Anti-hijacking (code requirement) | Yes | No | **TODO** |

## Network Monitoring

| Feature | Little Snitch | Sereno | Status |
|---------|---------------|--------|--------|
| Live connection list | Yes | Yes | **DONE** |
| Process + destination display | Yes | Yes | **DONE** |
| Bytes sent/received | Yes | Yes (TLM) | **DONE** |
| Connection duration | Yes | Yes | **DONE** |
| SNI/hostname resolution | Yes | Yes | **DONE** |
| Real-time updates | Yes | Yes | **DONE** |
| Connection state (active/closed) | Yes | Partial (active flag) | **PARTIAL** |
| Hierarchical view (process→domain) | Yes | No (flat list) | **TODO** |
| Geographic mapping | Yes | No | **TODO** |
| Traffic diagram/sparklines | Yes | Partial (in Flows tab) | **PARTIAL** |

## Alert System

| Feature | Little Snitch | Sereno | Status |
|---------|---------------|--------|--------|
| Connection alert popup | Yes | Yes (footer prompt) | **DONE** |
| Allow/Deny buttons | Yes | Yes (A/B keys) | **DONE** |
| Create rule from alert | Yes | Yes (T key + duration) | **DONE** |
| Alert detail level config | Yes | No | **TODO** |
| Sound notifications | Yes | No | **TODO** |

## Operation Modes

| Feature | Little Snitch | Sereno | Status |
|---------|---------------|--------|--------|
| Alert Mode (ask for each) | Yes | Yes | **DONE** |
| Silent Allow Mode | Yes | No | **TODO** |
| Silent Deny Mode | Yes | No | **TODO** |

## Profiles & Switching

| Feature | Little Snitch | Sereno | Status |
|---------|---------------|--------|--------|
| Multiple profiles | Yes | No | **TODO** |
| Network-based auto-switching | Yes | No | **TODO** |
| VPN profile switching | Yes | No | **TODO** |

## Blocklists

| Feature | Little Snitch | Sereno | Status |
|---------|---------------|--------|--------|
| URL-based blocklist subscriptions | Yes | No | **TODO** |
| Auto-updating blocklists | Yes | No | **TODO** |
| Built-in rule groups | Yes | No | **TODO** |

## DNS Features

| Feature | Little Snitch | Sereno | Status |
|---------|---------------|--------|--------|
| DNS query visibility | Yes | Yes (UDP:53) | **PARTIAL** |
| DNS over HTTPS (DoH) | Yes | No | **TODO** |
| DNS over TLS (DoT) | Yes | No | **TODO** |
| DNS encryption | Yes | No | **TODO** |

## UI Components

| Feature | Little Snitch | Sereno | Status |
|---------|---------------|--------|--------|
| Main window | Yes | Yes (TUI) | **DONE** |
| Connections list | Yes | Yes | **DONE** |
| Rules editor | Yes | Partial (view only) | **PARTIAL** |
| Logs view | Yes | Yes | **DONE** |
| Settings page | Yes | Partial | **PARTIAL** |
| Menu bar/tray icon | Yes | No (TUI only) | **TODO** |
| Traffic meter | Yes | Yes (header) | **DONE** |
| Sorting options | Yes | Yes | **DONE** |
| Filtering/search | Yes | No | **TODO** |
| Connection inspector/details | Yes | Yes (I key) | **DONE** |

## Data Management

| Feature | Little Snitch | Sereno | Status |
|---------|---------------|--------|--------|
| SQLite database | Yes | Yes | **DONE** |
| Rule import/export | Yes | No | **TODO** |
| Configuration backup | Yes | No | **TODO** |
| Historical traffic data | Yes | No (session only) | **TODO** |

## CLI Support

| Feature | Little Snitch | Sereno | Status |
|---------|---------------|--------|--------|
| Command-line interface | Yes | Primary interface | **DONE** |
| Preference management | Yes | No | **TODO** |
| Model export/restore | Yes | No | **TODO** |
| Traffic capture | Yes | No | **TODO** |

---

## Priority TODO List (Network Coverage Focus)

### P0 - Critical for Network Coverage
1. **Incoming connection filtering** - Currently only outgoing is filtered
2. **ICMP full support** - Ping and traceroute visibility
3. **IPv6 full support** - Ensure all IPv6 traffic is captured
4. **Silent Allow Mode** - For initial learning period
5. **Connection collapsing** - Group by destination to reduce duplicates

### P1 - Important Features
1. **Rule priority** - Control which rules take precedence
2. **Hierarchical view** - Process → Domain grouping
3. **Filtering/search** - Find specific connections or rules
4. **Rule import/export** - Share rules between machines
5. **System tray/background mode** - Run without TUI open

### P2 - Nice to Have
1. **Profiles** - Different configs for home/work/travel
2. **Blocklist subscriptions** - Community-maintained lists
3. **Geographic mapping** - Where connections go
4. **Sound notifications** - Audio alerts for blocked connections
5. **Traffic history** - Persistent connection logs

---

## Network Coverage Gaps Identified

### Currently Missing Traffic Types

1. **Loopback traffic (127.0.0.1)** - May not be intercepted
2. **IPv6 link-local** - fe80:: addresses
3. **Raw sockets** - Non TCP/UDP traffic
4. **QUIC (UDP:443)** - Being monitored but not distinguished
5. **WFP layer gaps** - Some system traffic may bypass filters

### Duplicate Connection Issue

The current implementation shows duplicate entries because:
- Each TCP connection has unique (local_port, remote_ip, remote_port)
- Multiple connections to same destination appear separate
- UDP flows may also duplicate ALE events

**Proposed Solutions:**
1. Add "Collapse by destination" view mode
2. Aggregate same-process same-destination connections
3. Add connection counter instead of individual entries
