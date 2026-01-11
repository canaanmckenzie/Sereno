# Sereno: Production-Grade Network Monitor & Firewall

## Complete Build Guide & Technical Specification

**Version:** 1.0  
**Target Platforms:** Windows 10/11, Android 8.0+  
**Architecture:** Cross-platform with native performance  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Little Snitch Feature Parity Matrix](#2-little-snitch-feature-parity-matrix)
3. [System Architecture](#3-system-architecture)
4. [Windows Implementation](#4-windows-implementation)
5. [Android Implementation](#5-android-implementation)
6. [Shared Components](#6-shared-components)
7. [User Interface Specifications](#7-user-interface-specifications)
8. [Database & Storage Design](#8-database--storage-design)
9. [Security Architecture](#9-security-architecture)
10. [Performance Requirements](#10-performance-requirements)
11. [Development Phases](#11-development-phases)
12. [Testing Strategy](#12-testing-strategy)
13. [Build & Deployment](#13-build--deployment)
14. [Appendices](#14-appendices)

---

## 1. Executive Summary

### 1.1 Project Overview

Sereno is a production-grade host-based application firewall that provides complete visibility and control over network connections on Windows and Android platforms. It replicates all functionality of Little Snitch (macOS) while adding platform-specific optimizations.

### 1.2 Core Value Proposition

- **Complete Network Visibility:** Monitor every connection attempt by every application
- **Granular Control:** Allow/deny connections per app, domain, port, protocol, and IP range
- **Privacy Protection:** Prevent unwanted data exfiltration and tracking
- **Security Enhancement:** Block malicious connections and command-and-control traffic
- **Performance Insights:** Understand bandwidth usage by application

### 1.3 Technical Goals

| Goal | Target |
|------|--------|
| Connection Decision Latency | < 1ms for cached rules |
| Memory Footprint (Idle) | < 50MB Windows, < 30MB Android |
| CPU Usage (Idle) | < 0.5% |
| Rule Evaluation Speed | > 100,000 rules/second |
| Startup Time | < 2 seconds |
| Battery Impact (Android) | < 3% per day |

---

## 2. Little Snitch Feature Parity Matrix

### 2.1 Core Firewall Features

| Little Snitch Feature | Sereno Windows | Sereno Android | Implementation Notes |
|----------------------|----------------|----------------|---------------------|
| Outbound connection monitoring | ✅ | ✅ | WFP (Windows) / VPN Service (Android) |
| Inbound connection monitoring | ✅ | ✅ | WFP callout driver / VPN tunnel |
| Per-application rules | ✅ | ✅ | Process identification / UID mapping |
| Per-domain rules | ✅ | ✅ | DNS inspection + SNI parsing |
| Per-port rules | ✅ | ✅ | TCP/UDP port filtering |
| Per-protocol rules (TCP/UDP/ICMP) | ✅ | ✅ | Protocol-level filtering |
| IP address/range rules | ✅ | ✅ | CIDR notation support |
| Wildcard domain matching | ✅ | ✅ | *.example.com patterns |
| Regular expression rules | ✅ | ✅ | Full regex support for advanced users |
| Rule priorities | ✅ | ✅ | Ordered rule evaluation |
| Temporary rules (time-limited) | ✅ | ✅ | Auto-expiring rules |
| Rules valid "until quit" | ✅ | ✅ | Process lifecycle tracking |
| Rules valid "once" | ✅ | ✅ | Single-use rules |

### 2.2 Connection Alert System

| Little Snitch Feature | Sereno Windows | Sereno Android | Implementation Notes |
|----------------------|----------------|----------------|---------------------|
| Real-time connection alerts | ✅ | ✅ | System notification + overlay |
| Alert with app icon | ✅ | ✅ | Extract from executable/APK |
| Show process path | ✅ | ✅ | Full path on Windows, package name Android |
| Show parent process | ✅ | ✅ | Process tree walking |
| Show code signature status | ✅ | ✅ | Authenticode / APK signature |
| Show domain/IP being accessed | ✅ | ✅ | Reverse DNS + original request |
| Show port and protocol | ✅ | ✅ | Service name lookup |
| Show geographic location | ✅ | ✅ | MaxMind GeoIP database |
| Remember decision checkbox | ✅ | ✅ | Quick rule creation |
| Custom rule creation from alert | ✅ | ✅ | Advanced options expansion |
| Alert queueing | ✅ | ✅ | Multiple pending alerts |
| Alert timeout configuration | ✅ | ✅ | Default action after timeout |
| Alert sound | ✅ | ✅ | Configurable notification sound |

### 2.3 Network Monitor

| Little Snitch Feature | Sereno Windows | Sereno Android | Implementation Notes |
|----------------------|----------------|----------------|---------------------|
| Real-time connection list | ✅ | ✅ | Live updating table |
| Data sent/received per connection | ✅ | ✅ | Byte counters |
| Connection duration | ✅ | ✅ | Timestamp tracking |
| Connection state (active/closed) | ✅ | ✅ | TCP state machine |
| Bandwidth graph per connection | ✅ | ✅ | Rolling time window |
| Total bandwidth graph | ✅ | ✅ | Aggregated statistics |
| Filter connections by app | ✅ | ✅ | Quick filter UI |
| Filter connections by state | ✅ | ✅ | Active/closed/blocked |
| Sort by various columns | ✅ | ✅ | All columns sortable |
| Connection inspector details | ✅ | ✅ | Deep packet metadata |
| Historical connection log | ✅ | ✅ | Persistent database |
| Export connection data | ✅ | ✅ | CSV/JSON export |

### 2.4 Map Visualization

| Little Snitch Feature | Sereno Windows | Sereno Android | Implementation Notes |
|----------------------|----------------|----------------|---------------------|
| World map with connections | ✅ | ✅ | WebGL/Canvas rendering |
| Animated connection lines | ✅ | ✅ | Direction indication |
| Server location markers | ✅ | ✅ | GeoIP coordinates |
| Click to inspect connection | ✅ | ✅ | Interactive elements |
| Filter map by application | ✅ | ✅ | Per-app visualization |
| Zoom and pan | ✅ | ✅ | Standard map controls |
| Dark/light map themes | ✅ | ✅ | Theme synchronization |

### 2.5 Rules Management

| Little Snitch Feature | Sereno Windows | Sereno Android | Implementation Notes |
|----------------------|----------------|----------------|---------------------|
| Rule editor GUI | ✅ | ✅ | Full-featured editor |
| Rule grouping/folders | ✅ | ✅ | Hierarchical organization |
| Rule search | ✅ | ✅ | Full-text search |
| Rule import/export | ✅ | ✅ | JSON/XML format |
| Rule backup/restore | ✅ | ✅ | Full configuration backup |
| Factory rules (system processes) | ✅ | ✅ | Pre-configured safe rules |
| Rule suggestions | ✅ | ✅ | ML-based recommendations |
| Duplicate rule detection | ✅ | ✅ | Conflict resolution |
| Rule statistics (hit count) | ✅ | ✅ | Usage tracking |
| Rule enable/disable toggle | ✅ | ✅ | Without deletion |
| Bulk rule operations | ✅ | ✅ | Multi-select actions |

### 2.6 Profiles

| Little Snitch Feature | Sereno Windows | Sereno Android | Implementation Notes |
|----------------------|----------------|----------------|---------------------|
| Multiple profiles | ✅ | ✅ | Named rule sets |
| Profile switching | ✅ | ✅ | Manual switch |
| Automatic profile switching | ✅ | ✅ | Network-based triggers |
| Profile based on network name | ✅ | ✅ | SSID/adapter detection |
| Profile based on IP range | ✅ | ✅ | Gateway/subnet matching |
| Profile inheritance | ✅ | ✅ | Base + overlay rules |
| Profile-specific rules | ✅ | ✅ | Per-profile exceptions |

### 2.7 Silent Mode

| Little Snitch Feature | Sereno Windows | Sereno Android | Implementation Notes |
|----------------------|----------------|----------------|---------------------|
| Allow all connections | ✅ | ✅ | Bypass with logging |
| Deny all connections | ✅ | ✅ | Block all with logging |
| Allow established & related | ✅ | ✅ | Stateful filtering |
| Scheduled silent mode | ✅ | ✅ | Time-based activation |
| Per-profile silent mode defaults | ✅ | ✅ | Profile integration |

### 2.8 Research Assistant

| Little Snitch Feature | Sereno Windows | Sereno Android | Implementation Notes |
|----------------------|----------------|----------------|---------------------|
| Domain information lookup | ✅ | ✅ | WHOIS integration |
| IP address information | ✅ | ✅ | ASN, organization data |
| Internet presence check | ✅ | ✅ | Reputation databases |
| Process information | ✅ | ✅ | App metadata lookup |
| Trackers/analytics identification | ✅ | ✅ | Known tracker database |
| User reports/ratings | ✅ | ✅ | Community database |

### 2.9 Code Signing Verification

| Little Snitch Feature | Sereno Windows | Sereno Android | Implementation Notes |
|----------------------|----------------|----------------|---------------------|
| Verify app signatures | ✅ | ✅ | Authenticode / APK signing |
| Show signing certificate | ✅ | ✅ | Certificate chain display |
| Warn on unsigned apps | ✅ | ✅ | Security indicator |
| Warn on modified apps | ✅ | ✅ | Integrity verification |
| Trust decisions per signer | ✅ | ✅ | Certificate-based rules |

### 2.10 System Integration

| Little Snitch Feature | Sereno Windows | Sereno Android | Implementation Notes |
|----------------------|----------------|----------------|---------------------|
| System tray/status bar icon | ✅ | ✅ | Quick access menu |
| Bandwidth indicator | ✅ | ✅ | Real-time mini display |
| Start at login | ✅ | ✅ | Auto-start configuration |
| Keyboard shortcuts | ✅ | ⚠️ | Limited on Android |
| Dock/taskbar badge | ✅ | ✅ | Blocked count indicator |
| Do Not Disturb integration | ✅ | ✅ | OS DND awareness |
| Focus mode integration | ✅ | ✅ | Windows Focus / Android DND |

### 2.11 Advanced Features

| Little Snitch Feature | Sereno Windows | Sereno Android | Implementation Notes |
|----------------------|----------------|----------------|---------------------|
| Automatic rule creation mode | ✅ | ✅ | Learning mode |
| Deny mode (block by default) | ✅ | ✅ | Whitelist approach |
| Allow mode (allow by default) | ✅ | ✅ | Blacklist approach |
| Custom DNS servers | ✅ | ✅ | Per-connection DNS |
| DNS-over-HTTPS support | ✅ | ✅ | DoH integration |
| Hosts file integration | ✅ | ✅ | System hosts support |
| localhost traffic filtering | ✅ | ✅ | Loopback monitoring |
| IPv6 full support | ✅ | ✅ | Dual-stack |
| VPN traffic handling | ✅ | ✅ | Tunnel-aware rules |

---

## 3. System Architecture

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SERENO ARCHITECTURE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         USER INTERFACE LAYER                         │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │   │
│  │  │   Desktop    │  │   Mobile     │  │     System Tray /        │  │   │
│  │  │   (Tauri)    │  │  (Flutter)   │  │     Notification         │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                        │
│                                     ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        APPLICATION LAYER                             │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │   │
│  │  │    Rules     │  │  Connection  │  │      Profile             │  │   │
│  │  │   Engine     │  │   Manager    │  │      Manager             │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │   │
│  │  │   Alert      │  │  Statistics  │  │      Research            │  │   │
│  │  │   System     │  │   Collector  │  │      Assistant           │  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                        │
│                                     ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                          CORE ENGINE LAYER                           │   │
│  │  ┌──────────────────────────────────────────────────────────────┐   │   │
│  │  │                    Rust Core Library                          │   │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │   │   │
│  │  │  │   Rule      │  │  Connection │  │    DNS              │  │   │   │
│  │  │  │  Evaluator  │  │   Tracker   │  │    Resolver         │  │   │   │
│  │  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │   │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │   │   │
│  │  │  │   GeoIP     │  │  Process    │  │    Signature        │  │   │   │
│  │  │  │   Lookup    │  │  Resolver   │  │    Verifier         │  │   │   │
│  │  │  └─────────────┘  └─────────────┘  └─────────────────────┘  │   │   │
│  │  └──────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                        │
│                                     ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     PLATFORM ABSTRACTION LAYER                       │   │
│  │  ┌────────────────────────────┐  ┌────────────────────────────────┐ │   │
│  │  │     Windows Backend        │  │      Android Backend           │ │   │
│  │  │  ┌──────────────────────┐  │  │  ┌──────────────────────────┐ │ │   │
│  │  │  │   WFP Callout        │  │  │  │   VPN Service            │ │ │   │
│  │  │  │   Driver (KMDF)      │  │  │  │   (tun2socks)            │ │ │   │
│  │  │  └──────────────────────┘  │  │  └──────────────────────────┘ │ │   │
│  │  │  ┌──────────────────────┐  │  │  ┌──────────────────────────┐ │ │   │
│  │  │  │   User-mode          │  │  │  │   Packet                 │ │ │   │
│  │  │  │   Service            │  │  │  │   Processor              │ │ │   │
│  │  │  └──────────────────────┘  │  │  └──────────────────────────┘ │ │   │
│  │  └────────────────────────────┘  └────────────────────────────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                     │                                        │
│                                     ▼                                        │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                          NETWORK LAYER                               │   │
│  │  ┌──────────────────────────────────────────────────────────────┐   │   │
│  │  │    TCP/IP Stack    │    Network Adapters    │    DNS          │   │   │
│  │  └──────────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Technology Stack

#### 3.2.1 Shared Core (Cross-Platform)

| Component | Technology | Justification |
|-----------|------------|---------------|
| Core Engine | Rust | Memory safety, performance, cross-platform FFI |
| Rule Engine | Rust + custom DSL | Fast evaluation, complex pattern matching |
| Database | SQLite + SQLCipher | Encrypted local storage, cross-platform |
| GeoIP Database | MaxMind GeoLite2 | Industry standard, monthly updates |
| DNS Resolution | trust-dns | Pure Rust, async, DoH support |
| IPC Protocol | Protocol Buffers | Efficient serialization, schema evolution |
| Configuration | TOML + JSON Schema | Human-readable, validated |

#### 3.2.2 Windows-Specific

| Component | Technology | Justification |
|-----------|------------|---------------|
| Network Filter | WFP (Windows Filtering Platform) | Official Microsoft API, kernel integration |
| Kernel Driver | KMDF (Kernel-Mode Driver Framework) | Modern driver model, stability |
| User Service | Windows Service (Rust) | Background operation, privilege management |
| Desktop UI | Tauri + React/TypeScript | Native performance, web technologies |
| System Tray | Tauri built-in | Cross-platform tray support |
| Installer | WiX Toolset | MSI packaging, enterprise deployment |
| Code Signing | Windows SDK SignTool | Authenticode verification |

#### 3.2.3 Android-Specific

| Component | Technology | Justification |
|-----------|------------|---------------|
| Network Capture | VpnService API | Non-root network interception |
| Packet Processing | tun2socks + Rust | Efficient packet handling |
| Mobile UI | Flutter | Cross-platform UI, native performance |
| Background Service | Foreground Service | Persistent operation |
| APK Verification | PackageManager API | Signature verification |
| Notifications | NotificationCompat | Modern notification channels |

---

## 4. Windows Implementation

### 4.1 Windows Filtering Platform (WFP) Architecture

#### 4.1.1 WFP Layers Used

```
FWPM_LAYER_ALE_AUTH_CONNECT_V4 / V6
├── Purpose: Intercept outbound TCP/UDP connection attempts
├── Information Available:
│   • Process ID
│   • Local/Remote IP and Port
│   • Protocol
│   • Application path
└── Action: PERMIT / BLOCK / DEFER to user-mode

FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 / V6
├── Purpose: Intercept inbound connection acceptance
├── Information Available: Same as above
└── Action: PERMIT / BLOCK

FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 / V6
├── Purpose: Track established connections for statistics
└── Action: Log only (no filtering)

FWPM_LAYER_OUTBOUND_TRANSPORT_V4 / V6
├── Purpose: Packet-level monitoring for bandwidth statistics
└── Action: Inspect and permit (bandwidth counters)
```

#### 4.1.2 Kernel Driver Header

```c
// sereno_driver.h - Main driver header

#ifndef SERENO_DRIVER_H
#define SERENO_DRIVER_H

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>

#define SERENO_DRIVER_NAME      L"Sereno Network Filter"
#define SERENO_DEVICE_NAME      L"\\Device\\Sereno"
#define SERENO_SYMLINK_NAME     L"\\DosDevices\\Sereno"

// Connection request structure for user-mode communication
typedef struct _SERENO_CONNECTION_REQUEST {
    UINT64      RequestId;
    UINT32      ProcessId;
    UINT32      Protocol;
    UINT32      Direction;
    UINT32      LocalAddress;
    UINT32      RemoteAddress;
    UINT16      LocalPort;
    UINT16      RemotePort;
    UINT8       LocalAddressV6[16];
    UINT8       RemoteAddressV6[16];
    BOOLEAN     IsIPv6;
    WCHAR       ApplicationPath[260];
} SERENO_CONNECTION_REQUEST, *PSERENO_CONNECTION_REQUEST;

typedef enum _SERENO_VERDICT {
    SERENO_VERDICT_PENDING = 0,
    SERENO_VERDICT_ALLOW = 1,
    SERENO_VERDICT_BLOCK = 2,
} SERENO_VERDICT;

// IOCTL codes
#define IOCTL_SERENO_GET_REQUEST    CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_SERENO_SET_VERDICT    CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_SERENO_GET_STATS      CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)

#endif
```

### 4.2 User-Mode Service (Rust)

```rust
// src/windows/service/main.rs

use std::ffi::OsString;
use windows_service::{
    define_windows_service,
    service::{ServiceControl, ServiceControlAccept, ServiceExitCode, 
              ServiceState, ServiceStatus, ServiceType},
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

mod driver_comm;
mod rule_engine;
mod connection_manager;
mod alert_system;

const SERVICE_NAME: &str = "SerenoService";

define_windows_service!(ffi_service_main, sereno_service_main);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn sereno_service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        log::error!("Service error: {}", e);
    }
}

fn run_service(_arguments: Vec<OsString>) -> Result<(), Box<dyn std::error::Error>> {
    // Initialize components
    let config = config::load_config()?;
    let database = database::Database::open(&config.database_path)?;
    let rule_engine = rule_engine::RuleEngine::new(database.clone())?;
    let connection_manager = connection_manager::ConnectionManager::new(database.clone())?;
    let alert_system = alert_system::AlertSystem::new(&config)?;
    
    // Start async runtime for main event loop
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let driver = driver_comm::DriverCommunication::connect().await?;
        let mut driver_events = driver.subscribe();
        
        loop {
            tokio::select! {
                Ok(request) = driver_events.recv() => {
                    let verdict = handle_connection_request(
                        &request, &rule_engine, &connection_manager, &alert_system
                    ).await;
                    driver.send_verdict(request.request_id, verdict).await?;
                }
            }
        }
    })
}

async fn handle_connection_request(
    request: &driver_comm::ConnectionRequest,
    rule_engine: &rule_engine::RuleEngine,
    connection_manager: &connection_manager::ConnectionManager,
    alert_system: &alert_system::AlertSystem,
) -> driver_comm::Verdict {
    // Resolve process information
    let process_info = process::get_process_info(request.process_id).await;
    let domain = dns::resolve_domain(&request.remote_address).await;
    
    let context = rule_engine::ConnectionContext {
        process: process_info,
        domain,
        remote_ip: request.remote_address,
        remote_port: request.remote_port,
        local_port: request.local_port,
        protocol: request.protocol,
        direction: request.direction,
    };
    
    match rule_engine.evaluate(&context).await {
        rule_engine::Decision::Allow(rule_id) => {
            connection_manager.record_connection(&context, rule_id, true).await;
            driver_comm::Verdict::Allow
        }
        rule_engine::Decision::Deny(rule_id) => {
            connection_manager.record_connection(&context, rule_id, false).await;
            driver_comm::Verdict::Block
        }
        rule_engine::Decision::Ask => {
            match alert_system.show_alert(&context).await {
                alert_system::AlertResponse::Allow { remember, scope } => {
                    if remember {
                        rule_engine.create_rule(&context, true, scope).await;
                    }
                    driver_comm::Verdict::Allow
                }
                alert_system::AlertResponse::Deny { remember, scope } => {
                    if remember {
                        rule_engine.create_rule(&context, false, scope).await;
                    }
                    driver_comm::Verdict::Block
                }
                alert_system::AlertResponse::Timeout => driver_comm::Verdict::Block
            }
        }
    }
}
```

---

## 5. Android Implementation

### 5.1 VPN-Based Network Interception

Android uses the VpnService API to create a local VPN tunnel that intercepts all network traffic without requiring root.

### 5.2 VPN Service Core

```kotlin
// SerenoVpnService.kt

package com.sereno.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.net.VpnService
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

class SerenoVpnService : VpnService() {
    
    companion object {
        private const val MTU = 1500
        init { System.loadLibrary("sereno_core") }
    }
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    
    private external fun nativeInit(dbPath: String): Long
    private external fun nativeProcessPacket(handle: Long, packet: ByteArray): ProcessResult
    private external fun nativeShutdown(handle: Long)
    
    private var nativeHandle: Long = 0
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }
        startForeground(1, createNotification())
        startVpn()
        return START_STICKY
    }
    
    private fun startVpn() {
        if (isRunning) return
        
        nativeHandle = nativeInit(getDatabasePath("sereno.db").absolutePath)
        
        val builder = Builder()
            .setSession("Sereno")
            .setMtu(MTU)
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .addDnsServer("8.8.8.8")
            .addDisallowedApplication(packageName)
        
        vpnInterface = builder.establish() ?: run {
            stopSelf()
            return
        }
        
        isRunning = true
        scope.launch { processPackets() }
    }
    
    private suspend fun processPackets() {
        val vpnFd = vpnInterface?.fileDescriptor ?: return
        val input = FileInputStream(vpnFd)
        val output = FileOutputStream(vpnFd)
        val packet = ByteBuffer.allocate(65535)
        
        while (isRunning) {
            val length = withContext(Dispatchers.IO) { input.read(packet.array()) }
            if (length <= 0) { delay(10); continue }
            
            packet.limit(length)
            val packetBytes = ByteArray(length)
            packet.get(packetBytes)
            
            val result = nativeProcessPacket(nativeHandle, packetBytes)
            
            when (result.decision) {
                Decision.ALLOW -> forwardPacket(packetBytes, result.connectionInfo)
                Decision.DENY -> sendRejection(result.connectionInfo, output)
                Decision.ASK -> {
                    queuePacket(packetBytes, result.connectionInfo)
                    showConnectionAlert(result.connectionInfo)
                }
            }
            packet.clear()
        }
    }
    
    private fun stopVpn() {
        isRunning = false
        scope.cancel()
        vpnInterface?.close()
        if (nativeHandle != 0L) nativeShutdown(nativeHandle)
        stopForeground(true)
        stopSelf()
    }
}
```

---

## 6. Shared Components - Rust Core

### 6.1 Rule Engine

```rust
// sereno-core/src/rule_engine/mod.rs

use std::net::IpAddr;
use parking_lot::RwLock;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    pub action: Action,
    pub conditions: Vec<Condition>,
    pub validity: Validity,
    pub hit_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action { Allow, Deny, Ask }

#[derive(Debug, Clone)]
pub enum Condition {
    ProcessPath(PathMatcher),
    ProcessName(StringMatcher),
    RemoteAddress(IpMatcher),
    RemotePort(PortMatcher),
    Protocol(ProtocolMatcher),
    Domain(DomainMatcher),
    Direction(Direction),
    And(Vec<Condition>),
    Or(Vec<Condition>),
    Not(Box<Condition>),
}

#[derive(Debug, Clone)]
pub enum Validity {
    Permanent,
    UntilQuit { process_id: u32 },
    Once,
    Timed { expires_at: chrono::DateTime<chrono::Utc> },
}

pub struct RuleEngine {
    rules: Arc<RwLock<Vec<Rule>>>,
    cache: DecisionCache,
    default_action: Action,
}

impl RuleEngine {
    pub fn evaluate(&self, ctx: &ConnectionContext) -> EvalResult {
        // Check cache first
        let cache_key = self.make_cache_key(ctx);
        if let Some(result) = self.cache.get(&cache_key) {
            return result;
        }
        
        let rules = self.rules.read();
        for rule in rules.iter() {
            if !rule.enabled { continue; }
            if !self.is_rule_valid(rule, ctx) { continue; }
            
            if self.evaluate_conditions(&rule.conditions, ctx) {
                let result = match rule.action {
                    Action::Allow => EvalResult::Allow { rule_id: rule.id.clone() },
                    Action::Deny => EvalResult::Deny { rule_id: rule.id.clone() },
                    Action::Ask => EvalResult::Ask,
                };
                
                if !matches!(result, EvalResult::Ask) {
                    self.cache.insert(cache_key, result.clone());
                }
                return result;
            }
        }
        
        EvalResult::Ask
    }
    
    fn evaluate_conditions(&self, conditions: &[Condition], ctx: &ConnectionContext) -> bool {
        conditions.iter().all(|c| self.evaluate_condition(c, ctx))
    }
    
    fn evaluate_condition(&self, condition: &Condition, ctx: &ConnectionContext) -> bool {
        match condition {
            Condition::ProcessPath(m) => self.match_path(&ctx.process_path, m),
            Condition::Domain(m) => ctx.domain.as_ref()
                .map(|d| self.match_domain(d, m)).unwrap_or(false),
            Condition::RemoteAddress(m) => self.match_ip(&ctx.remote_address, m),
            Condition::RemotePort(m) => self.match_port(ctx.remote_port, m),
            Condition::And(conds) => conds.iter().all(|c| self.evaluate_condition(c, ctx)),
            Condition::Or(conds) => conds.iter().any(|c| self.evaluate_condition(c, ctx)),
            Condition::Not(c) => !self.evaluate_condition(c, ctx),
            _ => true,
        }
    }
    
    fn match_domain(&self, domain: &str, matcher: &DomainMatcher) -> bool {
        let domain_lower = domain.to_lowercase();
        matcher.patterns.iter().any(|p| match p {
            DomainPattern::Exact(s) => domain_lower == s.to_lowercase(),
            DomainPattern::Wildcard(s) => {
                let pattern = s.to_lowercase();
                if pattern.starts_with("*.") {
                    let suffix = &pattern[1..];
                    domain_lower.ends_with(suffix) || domain_lower == pattern[2..]
                } else {
                    domain_lower == pattern
                }
            }
            DomainPattern::Regex(r) => r.is_match(&domain_lower),
        })
    }
}
```

---

## 7. Database Schema

```sql
-- Rules table
CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 0,
    action TEXT NOT NULL CHECK (action IN ('allow', 'deny', 'ask')),
    conditions TEXT NOT NULL,  -- JSON encoded
    validity_type TEXT NOT NULL,
    validity_data TEXT,
    hit_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    profile_id TEXT,
    FOREIGN KEY (profile_id) REFERENCES profiles(id)
);

-- Profiles table
CREATE TABLE IF NOT EXISTS profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 0,
    silent_mode TEXT,
    created_at TEXT NOT NULL
);

-- Connections log
CREATE TABLE IF NOT EXISTS connections (
    id TEXT PRIMARY KEY,
    process_path TEXT NOT NULL,
    process_name TEXT NOT NULL,
    remote_address TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    domain TEXT,
    country TEXT,
    bytes_sent INTEGER DEFAULT 0,
    bytes_received INTEGER DEFAULT 0,
    allowed INTEGER NOT NULL,
    rule_id TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT
);

CREATE INDEX idx_connections_started ON connections(started_at DESC);
CREATE INDEX idx_connections_process ON connections(process_path);
```

---

## 8. Development Phases

### Phase 1: Core Foundation (Weeks 1-4)
- [ ] Rust core library with rule engine
- [ ] Basic database schema and operations
- [ ] WFP driver skeleton (Windows)
- [ ] VPN service skeleton (Android)

### Phase 2: Network Interception (Weeks 5-8)
- [ ] Complete WFP driver implementation
- [ ] Complete VPN service implementation
- [ ] Driver ↔ Service communication
- [ ] Basic connection tracking

### Phase 3: User Interface (Weeks 9-12)
- [ ] Tauri desktop application
- [ ] Flutter mobile application
- [ ] Connection alert dialogs
- [ ] Network monitor view

### Phase 4: Advanced Features (Weeks 13-16)
- [ ] World map visualization
- [ ] Profile management
- [ ] Research assistant
- [ ] Code signature verification

### Phase 5: Polish & Testing (Weeks 17-20)
- [ ] Comprehensive test suite
- [ ] Performance optimization
- [ ] Security audit
- [ ] Beta release

### Phase 6: Launch (Weeks 21-24)
- [ ] Windows installer (MSI)
- [ ] Play Store submission
- [ ] Documentation
- [ ] v1.0 release

---

## 9. Performance Targets

| Metric | Target |
|--------|--------|
| Rule evaluation | < 1μs per rule |
| Connection decision (cached) | < 100μs |
| Connection decision (uncached) | < 5ms |
| Memory usage (idle) | < 50MB Win / 30MB Android |
| CPU usage (idle) | < 0.5% |
| Startup time | < 2 seconds |

---

## 10. Quick Start

### Prerequisites

```bash
# Windows
winget install Rustlang.Rustup Microsoft.VisualStudio.2022.BuildTools nodejs pnpm

# Install Windows SDK and WDK for driver development
```

### Build

```bash
git clone https://github.com/sereno/sereno.git
cd sereno

# Build core
cargo build --release -p sereno-core

# Build desktop app
cd sereno-desktop && pnpm install && pnpm tauri build

# Build Android
cd sereno-android && flutter build apk --release
```

---

## Appendix: Factory Rules

```json
{
  "factory_rules": [
    {
      "name": "Allow Windows Update",
      "process_path": "C:\\Windows\\System32\\svchost.exe",
      "domains": ["*.windowsupdate.com", "*.microsoft.com"],
      "action": "allow"
    },
    {
      "name": "Allow DNS",
      "remote_port": 53,
      "protocol": "udp",
      "action": "allow"
    },
    {
      "name": "Block Telemetry",
      "domains": ["*.data.microsoft.com", "telemetry.*"],
      "action": "deny"
    },
    {
      "name": "Allow Local Network",
      "remote_address": ["192.168.0.0/16", "10.0.0.0/8"],
      "action": "allow"
    }
  ]
}
```

---

**Document Version:** 1.0  
**Status:** Complete Specification

*This document provides a comprehensive blueprint for building Sereno with full Little Snitch feature parity on Windows and Android.*
