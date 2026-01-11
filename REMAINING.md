# Sereno - Remaining Tasks to Complete Phase 4

**Last Updated:** 2026-01-11
**Status:** Phase 4 (WFP Driver) in progress

---

## Current State Summary

### Completed
- [x] **Phase 1:** Core Library (`sereno-core/`) - Rule engine, database, types
- [x] **Phase 2:** CLI (`sereno-cli/`) - Rule management, connection history
- [x] **Phase 3:** Service (`sereno-service/`) - Connection monitoring, DNS lookup, process info
- [x] **Phase 4 Partial:**
  - [x] WDK installed (10.0.26100)
  - [x] Kernel driver source code (`sereno-driver/src/driver.c`, `driver.h`)
  - [x] Visual Studio project files (`SerenoFilter.vcxproj`, `.sln`)
  - [x] INF file for driver installation
  - [x] Build/install PowerShell scripts
  - [x] Service IOCTL communication module (`sereno-service/src/driver.rs`)
  - [x] Service integration (detects driver, shows kernel mode status)

### All Tests Pass
```
19 tests total (16 core + 3 service)
```

---

## IMMEDIATE NEXT STEPS

### Step 1: Enable Test Signing Mode (REQUIRES ADMIN + REBOOT)

Windows requires drivers to be signed. For development, you must enable "test signing mode" which allows loading of self-signed test drivers.

**What Test Signing Does:**
- Allows loading drivers signed with test certificates
- Adds a "Test Mode" watermark to the desktop (bottom right)
- Required for any kernel driver development without a production EV certificate

**How to Enable:**

```powershell
# Option A: Use the provided script (run as Administrator)
cd C:\Users\Virgil\Desktop\sereno-dev\sereno-driver\scripts
.\enable-test-signing.ps1

# Option B: Manual command (run as Administrator)
bcdedit /set testsigning on
```

**Important Notes:**
- **Requires Administrator PowerShell**
- **Requires a REBOOT to take effect**
- If Secure Boot is enabled in BIOS/UEFI, you may need to disable it first
- After reboot, you'll see "Test Mode" watermark on desktop - this is normal

**To disable later:**
```powershell
bcdedit /set testsigning off
# Reboot required
```

---

### Step 2: Build the Kernel Driver

After reboot with test signing enabled:

**Option A: Using Visual Studio (Recommended)**
1. Open `C:\Users\Virgil\Desktop\sereno-dev\sereno-driver\SerenoFilter.sln` in Visual Studio 2022
2. Ensure "Windows Driver Kit" workload is installed in VS
3. Select `Release | x64` configuration
4. Build > Build Solution (Ctrl+Shift+B)

**Option B: Using Command Line**
```powershell
cd C:\Users\Virgil\Desktop\sereno-dev\sereno-driver\scripts
.\build.ps1 -Configuration Release -Platform x64
```

**Build Output Location:**
```
sereno-driver\bin\x64\Release\
├── SerenoFilter.sys    # The driver binary
├── SerenoFilter.pdb    # Debug symbols
└── sereno.inf          # Installation manifest
```

---

### Step 3: Test Sign the Driver

The WDK build should auto-sign with a test certificate. If not, manual signing:

```powershell
# Create a test certificate (one time)
makecert -r -pe -ss PrivateCertStore -n "CN=Sereno Test" SereneTest.cer

# Sign the driver
signtool sign /v /s PrivateCertStore /n "Sereno Test" /t http://timestamp.digicert.com SerenoFilter.sys
```

**Verify signature:**
```powershell
signtool verify /v /pa SerenoFilter.sys
```

---

### Step 4: Install the Driver

```powershell
# Run as Administrator
cd C:\Users\Virgil\Desktop\sereno-dev\sereno-driver\scripts
.\install.ps1 -Configuration Release
```

**Manual installation:**
```powershell
# Copy driver to system32\drivers
copy bin\x64\Release\SerenoFilter.sys C:\Windows\System32\drivers\

# Create the service
sc create SerenoFilter type= kernel binPath= C:\Windows\System32\drivers\SerenoFilter.sys start= demand

# Start the driver
sc start SerenoFilter
```

**Verify driver is running:**
```powershell
sc query SerenoFilter
# Should show STATE: RUNNING
```

---

### Step 5: Test the Integration

With driver running, the service should detect it:

```powershell
cd C:\Users\Virgil\Desktop\sereno-dev
cargo run -p sereno-service
```

Expected output should show:
```
Kernel Driver: Available
Mode: Full Kernel (Synchronous Pre-Connection Blocking)
```

When connections are blocked, output should show:
```
  DENY  │ someapp.exe → blocked-domain.com:443 [BLOCKED]
```

---

## REMAINING FEATURES

### DNS Inspection for Domain-Based Blocking

**Problem:** The WFP callout intercepts connections by IP address, but rules often specify domains (e.g., `*.facebook.com`). By the time the connection reaches the driver, DNS has already resolved.

**Solution Options:**

1. **DNS Query Interception** (Recommended)
   - Add WFP filter at `FWPM_LAYER_ALE_AUTH_CONNECT_V4` for port 53/UDP
   - Parse DNS queries to map domains → IPs
   - Cache domain→IP mappings in driver or service
   - When connection arrives, look up IP to find original domain

2. **SNI Inspection** (For HTTPS)
   - For TLS connections on port 443
   - Parse the TLS Client Hello to extract SNI (Server Name Indication)
   - Requires FWPM_LAYER_STREAM or deeper packet inspection

3. **IP-to-Domain Cache** (Current partial approach)
   - Service performs reverse DNS on connection IPs
   - Less reliable (PTR records may not match forward DNS)

**Implementation Location:**
- `sereno-driver/src/driver.c` - Add DNS layer callout
- `sereno-service/src/dns.rs` - Domain→IP cache
- `sereno-service/src/driver.rs` - Pass domain info to driver

### Files to Modify for DNS Inspection

```
sereno-driver/src/driver.h
├── Add DNS request structure
├── Add IOCTL for domain cache updates

sereno-driver/src/driver.c
├── Add FWPM_LAYER_ALE_AUTH_CONNECT for port 53
├── Parse DNS query packets
├── Maintain domain→IP lookup table

sereno-service/src/dns.rs
├── Enhance reverse lookup caching
├── Add SNI extraction for HTTPS

sereno-service/src/driver.rs
├── Add domain cache IOCTL
├── Send domain mappings to driver
```

---

## FILE STRUCTURE REFERENCE

```
sereno-dev/
├── sereno-core/           # Rust core library
│   └── src/
│       ├── lib.rs
│       ├── database.rs
│       ├── rule_engine/
│       └── types.rs
│
├── sereno-cli/            # CLI tool
│   └── src/main.rs
│
├── sereno-service/        # Windows service
│   └── src/
│       ├── main.rs        # Service entry point
│       ├── driver.rs      # Kernel driver IOCTL communication
│       ├── wfp.rs         # User-mode WFP (fallback)
│       ├── dns.rs         # DNS resolution
│       └── process.rs     # Process info extraction
│
├── sereno-driver/         # Kernel driver (C/WDK)
│   ├── src/
│   │   ├── driver.c       # Main driver implementation
│   │   └── driver.h       # Headers and structures
│   ├── SerenoFilter.vcxproj
│   ├── SerenoFilter.sln
│   ├── sereno.inf
│   └── scripts/
│       ├── enable-test-signing.ps1
│       ├── build.ps1
│       └── install.ps1
│
├── SERENO_BUILD_GUIDE.md  # Full specification
└── REMAINING.md           # This file
```

---

## IOCTL INTERFACE (driver ↔ service)

| IOCTL Code | Name | Direction | Purpose |
|------------|------|-----------|---------|
| 0x80006004 | GET_PENDING | Driver → Service | Get pending connection for verdict |
| 0x8000A008 | SET_VERDICT | Service → Driver | Send allow/block decision |
| 0x80006004 | GET_STATS | Driver → Service | Get connection statistics |
| 0x8000A014 | ENABLE | Service → Driver | Enable filtering |
| 0x8000A018 | DISABLE | Service → Driver | Disable filtering |

**Data Structures (must match between C and Rust):**

```c
// Connection request (driver → service)
typedef struct _SERENO_CONNECTION_REQUEST {
    UINT64      RequestId;
    UINT64      Timestamp;
    UINT32      ProcessId;
    UINT8       Protocol;        // 6=TCP, 17=UDP, 1=ICMP
    UINT8       Direction;       // 0=Outbound, 1=Inbound
    UINT8       IpVersion;       // 4 or 6
    UINT8       Reserved;
    UINT32      LocalAddressV4;
    UINT32      RemoteAddressV4;
    UINT8       LocalAddressV6[16];
    UINT8       RemoteAddressV6[16];
    UINT16      LocalPort;
    UINT16      RemotePort;
    WCHAR       ApplicationPath[260];
    UINT32      ApplicationPathLength;
    WCHAR       DomainName[256];
    UINT32      DomainNameLength;
} SERENO_CONNECTION_REQUEST;

// Verdict response (service → driver)
typedef struct _SERENO_VERDICT_RESPONSE {
    UINT64      RequestId;
    UINT32      Verdict;         // 0=Pending, 1=Allow, 2=Block
    UINT32      Reserved;
} SERENO_VERDICT_RESPONSE;
```

---

## TROUBLESHOOTING

### Driver won't load
1. Check test signing is enabled: `bcdedit | findstr testsigning`
2. Check driver is signed: `signtool verify /v SerenoFilter.sys`
3. Check Event Viewer > System for driver load errors
4. Try `sc query SerenoFilter` for status

### BSOD on driver load
1. Boot into Safe Mode
2. `sc delete SerenoFilter`
3. Review driver code for issues
4. Check WDK debug output via WinDbg

### Service can't connect to driver
1. Verify driver is running: `sc query SerenoFilter`
2. Check device path: `\\.\SerenoFilter`
3. Run service as Administrator

### No connections being intercepted
1. Check WFP filters are registered
2. Verify callout GUIDs match
3. Use `netsh wfp show filters` to list filters

---

## COMMANDS QUICK REFERENCE

```powershell
# Build everything
cargo build --workspace

# Run tests
cargo test --workspace

# Run service
cargo run -p sereno-service

# Run CLI
cargo run -p sereno-cli -- --help

# Build driver (after VS/WDK setup)
cd sereno-driver\scripts
.\build.ps1 -Configuration Release

# Install driver
.\install.ps1

# Uninstall driver
.\install.ps1 -Uninstall

# Check driver status
sc query SerenoFilter

# Enable test signing (requires reboot)
bcdedit /set testsigning on

# View WFP filters
netsh wfp show filters
```

---

## NEXT CLAUDE AGENT INSTRUCTIONS

1. **First:** Check if test signing is enabled (`bcdedit | findstr testsigning`)
2. **If not:** Guide user through enabling test signing + reboot
3. **After reboot:** Build the driver with Visual Studio or build.ps1
4. **Then:** Install driver and test integration
5. **Finally:** Implement DNS inspection for domain-based blocking

The code is complete and compiles. The blocker is Windows security requiring test signing mode to be enabled before the kernel driver can be loaded.

---

**Document Version:** 1.0
**Author:** Claude (Opus 4.5)
