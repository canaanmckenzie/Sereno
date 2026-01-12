# Sereno Development Environment and Build Plan

## Part 1: Proxmox VM Setup for Isolated Development

### 1.1 Create Windows 11 VM in Proxmox

#### Download Windows 11 ISO

Microsoft requires the Media Creation Tool or manual download from their website.
Direct wget from Proxmox does not work.

**Steps:**

1. On your local machine, go to <https://www.microsoft.com/software-download/windows11>
2. Download the Windows 11 ISO (select your language, 64-bit)
3. Upload to Proxmox via Web UI:
   - Open Proxmox Web UI in browser
   - Navigate to: Datacenter -> your-node -> local (or your storage)
   - Click "ISO Images" in the middle panel
   - Click "Upload" button
   - Select your downloaded Windows 11 ISO file
   - Wait for upload to complete

#### Download VirtIO Drivers

```bash
# WHERE TO RUN: Proxmox host via SSH (root@pve)
# These drivers let Windows recognize VirtIO disk/network devices
ssh root@<your-proxmox-ip>
cd /var/lib/vz/template/iso
wget https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
```

Or upload via Proxmox Web UI: local -> ISO Images -> Upload

#### Create VM in Proxmox Web UI

1. Click "Create VM" in top right
2. **General tab:**
   - Node: (your node)
   - VM ID: (auto or pick one, e.g., 200)
   - Name: `sereno-dev`
3. **OS tab:**
   - ISO image: Select Windows 11 ISO
   - Type: Microsoft Windows
   - Version: 11/2022
4. **System tab:**
   - Machine: q35
   - BIOS: OVMF (UEFI) - required for Windows 11
   - Add TPM: Check (v2.0, storage on local-lvm)
   - Add EFI Disk: Check
5. **Disks tab:**
   - Bus: VirtIO Block (faster) or SCSI
   - Size: 150GB minimum (driver dev needs space)
   - Cache: Write back
   - SSD emulation: Check if on SSD storage
6. **CPU tab:**
   - Cores: 4-8 (driver compilation is CPU intensive)
   - Type: host (best performance)
7. **Memory tab:**
   - RAM: 16384 MB (16GB) minimum, 32GB preferred
8. **Network tab:**
   - Bridge: vmbr0
   - Model: VirtIO (paravirtualized)

#### After VM Creation - Add VirtIO ISO

1. Select VM -> Hardware -> Add -> CD/DVD Drive
2. Select virtio-win.iso

### 1.2 Configure SPICE Display (Before First Boot)

Configure the VM for SPICE to get seamless mouse, auto-resize, and clipboard sharing.

#### In Proxmox Web UI - VM Hardware Settings

1. Select your VM -> Hardware
2. Change **Display**:
   - Graphic card: SPICE (qxl)
   - Memory: 128 MB (or higher for better graphics)
3. Add **USB Device**:
   - Click Add -> USB Device
   - Choose "Spice Port" (usb-redirect)

#### In Proxmox Web UI - VM Options

1. Select your VM -> Options
2. Set **SPICE enhancements**:
   - Video Streaming: all (or off if you prefer)
   - Folder Sharing: enable if you want shared folders

### 1.3 Install Windows 11

```text
WHERE TO RUN: Inside the VM console (Proxmox web UI -> VM -> Console)
```

1. Start VM, open Console
2. Boot from Windows ISO
3. At disk selection: "Load driver" -> Browse to VirtIO CD -> `vioscsi\w11\amd64`
4. Also load: `NetKVM\w11\amd64` (network driver)
5. Continue Windows installation
6. Create local account (avoid Microsoft account for dev VM)
7. After install, install remaining VirtIO drivers:
   - Open VirtIO CD in Explorer
   - Run `virtio-win-guest-tools.exe`

### 1.4 Install SPICE Guest Tools (After Windows Install)

Install these inside Windows to enable auto-resize, clipboard, and seamless mouse.

#### Install SPICE Guest Tools

1. Download SPICE Guest Tools in the Windows VM:
   <https://www.spice-space.org/download/windows/spice-guest-tools/spice-guest-tools-latest.exe>
2. Run the installer, accept defaults
3. Reboot when prompted

#### Install SPICE WebDAV Daemon (Optional - for folder sharing)

1. Download: <https://www.spice-space.org/download/windows/spice-webdavd/>
2. Install the MSI package
3. Enables shared folders between host and guest

#### Install Virt-Viewer on Your Local Machine

This is the SPICE client that gives you auto-resize and clipboard.

**Windows (your local desktop):**

```powershell
# WHERE TO RUN: Your local Windows machine (not the VM)
winget install virt-viewer
```

Or download from: <https://virt-manager.org/download/>

**Linux:**

```bash
# WHERE TO RUN: Your local Linux machine
sudo apt install virt-viewer    # Debian/Ubuntu
sudo dnf install virt-viewer    # Fedora
```

#### Connect via Virt-Viewer

1. In Proxmox Web UI: Select VM -> Console -> Click "SPICE" button (top right)
2. This downloads a `.vv` file
3. Open the `.vv` file with virt-viewer
4. Window now auto-resizes, clipboard works, mouse is seamless

#### Verify Everything Works

| Feature | How to Test |
|---------|-------------|
| Auto-resize | Drag the virt-viewer window corners - VM resolution follows |
| Clipboard | Copy text on local machine, Ctrl+V in VM (and vice versa) |
| Seamless mouse | Mouse moves in/out of window without clicking or key combos |

#### Troubleshooting

If clipboard or resize not working:

```powershell
# WHERE TO RUN: Windows 11 VM - PowerShell
# Check SPICE agent is running
Get-Service -Name "spice-agent" | Select-Object Status, Name
Get-Service -Name "vdservice" | Select-Object Status, Name

# Restart if needed
Restart-Service -Name "spice-agent"
Restart-Service -Name "vdservice"
```

### 1.5 Initial Development Environment Setup

All commands in this section run **inside the Windows 11 VM (sereno-dev)**.

Complete these steps in order. Each step has a verification check.

#### Step 1: Update Windows

```powershell
# WHERE TO RUN: sereno-dev VM - Settings app
# Settings → Windows Update → Check for updates → Install all → Reboot if needed
```

**Verify:**

```powershell
# WHERE TO RUN: sereno-dev VM - PowerShell
winver
# Should show Windows 11 with recent build number
```

#### Step 2: Install winget (if not present)

Usually pre-installed on Windows 11. Check first:

```powershell
# WHERE TO RUN: sereno-dev VM - PowerShell
winget --version
```

**If missing**, download from: <https://github.com/microsoft/winget-cli/releases>

**Verify:**

```powershell
winget --version
# Should show: v1.x.xxxxx
```

#### Step 3: Install Git

```powershell
# WHERE TO RUN: sereno-dev VM - PowerShell (as Administrator)
winget install Git.Git
```

Close and reopen PowerShell after install.

**Verify:**

```powershell
# WHERE TO RUN: sereno-dev VM - NEW PowerShell window
git --version
# Should show: git version 2.x.x
```

#### Step 4: Install Node.js (includes npm)

```powershell
# WHERE TO RUN: sereno-dev VM - PowerShell (as Administrator)
winget install -e --id OpenJS.NodeJS.LTS
```

Close and reopen PowerShell after install.

**Verify:**

```powershell
# WHERE TO RUN: sereno-dev VM - NEW PowerShell window
node --version
# Should show: v20.x.x or v22.x.x

npm --version
# Should show: 10.x.x
```

#### Step 5: Install pnpm (faster package manager)

```powershell
# WHERE TO RUN: sereno-dev VM - PowerShell
npm install -g pnpm
```

**Verify:**

```powershell
pnpm --version
# Should show: 9.x.x
```

> **Important:** Once you choose pnpm, use it consistently throughout the project. Never mix `npm install` and `pnpm install` - this creates conflicting lockfiles (`package-lock.json` vs `pnpm-lock.yaml`) and can cause dependency resolution issues. Always use `pnpm add`, `pnpm install`, `pnpm run`, etc.

#### Step 6: Install Rust

```powershell
# WHERE TO RUN: sereno-dev VM - PowerShell (as Administrator)
winget install Rustlang.Rustup
```

Close and reopen PowerShell after install.

**Verify:**

```powershell
# WHERE TO RUN: sereno-dev VM - NEW PowerShell window
rustup --version
# Should show: rustup 1.x.x

rustc --version
# Should show: rustc 1.x.x
```

#### Step 7: Configure Rust

```powershell
# WHERE TO RUN: sereno-dev VM - PowerShell
rustup default stable
rustup component add rust-src
rustup target add x86_64-pc-windows-msvc
```

**Verify:**

```powershell
rustup show
# Should show:
# Default host: x86_64-pc-windows-msvc
# installed targets: x86_64-pc-windows-msvc
# active toolchain: stable-x86_64-pc-windows-msvc
```

#### Step 8: Install Visual Studio Build Tools

Required for compiling native code.

```powershell
# WHERE TO RUN: sereno-dev VM - PowerShell (as Administrator)
winget install Microsoft.VisualStudio.2022.BuildTools
```

After install, open "Visual Studio Installer" and add the required workloads:

1. Find "Visual Studio Build Tools 2022" in the list
2. Click the **"Modify"** button on that entry
3. This opens the workloads selection screen
4. Check **"Desktop development with C++"** (easiest - includes everything needed)
   - Or at minimum under "Individual components" tab: "MSVC v143 build tools" + "Windows 11 SDK"
5. Click "Modify" in the bottom right to install

**Verify:**

```powershell
# WHERE TO RUN: sereno-dev VM - PowerShell
# Check cl.exe (C++ compiler) is accessible
# Open "Developer PowerShell for VS 2022" from Start menu, then:
cl
# Should show: Microsoft (R) C/C++ Optimizing Compiler Version 19.x.x
```

#### Step 9: Install VS Code

```powershell
# WHERE TO RUN: sereno-dev VM - PowerShell (as Administrator)
winget install Microsoft.VisualStudioCode
```

**Verify:**

```powershell
# WHERE TO RUN: sereno-dev VM - NEW PowerShell window
code --version
# Should show version number
```

#### Step 10: Install VS Code Extensions

```powershell
# WHERE TO RUN: sereno-dev VM - PowerShell
code --install-extension rust-lang.rust-analyzer
code --install-extension ms-vscode.cpptools
code --install-extension tamasfe.even-better-toml
code --install-extension serayuzgur.crates
code --install-extension ms-vscode.powershell
```

**Verify:**

```powershell
code --list-extensions
# Should include all the extensions above
```

#### Step 11: Install Cargo Audit Tools

```powershell
# WHERE TO RUN: sereno-dev VM - PowerShell
cargo install cargo-audit
cargo install cargo-deny
```

This takes a few minutes to compile.

**Verify:**

```powershell
cargo audit --version
cargo deny --version
# Both should show version numbers
```

#### Step 12: Create Project Directory

```powershell
# WHERE TO RUN: sereno-dev VM - PowerShell
mkdir C:\Dev\sereno
cd C:\Dev\sereno
```

**Verify:**

```powershell
pwd
# Should show: C:\Dev\sereno
```

---

### 1.6 Windows Configuration for Driver Development

All commands in this section run **inside the Windows 11 VM**.

#### Enable Developer Mode

```powershell
# WHERE TO RUN: Windows 11 VM - PowerShell as Administrator
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowDevelopmentWithoutDevLicense" /d "1"
```

#### Enable Test Signing

```cmd
# WHERE TO RUN: Windows 11 VM - CMD as Administrator
bcdedit /set testsigning on
# Reboot required after this command
```

#### Disable Secure Boot

Choose one method:

- In Proxmox VM settings: Hardware -> EFI Disk -> Pre-enrolled keys: No
- Or in Windows: msconfig -> Boot -> Safe boot options

#### Install Windows SDK and WDK

1. Download Windows SDK: <https://developer.microsoft.com/windows/downloads/windows-sdk/>
2. Download WDK: <https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk>
3. Install SDK first, then WDK
4. WDK includes Visual Studio extension for driver projects

---

## Part 2: Development Tools Setup

All commands in Part 2 run **inside the Windows 11 VM**.

### 2.1 Install Core Tools

#### Install winget

- Usually pre-installed on Windows 11
- If not: <https://github.com/microsoft/winget-cli/releases>

#### Install Development Tools

```powershell
# WHERE TO RUN: Windows 11 VM - PowerShell as Administrator
winget install Microsoft.VisualStudioCode
winget install Rustlang.Rustup
winget install Git.Git
winget install Microsoft.VisualStudio.2022.BuildTools
winget install -e --id OpenJS.NodeJS.LTS
winget install pnpm.pnpm
```

#### Configure Rust

```powershell
# WHERE TO RUN: Windows 11 VM - PowerShell (regular user is fine)
rustup default stable
rustup component add rust-src
rustup target add x86_64-pc-windows-msvc
```

### 2.2 VS Code Extensions

```powershell
# WHERE TO RUN: Windows 11 VM - PowerShell
code --install-extension rust-lang.rust-analyzer
code --install-extension ms-vscode.cpptools
code --install-extension tamasfe.even-better-toml
code --install-extension serayuzgur.crates
code --install-extension ms-vscode.powershell
```

---

## Part 3: Project Scaffolding

### 3.1 Directory Structure

```text
C:\Dev\sereno\
├── Cargo.toml              # Workspace root
├── rust-toolchain.toml     # Pin Rust version
├── .cargo\
│   └── config.toml         # Build configuration
├── deny.toml               # cargo-deny policy
├── sereno-core\            # Shared Rust library
│   ├── Cargo.toml
│   └── src\
│       ├── lib.rs
│       ├── rule_engine\
│       ├── database\
│       ├── dns\
│       ├── geoip\
│       └── process\
├── sereno-service\         # Windows service (user-mode)
│   ├── Cargo.toml
│   └── src\
│       └── main.rs
├── sereno-driver\          # WFP kernel driver
│   ├── Cargo.toml          # Or C project
│   └── src\
├── sereno-cli\             # CLI companion tool
│   ├── Cargo.toml
│   └── src\
│       └── main.rs
├── sereno-desktop\         # Tauri app
│   ├── package.json
│   ├── src-tauri\
│   └── src\                # React frontend
└── proto\                  # Protocol buffer definitions
    └── sereno.proto
```

### 3.2 Cargo Workspace Setup

**File: Cargo.toml (workspace root)**

```toml
[workspace]
resolver = "2"
members = [
    "sereno-core",
    "sereno-service",
    "sereno-cli",
    "sereno-desktop/src-tauri",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"
repository = "https://github.com/yourusername/sereno"

[workspace.dependencies]
# Async runtime
tokio = { version = "1.43", features = ["full"] }

# Database
rusqlite = { version = "0.32", features = ["bundled", "backup"] }

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# Windows APIs (official Microsoft crate)
windows = { version = "0.58" }
windows-service = "0.7"

# Networking
trust-dns-resolver = "0.23"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Error handling
thiserror = "2.0"
anyhow = "1.0"

# GeoIP
maxminddb = "0.24"

# CLI
clap = { version = "4.5", features = ["derive"] }

# IPC
prost = "0.13"
tonic = "0.12"
```

### 3.3 Security - Dependency Auditing

#### Install Audit Tools

```powershell
# WHERE TO RUN: Windows 11 VM - PowerShell
cargo install cargo-audit
cargo install cargo-deny
```

#### Create deny.toml Policy File

```toml
[advisories]
db-path = "~/.cargo/advisory-db"
vulnerability = "deny"
unmaintained = "warn"

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Zlib"]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-git = []

[bans]
multiple-versions = "warn"
wildcards = "deny"
```

#### Run Before Each Build

```powershell
# WHERE TO RUN: Windows 11 VM - PowerShell (in project directory)
cargo deny check
cargo audit
```

---

## Part 4: Implementation Phases

### Phase 1: Core Library (sereno-core)

**Goal:** Rule engine, database, and shared types

Files to create:

- `sereno-core/src/lib.rs` - Module exports
- `sereno-core/src/types.rs` - Core data types (Rule, Connection, etc.)
- `sereno-core/src/database/mod.rs` - SQLite operations
- `sereno-core/src/database/schema.rs` - Table creation
- `sereno-core/src/rule_engine/mod.rs` - Rule evaluation logic
- `sereno-core/src/rule_engine/conditions.rs` - Condition matching
- `sereno-core/src/rule_engine/cache.rs` - Decision caching

### Phase 2: CLI Tool (sereno-cli)

**Goal:** Validate core library works, provide power-user interface

Features:

- `sereno rules list/add/remove/enable/disable`
- `sereno connections list/export`
- `sereno profiles list/switch`
- `sereno status`

### Phase 3: Mock Driver and Service

**Goal:** Build service architecture without real kernel driver

- Create mock driver that simulates connection events
- Build full service logic against mock
- Validate IPC, alerts, rule evaluation flow

### Phase 4: WFP Driver

**Goal:** Real kernel-mode network interception

- Start with usermode WFP (less privileged, easier to debug)
- Escalate to kernel callout driver if needed
- Test in VM with snapshots

### Phase 5: Tauri Desktop App

**Goal:** Full GUI with alerts, tray, visualization

- Connection alert dialogs
- System tray with status
- Network monitor view
- Rule management UI

---

## Part 5: VM Workflow Tips

### Snapshots

- Take snapshot after Windows setup (before any dev tools)
- Take snapshot after dev tools installed
- Take snapshot before testing driver code
- Roll back if driver causes BSOD

### Shared Folder Options

1. VM -> Hardware -> Add -> USB Device (for USB drive)
2. Or: Use Git to push/pull between host and VM
3. Or: SMB share from host

### Performance Tuning

```bash
# WHERE TO RUN: Proxmox host via SSH (root@pve)
# Edit VM config file (replace VMID with your VM's ID, e.g., 200)
ssh root@<your-proxmox-ip>
nano /etc/pve/qemu-server/VMID.conf

# Add or modify these lines:
# cpu: host
# balloon: 0
# numa: 1
```

Or configure via Proxmox Web UI: Select VM -> Hardware -> Edit each setting.

---

## Quick Start Commands (After VM Setup)

```powershell
# WHERE TO RUN: Windows 11 VM - PowerShell

# Create project directory
mkdir C:\Dev\sereno
cd C:\Dev\sereno

# First build
cargo build

# Run audits
cargo deny check
cargo audit

# Run tests
cargo test
```

