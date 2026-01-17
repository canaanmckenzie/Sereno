# Sereno Reboot Plan - 2026-01-17 (Updated)

## Current State

We've implemented the **Network Coverage Enhancement** features. This includes **driver changes** that require a rebuild and reboot.

---

## What Was Implemented

### Phase 1: CLI-Only Changes (Already Working)

| Feature | Status | Key |
|---------|--------|-----|
| **Silent Allow Mode** | ✅ Done | `M` in Settings tab |
| **Connection Collapsing/Grouping** | ✅ Done | `G` in Connections tab |
| **IPv6 Improvements** | ✅ Done | Auto |

### Phase 2: Driver Changes (Require Rebuild + Reboot)

| Feature | Status | Notes |
|---------|--------|-------|
| **Incoming Connection Filtering** | ✅ Code Done | Driver pends inbound connections |
| **ICMP Visibility** | ✅ Structs Added | Full queue needs driver rebuild |

### Files Modified

**CLI (Rust):**
- `sereno-cli/src/tui/app.rs` - Mode, AuthStatus, GroupedConnection, ViewMode, direction
- `sereno-cli/src/tui/mod.rs` - Event handling, direction passing
- `sereno-cli/src/tui/ui.rs` - Direction display, grouped view, IPv6 truncation
- `sereno-cli/src/tui/events.rs` - `M` (mode) and `G` (group) key handlers
- `sereno-cli/src/driver.rs` - ICMP notification structs, get_icmp()

**Driver (C):**
- `sereno-driver/src/driver.h` - Added `IOCTL_SERENO_GET_ICMP`, `SERENO_ICMP_NOTIFICATION`
- `sereno-driver/src/driver.c` - Modified `SerenoClassifyRecvAccept` for interactive inbound filtering

---

## Step-by-Step Reboot Instructions

### BEFORE REBOOT (Do These Now)

#### Step 1: Stop the running driver
```powershell
sc.exe stop SerenoFilter
```

#### Step 2: Delete the driver service
```powershell
sc.exe delete SerenoFilter
```
If it says "FAILED 1072: service marked for deletion", that's OK.

#### Step 3: Rebuild the driver (IMPORTANT - driver code changed!)
```powershell
cd C:\Users\Virgil\Desktop\sereno-dev

# Set certificate thumbprint
$env:SERENO_CERT_THUMBPRINT = "1DC360B0502EDDBF7424ADF0D18EEDB70904523F"

# Build driver
.\dev.ps1 -BuildDriver
```

If this fails due to locked files, we'll rebuild after reboot.

#### Step 4: Copy new driver to system32
```powershell
Copy-Item .\sereno-driver\bin\x64\Release\SerenoFilter.sys C:\Windows\System32\drivers\ -Force
```

#### Step 5: Verify test signing is enabled
```powershell
bcdedit | findstr testsigning
```
Should show: `testsigning Yes`

#### Step 6: Reboot Windows
```powershell
Restart-Computer
```

---

### AFTER REBOOT (Do These In Order)

#### Step 1: Open PowerShell as Administrator

#### Step 2: Set environment and navigate
```powershell
$env:SERENO_CERT_THUMBPRINT = "1DC360B0502EDDBF7424ADF0D18EEDB70904523F"
cd C:\Users\Virgil\Desktop\sereno-dev
```

#### Step 3: Rebuild driver if needed (if pre-reboot build failed)
```powershell
.\dev.ps1 -BuildDriver
```

#### Step 4: Copy driver to system32 (if rebuild happened)
```powershell
Copy-Item .\sereno-driver\bin\x64\Release\SerenoFilter.sys C:\Windows\System32\drivers\ -Force
```

#### Step 5: Rebuild CLI
```powershell
cargo build --release -p sereno-cli
```

#### Step 6: Install driver service
```powershell
sc.exe create SerenoFilter type=kernel start=demand binPath="C:\Windows\System32\drivers\SerenoFilter.sys"
```
Expected: `[SC] CreateService SUCCESS`

#### Step 7: Start driver
```powershell
sc.exe start SerenoFilter
```
Expected: `STATE: 4 RUNNING`

#### Step 8: Run Sereno
```powershell
.\dev.ps1 -Run
```

---

## Testing the New Features

### 1. Silent Allow Mode (Settings tab)
```
Press Tab until you're on Settings tab
Press M to toggle mode
Header should show "Silent Allow" in magenta
New connections show "SA" instead of "ASK"
```

### 2. Connection Grouping (Connections tab)
```
Press G to toggle grouped view
Connections aggregate by destination:port
Shows connection count, unique processes, total bandwidth
Press G again to return to detailed view
```

### 3. Direction Indicator
```
Outbound connections show → (cyan)
Inbound connections show ← (yellow)
```

### 4. Inbound Filtering
```
# Start a simple HTTP server on another machine or:
python -m http.server 8000

# Connect to it from another device
# Should see ← INBOUND connection with ASK prompt
```

### 5. IPv6 Display
```
ping -6 google.com
# IPv6 addresses truncate to 25 chars for display
# Link-local (fe80:) shows as "System (IPv6 link-local)"
```

---

## Quick Reference

```powershell
# === Environment (every new terminal) ===
$env:SERENO_CERT_THUMBPRINT = "1DC360B0502EDDBF7424ADF0D18EEDB70904523F"
cd C:\Users\Virgil\Desktop\sereno-dev

# === Driver commands ===
sc.exe stop SerenoFilter
sc.exe start SerenoFilter
sc.exe query SerenoFilter
sc.exe delete SerenoFilter
sc.exe create SerenoFilter type=kernel start=demand binPath="C:\Windows\System32\drivers\SerenoFilter.sys"

# === Build commands ===
.\dev.ps1 -BuildDriver    # Build driver
cargo build --release -p sereno-cli  # Build CLI
.\dev.ps1 -Run            # Run TUI

# === Copy driver ===
Copy-Item .\sereno-driver\bin\x64\Release\SerenoFilter.sys C:\Windows\System32\drivers\ -Force
```

---

## Troubleshooting

### "StartService FAILED 2: file not found"
```powershell
# Check file exists
dir C:\Windows\System32\drivers\SerenoFilter.sys

# Re-copy if missing
Copy-Item .\sereno-driver\bin\x64\Release\SerenoFilter.sys C:\Windows\System32\drivers\ -Force

# Recreate service
sc.exe delete SerenoFilter
sc.exe create SerenoFilter type=kernel start=demand binPath="C:\Windows\System32\drivers\SerenoFilter.sys"
sc.exe start SerenoFilter
```

### "Access denied"
- Make sure PowerShell is running as Administrator
- Check test signing: `bcdedit | findstr testsigning`

### Driver crashes (TUI shows "Driver: Stopped")
- Check Event Viewer: Windows Logs > System > look for "SerenoFilter"
- May need to revert driver changes if new inbound filtering causes issues

### Rollback if needed
The previous driver binary is still in git. To restore:
```powershell
git checkout HEAD~1 -- sereno-driver/bin/x64/Release/SerenoFilter.sys
Copy-Item .\sereno-driver\bin\x64\Release\SerenoFilter.sys C:\Windows\System32\drivers\ -Force
```

---

## Implementation Summary

| Feature | Files Changed | Reboot? |
|---------|---------------|---------|
| Silent Allow Mode | app.rs, mod.rs, ui.rs, events.rs | No |
| Connection Grouping | app.rs, ui.rs, events.rs | No |
| Inbound Filtering | driver.c, app.rs, mod.rs, ui.rs | **Yes** |
| ICMP Visibility | driver.h, driver.rs | **Yes** |
| IPv6 Improvements | app.rs, ui.rs | No |

**CLI build: ✅ Compiles successfully**
**Driver build: Needs rebuild + reboot**

---

## Next Steps After Reboot

1. Test all new features work
2. Verify inbound connections prompt for decision
3. Check driver stability with new inbound filtering
4. If stable, ICMP queue can be fully implemented in next iteration
