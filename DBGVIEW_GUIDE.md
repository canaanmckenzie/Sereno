# DbgView64 Setup for Sereno Driver Debugging

**Created:** 2026-01-12

## Why Not File Logging?

The file-based logging to `C:\sereno-driver-debug.log` is **intentionally disabled** in `driver.c` line ~155:
```c
// NOTE: File logging disabled - ZwCreateFile during DriverEntry can hang
// SerenoLogInit();
```

**Reason:** `ZwCreateFile` during DriverEntry can cause the driver load to hang.

---

## DbgView64 Quick Start

### 1. Download
https://learn.microsoft.com/en-us/sysinternals/downloads/debugview

### 2. Run as Administrator
Right-click → Run as Administrator (required for kernel capture)

### 3. Enable Kernel Capture
- **Capture menu → Capture Kernel** (or press Ctrl+K)
- **Capture menu → Enable Verbose Kernel Output**

### 4. Set Up Filter (Recommended)
- **Edit → Filter/Highlight**
- **Include:** `Sereno*`
- This filters out all the noise and shows only our driver's messages

---

## Testing Workflow

```powershell
# In Admin PowerShell:

# 1. Clear DbgView output: Edit → Clear Display (Ctrl+X)

# 2. Start driver
sc.exe start SerenoFilter

# 3. Watch DbgView for "Sereno: DriverEntry" message

# 4. Run TUI
cd C:\Users\Virgil\Desktop\sereno-dev
.\dev.ps1 -Run

# 5. In another terminal, test a connection
curl http://example.com

# 6. Watch DbgView for PEND/VERDICT/CACHE messages
```

---

## Key Messages to Look For

The driver uses `KdPrint()` with prefix "Sereno:":

| Message | Meaning |
|---------|---------|
| `Sereno: DriverEntry` | Driver loaded successfully |
| `Sereno: PEND NEW pid=X port=Y reqId=Z` | New connection pended to userspace |
| `Sereno: SET_VERDICT reqId=X verdict=Y` | Verdict received (1=ALLOW, 2=BLOCK) |
| `Sereno: CacheAdd pid=X port=Y verdict=Z` | Verdict added to cache |
| `Sereno: Cache HIT pid=X port=Y verdict=Z` | Re-auth found cached verdict |
| `Sereno: Cache MISS pid=X port=Y` | No cached verdict found |

---

## Troubleshooting

### No output at all?
1. Make sure "Capture Kernel" is checked (Ctrl+K)
2. Make sure running as Administrator
3. Check driver is running: `sc.exe query SerenoFilter`

### Too much noise?
Add include filter: `Sereno*`

### DbgView shows nothing for Sereno but driver is running?
The driver might not have KdPrint statements enabled. Check if `DBG` is defined in the build.

---

## If DbgView64 Doesn't Work - Fallback to File Logging

If DbgView64 fails to capture anything, enable deferred file logging:

1. In `driver.c`, find the IOCTL handler (around line 450)
2. Add at the start of the IOCTL handler:
```c
static BOOLEAN logInitialized = FALSE;
if (!logInitialized) {
    SerenoLogInit();
    SerenoLog("Logging initialized on first IOCTL");
    logInitialized = TRUE;
}
```

3. Rebuild driver: `.\dev.ps1 -BuildDriver`
4. Test and check: `Get-Content C:\sereno-driver-debug.log`

This defers log file creation until userspace connects, avoiding the DriverEntry hang.

---

## Update (2026-01-12): Debug Output Now Works in Release Builds

Changed all `KdPrint` calls to use `SERENO_DBG` macro which uses `DbgPrintEx`.
This ensures debug output works in both Debug and Release builds.

The macro is defined in `driver.c`:
```c
#define SERENO_DBG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Sereno: " fmt, ##__VA_ARGS__)
```
