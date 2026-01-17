/*
 * Sereno WFP Callout Driver - Main Implementation
 *
 * This driver implements synchronous connection filtering using WFP callouts
 * at the ALE (Application Layer Enforcement) layers.
 *
 * This is a non-PnP control device driver - it creates its own device
 * in DriverEntry rather than waiting for PnP enumeration.
 */

// INITGUID must be defined before including headers to actually define GUIDs
#define INITGUID
#include <initguid.h>
#include "driver.h"
// Debug output macro that works in BOTH Debug and Release builds
// KdPrint is disabled in Release, but DbgPrintEx always works
#define SERENO_DBG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Sereno: " fmt, ##__VA_ARGS__)

// SDDL string for device security (System full access, Administrators full access)
DECLARE_CONST_UNICODE_STRING(SERENO_DEVICE_SDDL, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

// Global device context pointer for callout functions
static PSERENO_DEVICE_CONTEXT g_DeviceContext = NULL;
static WDFDEVICE g_ControlDevice = NULL;

// Debug log file handle
static HANDLE g_LogFileHandle = NULL;
static FAST_MUTEX g_LogFileMutex;

// Forward declarations
EVT_WDF_DRIVER_UNLOAD SerenoEvtDriverUnload;

/*
 * SerenoLogInit - Initialize debug log file
 */
VOID SerenoLogInit(VOID)
{
    UNICODE_STRING logPath;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;

    ExInitializeFastMutex(&g_LogFileMutex);

    RtlInitUnicodeString(&logPath, L"\\??\\C:\\sereno-driver-debug.log");
    InitializeObjectAttributes(&objAttr, &logPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(
        &g_LogFileHandle,
        FILE_APPEND_DATA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL,
        0);

    if (!NT_SUCCESS(status)) {
        g_LogFileHandle = NULL;
        SERENO_DBG("Failed to create log file: 0x%08X\n", status);
    }
}

/*
 * SerenoLogClose - Close debug log file
 */
VOID SerenoLogClose(VOID)
{
    if (g_LogFileHandle) {
        ZwClose(g_LogFileHandle);
        g_LogFileHandle = NULL;
    }
}

/*
 * SerenoLog - Write to debug log file
 */
VOID SerenoLog(_In_ const char* Format, ...)
{
    char buffer[512];
    char* bufPtr;
    va_list args;
    IO_STATUS_BLOCK ioStatus;
    size_t remaining;
    LARGE_INTEGER time;
    TIME_FIELDS timeFields;
    NTSTATUS status;

    if (!g_LogFileHandle) return;

    // Get current time
    KeQuerySystemTime(&time);
    ExSystemTimeToLocalTime(&time, &time);
    RtlTimeToTimeFields(&time, &timeFields);

    // Format timestamp using kernel-safe string functions
    status = RtlStringCbPrintfA(buffer, sizeof(buffer), "[%02d:%02d:%02d.%03d] ",
        timeFields.Hour, timeFields.Minute, timeFields.Second, timeFields.Milliseconds);
    if (!NT_SUCCESS(status)) return;

    // Find end of timestamp
    status = RtlStringCbLengthA(buffer, sizeof(buffer), &remaining);
    if (!NT_SUCCESS(status)) return;
    bufPtr = buffer + remaining;
    remaining = sizeof(buffer) - remaining;

    // Format message
    va_start(args, Format);
    status = RtlStringCbVPrintfA(bufPtr, remaining, Format, args);
    va_end(args);
    if (!NT_SUCCESS(status)) return;

    // Get final length and add newline
    status = RtlStringCbLengthA(buffer, sizeof(buffer), &remaining);
    if (!NT_SUCCESS(status)) return;

    if (remaining > 0 && remaining < sizeof(buffer) - 1 && buffer[remaining-1] != '\n') {
        buffer[remaining++] = '\n';
        buffer[remaining] = '\0';
    }

    // Write to file (with mutex for thread safety)
    ExAcquireFastMutex(&g_LogFileMutex);
    ZwWriteFile(g_LogFileHandle, NULL, NULL, NULL, &ioStatus, buffer, (ULONG)remaining, NULL, NULL);
    ExReleaseFastMutex(&g_LogFileMutex);
}

/*
 * DriverEntry - Driver initialization
 *
 * For a non-PnP software driver, we create the control device directly here.
 */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES driverAttributes;
    WDFDRIVER driver;
    PWDFDEVICE_INIT deviceInit = NULL;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;
    PSERENO_DEVICE_CONTEXT deviceContext;
    DECLARE_CONST_UNICODE_STRING(deviceName, SERENO_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(symlinkName, SERENO_SYMLINK_NAME);

    SERENO_DBG("DriverEntry\n");

    // NOTE: File logging disabled - ZwCreateFile during DriverEntry can hang
    // Use DebugView with Capture Kernel to see KdPrint output instead
    // SerenoLogInit();
    // SERENO_DBG("DriverEntry starting");

    // Initialize driver config - no DeviceAdd callback for non-PnP driver
    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = SerenoEvtDriverUnload;

    WDF_OBJECT_ATTRIBUTES_INIT(&driverAttributes);

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &driverAttributes,
        &config,
        &driver
    );

    if (!NT_SUCCESS(status)) {
        SERENO_DBG("WdfDriverCreate failed: 0x%08X\n", status);
        return status;
    }

    // Allocate a device init structure for our control device
    deviceInit = WdfControlDeviceInitAllocate(driver, &SERENO_DEVICE_SDDL);
    if (deviceInit == NULL) {
        SERENO_DBG("WdfControlDeviceInitAllocate failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set device name
    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("WdfDeviceInitAssignName failed: 0x%08X\n", status);
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    // Set device type
    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetCharacteristics(deviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);

    // Set cleanup callback
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, SERENO_DEVICE_CONTEXT);
    deviceAttributes.EvtCleanupCallback = SerenoEvtDeviceContextCleanup;

    // Create device
    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &g_ControlDevice);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("WdfDeviceCreate failed: 0x%08X\n", status);
        // deviceInit is freed by WdfDeviceCreate on failure
        return status;
    }

    // Get device context
    deviceContext = SerenoGetDeviceContext(g_ControlDevice);
    RtlZeroMemory(deviceContext, sizeof(SERENO_DEVICE_CONTEXT));
    deviceContext->Device = g_ControlDevice;
    g_DeviceContext = deviceContext;

    // Initialize pending list
    InitializeListHead(&deviceContext->PendingList);
    KeInitializeSpinLock(&deviceContext->PendingLock);
    deviceContext->PendingCount = 0;
    deviceContext->NextRequestId = 1;
    deviceContext->FilteringEnabled = FALSE;
    deviceContext->ShuttingDown = FALSE;

    // Initialize DNS cache
    SerenoDnsCacheInit(deviceContext);

    // Initialize verdict cache (for re-authorization)
    RtlZeroMemory(deviceContext->VerdictCache, sizeof(deviceContext->VerdictCache));
    KeInitializeSpinLock(&deviceContext->VerdictCacheLock);

    // Initialize SNI cache (for TLS ClientHello domain extraction)
    RtlZeroMemory(deviceContext->SniCache, sizeof(deviceContext->SniCache));
    KeInitializeSpinLock(&deviceContext->SniCacheLock);

    // Initialize SNI notification queue (for sending SNI to usermode)
    RtlZeroMemory(deviceContext->SniNotifications, sizeof(deviceContext->SniNotifications));
    deviceContext->SniNotifyHead = 0;
    deviceContext->SniNotifyTail = 0;
    KeInitializeSpinLock(&deviceContext->SniNotifyLock);

    // Initialize blocked domain list (for SNI-based blocking)
    RtlZeroMemory(deviceContext->BlockedDomains, sizeof(deviceContext->BlockedDomains));
    deviceContext->BlockedDomainCount = 0;
    KeInitializeSpinLock(&deviceContext->BlockedDomainLock);

    // Initialize TLM bandwidth cache
    SerenoBandwidthCacheInit(deviceContext);

    // Create TCP injection handle for RST injection (Phase 2: SNI-based blocking)
    status = FwpsInjectionHandleCreate0(AF_UNSPEC, FWPS_INJECTION_TYPE_STREAM, &deviceContext->InjectionHandle);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpsInjectionHandleCreate0 failed: 0x%08X (RST injection disabled)\n", status);
        deviceContext->InjectionHandle = NULL;
        // Don't fail - RST injection is optional enhancement
    } else {
        SERENO_DBG("TCP injection handle created successfully\n");
    }

    // Create symbolic link
    status = WdfDeviceCreateSymbolicLink(g_ControlDevice, &symlinkName);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("WdfDeviceCreateSymbolicLink failed: 0x%08X\n", status);
        return status;
    }

    // Create I/O queue
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = SerenoEvtIoDeviceControl;

    status = WdfIoQueueCreate(g_ControlDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("WdfIoQueueCreate failed: 0x%08X\n", status);
        return status;
    }

    // Register WFP callouts
    status = SerenoRegisterCallouts(deviceContext);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("SerenoRegisterCallouts failed: 0x%08X\n", status);
        // Don't fail driver load, just log
    }

    // Finish initializing the control device
    WdfControlFinishInitializing(g_ControlDevice);

    SERENO_DBG("Driver initialized successfully\n");
    return STATUS_SUCCESS;
}

/*
 * SerenoEvtDriverUnload - Called when driver is unloading
 */
VOID
SerenoEvtDriverUnload(
    _In_ WDFDRIVER Driver
)
{
    UNREFERENCED_PARAMETER(Driver);
    // SERENO_DBG("Driver unloading");  // Disabled - file logging not initialized
    SERENO_DBG("Driver unloading\n");

    // Cleanup is handled by device context cleanup callback
    if (g_ControlDevice != NULL) {
        WdfObjectDelete(g_ControlDevice);
        g_ControlDevice = NULL;
    }

    // SerenoLogClose();  // Disabled - file logging not initialized
}

/*
 * SerenoEvtDeviceAdd - Not used for non-PnP driver but kept for reference
 */
NTSTATUS
SerenoEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    UNREFERENCED_PARAMETER(Driver);
    UNREFERENCED_PARAMETER(DeviceInit);
    // Not used - we create the device in DriverEntry
    return STATUS_SUCCESS;
}

/*
 * SerenoEvtDeviceContextCleanup - Cleanup on device removal
 *
 * NON-BLOCKING MODEL: Just free all pending requests (no threads to unblock)
 */
VOID
SerenoEvtDeviceContextCleanup(
    _In_ WDFOBJECT Device
)
{
    PSERENO_DEVICE_CONTEXT deviceContext;
    PLIST_ENTRY entry;
    PPENDING_REQUEST request;
    KIRQL oldIrql;
    LIST_ENTRY tempList;

    SERENO_DBG("SerenoEvtDeviceContextCleanup\n");

    deviceContext = SerenoGetDeviceContext(Device);
    deviceContext->ShuttingDown = TRUE;

    // Unregister WFP callouts first (prevents new connections)
    SerenoUnregisterCallouts(deviceContext);

    // Free DNS cache
    SerenoDnsCacheCleanup(deviceContext);

    // Move all pending requests to temp list (under lock)
    InitializeListHead(&tempList);
    KeAcquireSpinLock(&deviceContext->PendingLock, &oldIrql);
    while (!IsListEmpty(&deviceContext->PendingList)) {
        entry = RemoveHeadList(&deviceContext->PendingList);
        InsertTailList(&tempList, entry);
        deviceContext->PendingCount--;
    }
    KeReleaseSpinLock(&deviceContext->PendingLock, oldIrql);

    // Free all pending requests
    while (!IsListEmpty(&tempList)) {
        entry = RemoveHeadList(&tempList);
        request = CONTAINING_RECORD(entry, PENDING_REQUEST, ListEntry);
        SerenoFreePendingRequest(request);
    }

    g_DeviceContext = NULL;
    SERENO_DBG("Cleanup complete\n");
}

/*
 * SerenoEvtIoDeviceControl - Handle IOCTLs from user-mode
 */
VOID
SerenoEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PSERENO_DEVICE_CONTEXT deviceContext;
    size_t bytesReturned = 0;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    deviceContext = SerenoGetDeviceContext(WdfIoQueueGetDevice(Queue));

    switch (IoControlCode) {

    case IOCTL_SERENO_GET_PENDING:
    {
        // Return next pending connection request to user-mode
        PSERENO_CONNECTION_REQUEST outRequest;
        PLIST_ENTRY entry;
        PPENDING_REQUEST pendingRequest;
        KIRQL oldIrql;

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(SERENO_CONNECTION_REQUEST), &outputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        outRequest = (PSERENO_CONNECTION_REQUEST)outputBuffer;

        KeAcquireSpinLock(&deviceContext->PendingLock, &oldIrql);
        if (!IsListEmpty(&deviceContext->PendingList)) {
            // Get first pending request that hasn't been sent to user-mode yet
            for (entry = deviceContext->PendingList.Flink;
                 entry != &deviceContext->PendingList;
                 entry = entry->Flink) {
                pendingRequest = CONTAINING_RECORD(entry, PENDING_REQUEST, ListEntry);
                if (pendingRequest->Verdict == SERENO_VERDICT_PENDING && !pendingRequest->SentToUserMode) {
                    pendingRequest->SentToUserMode = TRUE;
                    RtlCopyMemory(outRequest, &pendingRequest->ConnectionInfo, sizeof(SERENO_CONNECTION_REQUEST));
                    bytesReturned = sizeof(SERENO_CONNECTION_REQUEST);
                    break;
                }
            }
        }
        KeReleaseSpinLock(&deviceContext->PendingLock, oldIrql);

        if (bytesReturned == 0) {
            status = STATUS_NO_MORE_ENTRIES;
        }
        break;
    }

    case IOCTL_SERENO_SET_VERDICT:
    {
        // Set verdict for a pending request
        PSERENO_VERDICT_RESPONSE verdictResponse;

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(SERENO_VERDICT_RESPONSE), &inputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        verdictResponse = (PSERENO_VERDICT_RESPONSE)inputBuffer;

        SERENO_DBG("IOCTL SET_VERDICT reqId=%llu verdict=%u",
                 verdictResponse->RequestId, verdictResponse->Verdict);

        SerenoCompletePendingRequest(
            deviceContext,
            verdictResponse->RequestId,
            (SERENO_VERDICT)verdictResponse->Verdict
        );
        break;
    }

    case IOCTL_SERENO_GET_STATS:
    {
        // Return statistics
        PSERENO_STATS stats;

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(SERENO_STATS), &outputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        stats = (PSERENO_STATS)outputBuffer;
        stats->TotalConnections = deviceContext->Stats.TotalConnections;
        stats->AllowedConnections = deviceContext->Stats.AllowedConnections;
        stats->BlockedConnections = deviceContext->Stats.BlockedConnections;
        stats->PendingRequests = deviceContext->PendingCount;
        stats->TimedOutRequests = deviceContext->Stats.TimedOutRequests;
        stats->DroppedRequests = deviceContext->Stats.DroppedRequests;
        bytesReturned = sizeof(SERENO_STATS);
        break;
    }

    case IOCTL_SERENO_ENABLE:
    {
        // Reset circuit breaker when re-enabling
        deviceContext->Stats.TimedOutRequests = 0;
        deviceContext->FilteringEnabled = TRUE;
        SERENO_DBG("Filtering enabled (circuit breaker reset)\n");
        break;
    }

    case IOCTL_SERENO_DISABLE:
    {
        deviceContext->FilteringEnabled = FALSE;
        SERENO_DBG("Filtering disabled\n");
        break;
    }

    case IOCTL_SERENO_GET_SNI:
    {
        // Return next SNI notification from queue
        PSERENO_SNI_NOTIFICATION outNotification;

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(SERENO_SNI_NOTIFICATION), &outputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        outNotification = (PSERENO_SNI_NOTIFICATION)outputBuffer;

        if (SerenoSniNotifyGet(deviceContext, outNotification)) {
            bytesReturned = sizeof(SERENO_SNI_NOTIFICATION);
            status = STATUS_SUCCESS;
        } else {
            // No notifications in queue
            status = STATUS_NO_MORE_ENTRIES;
            bytesReturned = 0;
        }
        break;
    }

    case IOCTL_SERENO_ADD_BLOCKED_DOMAIN:
    {
        // Add a domain to the blocked domain list (for SNI-based blocking)
        PSERENO_BLOCKED_DOMAIN_REQUEST inRequest;

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(SERENO_BLOCKED_DOMAIN_REQUEST), &inputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        inRequest = (PSERENO_BLOCKED_DOMAIN_REQUEST)inputBuffer;

        if (SerenoBlockedDomainAdd(deviceContext, inRequest->DomainName, inRequest->DomainNameLength)) {
            SERENO_DBG("Added blocked domain: %S\n", inRequest->DomainName);
            status = STATUS_SUCCESS;
        } else {
            SERENO_DBG("Failed to add blocked domain (list full or invalid)\n");
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        break;
    }

    case IOCTL_SERENO_CLEAR_BLOCKED_DOMAINS:
    {
        // Clear all blocked domains
        SerenoBlockedDomainClear(deviceContext);
        SERENO_DBG("Cleared all blocked domains\n");
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_SERENO_GET_BANDWIDTH:
    {
        // Get bandwidth statistics for usermode
        PSERENO_BANDWIDTH_STATS outStats;
        SERENO_DBG("GET_BANDWIDTH: sizeof(ENTRY)=%u, sizeof(STATS)=%u\n",
            (UINT32)sizeof(SERENO_BANDWIDTH_ENTRY), (UINT32)sizeof(SERENO_BANDWIDTH_STATS));
        status = WdfRequestRetrieveOutputBuffer(Request,
            sizeof(SERENO_BANDWIDTH_STATS), &outputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            SERENO_DBG("GET_BANDWIDTH: Failed to get output buffer: 0x%08X\n", status);
            break;
        }

        outStats = (PSERENO_BANDWIDTH_STATS)outputBuffer;
        SerenoBandwidthGetStats(deviceContext, outStats);
        bytesReturned = sizeof(SERENO_BANDWIDTH_STATS);
        SERENO_DBG("GET_BANDWIDTH: Returned %u entries (total %u)\n",
            outStats->ReturnedCount, outStats->TotalEntries);
        status = STATUS_SUCCESS;
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}

/*
 * SerenoRegisterCallouts - Register WFP callouts and filters
 */
NTSTATUS
SerenoRegisterCallouts(
    _In_ PSERENO_DEVICE_CONTEXT DeviceContext
)
{
    NTSTATUS status;
    FWPM_SESSION0 session = { 0 };
    FWPM_PROVIDER0 provider = { 0 };
    FWPM_SUBLAYER0 sublayer = { 0 };
    FWPS_CALLOUT3 sCallout = { 0 };
    FWPM_CALLOUT0 mCallout = { 0 };
    FWPM_FILTER0 filter = { 0 };

    SERENO_DBG("Registering callouts\n");

    // Open WFP engine
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &DeviceContext->EngineHandle);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpmEngineOpen0 failed: 0x%08X\n", status);
        return status;
    }

    // Start transaction
    status = FwpmTransactionBegin0(DeviceContext->EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpmTransactionBegin0 failed: 0x%08X\n", status);
        goto cleanup;
    }

    // Add provider
    provider.providerKey = SERENO_PROVIDER_GUID;
    provider.displayData.name = L"Sereno Network Filter";
    provider.displayData.description = L"Sereno Application Firewall Provider";
    provider.flags = 0;

    status = FwpmProviderAdd0(DeviceContext->EngineHandle, &provider, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        SERENO_DBG("FwpmProviderAdd0 failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Add sublayer
    sublayer.subLayerKey = SERENO_SUBLAYER_GUID;
    sublayer.displayData.name = L"Sereno Sublayer";
    sublayer.displayData.description = L"Sereno Filtering Sublayer";
    sublayer.providerKey = (GUID*)&SERENO_PROVIDER_GUID;
    sublayer.weight = 0xFFFF; // High priority

    status = FwpmSubLayerAdd0(DeviceContext->EngineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        SERENO_DBG("FwpmSubLayerAdd0 failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Register Connect V4 callout
    sCallout.calloutKey = SERENO_CALLOUT_CONNECT_V4_GUID;
    sCallout.classifyFn = SerenoClassifyConnect;
    sCallout.notifyFn = SerenoNotify;
    sCallout.flowDeleteFn = SerenoFlowDelete;
    sCallout.flags = 0;

    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(DeviceContext->Device),
                                   &sCallout, &DeviceContext->ConnectCalloutIdV4);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpsCalloutRegister3 (Connect V4) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Add Connect V4 callout to filter engine
    mCallout.calloutKey = SERENO_CALLOUT_CONNECT_V4_GUID;
    mCallout.displayData.name = L"Sereno Connect V4 Callout";
    mCallout.displayData.description = L"Intercepts outbound IPv4 connections";
    mCallout.providerKey = (GUID*)&SERENO_PROVIDER_GUID;
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;

    status = FwpmCalloutAdd0(DeviceContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        SERENO_DBG("FwpmCalloutAdd0 (Connect V4) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Register Connect V6 callout
    sCallout.calloutKey = SERENO_CALLOUT_CONNECT_V6_GUID;
    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(DeviceContext->Device),
                                   &sCallout, &DeviceContext->ConnectCalloutIdV6);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpsCalloutRegister3 (Connect V6) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    mCallout.calloutKey = SERENO_CALLOUT_CONNECT_V6_GUID;
    mCallout.displayData.name = L"Sereno Connect V6 Callout";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

    status = FwpmCalloutAdd0(DeviceContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        SERENO_DBG("FwpmCalloutAdd0 (Connect V6) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Add filter for Connect V4
    filter.filterKey = GUID_NULL;
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.displayData.name = L"Sereno Connect V4 Filter";
    filter.displayData.description = L"Filters outbound IPv4 connections";
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = SERENO_CALLOUT_CONNECT_V4_GUID;
    filter.subLayerKey = SERENO_SUBLAYER_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0xF;
    filter.numFilterConditions = 0;
    filter.filterCondition = NULL;

    status = FwpmFilterAdd0(DeviceContext->EngineHandle, &filter, NULL, &DeviceContext->ConnectFilterIdV4);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpmFilterAdd0 (Connect V4) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Add filter for Connect V6
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.displayData.name = L"Sereno Connect V6 Filter";
    filter.action.calloutKey = SERENO_CALLOUT_CONNECT_V6_GUID;

    status = FwpmFilterAdd0(DeviceContext->EngineHandle, &filter, NULL, &DeviceContext->ConnectFilterIdV6);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpmFilterAdd0 (Connect V6) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // ========================================
    // DNS Interception Callouts (port 53 UDP)
    // ========================================

    // Register DNS V4 callout
    sCallout.calloutKey = SERENO_CALLOUT_DNS_V4_GUID;
    sCallout.classifyFn = SerenoClassifyDns;
    sCallout.notifyFn = SerenoNotify;
    sCallout.flowDeleteFn = SerenoFlowDelete;
    sCallout.flags = 0;

    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(DeviceContext->Device),
                                   &sCallout, &DeviceContext->DnsCalloutIdV4);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpsCalloutRegister3 (DNS V4) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Add DNS V4 callout to filter engine
    mCallout.calloutKey = SERENO_CALLOUT_DNS_V4_GUID;
    mCallout.displayData.name = L"Sereno DNS V4 Callout";
    mCallout.displayData.description = L"Intercepts DNS responses for domain resolution";
    mCallout.providerKey = (GUID*)&SERENO_PROVIDER_GUID;
    mCallout.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4;

    status = FwpmCalloutAdd0(DeviceContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        SERENO_DBG("FwpmCalloutAdd0 (DNS V4) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Register DNS V6 callout
    sCallout.calloutKey = SERENO_CALLOUT_DNS_V6_GUID;
    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(DeviceContext->Device),
                                   &sCallout, &DeviceContext->DnsCalloutIdV6);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpsCalloutRegister3 (DNS V6) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    mCallout.calloutKey = SERENO_CALLOUT_DNS_V6_GUID;
    mCallout.displayData.name = L"Sereno DNS V6 Callout";
    mCallout.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V6;

    status = FwpmCalloutAdd0(DeviceContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        SERENO_DBG("FwpmCalloutAdd0 (DNS V6) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Add DNS filter V4 - only match UDP port 53 (inbound DNS responses)
    {
        FWPM_FILTER_CONDITION0 dnsConditions[2];

        // Condition 1: UDP protocol
        dnsConditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        dnsConditions[0].matchType = FWP_MATCH_EQUAL;
        dnsConditions[0].conditionValue.type = FWP_UINT8;
        dnsConditions[0].conditionValue.uint8 = IPPROTO_UDP;

        // Condition 2: Source port 53 (DNS server response)
        dnsConditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        dnsConditions[1].matchType = FWP_MATCH_EQUAL;
        dnsConditions[1].conditionValue.type = FWP_UINT16;
        dnsConditions[1].conditionValue.uint16 = 53;

        filter.filterKey = GUID_NULL;
        filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
        filter.displayData.name = L"Sereno DNS V4 Filter";
        filter.displayData.description = L"Captures DNS responses";
        filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;  // Inspect only, don't block
        filter.action.calloutKey = SERENO_CALLOUT_DNS_V4_GUID;
        filter.subLayerKey = SERENO_SUBLAYER_GUID;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 0xF;
        filter.numFilterConditions = 2;
        filter.filterCondition = dnsConditions;

        status = FwpmFilterAdd0(DeviceContext->EngineHandle, &filter, NULL, &DeviceContext->DnsFilterIdV4);
        if (!NT_SUCCESS(status)) {
            SERENO_DBG("FwpmFilterAdd0 (DNS V4) failed: 0x%08X\n", status);
            FwpmTransactionAbort0(DeviceContext->EngineHandle);
            goto cleanup;
        }

        // Add DNS filter V6
        filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V6;
        filter.displayData.name = L"Sereno DNS V6 Filter";
        filter.action.calloutKey = SERENO_CALLOUT_DNS_V6_GUID;

        status = FwpmFilterAdd0(DeviceContext->EngineHandle, &filter, NULL, &DeviceContext->DnsFilterIdV6);
        if (!NT_SUCCESS(status)) {
            SERENO_DBG("FwpmFilterAdd0 (DNS V6) failed: 0x%08X\n", status);
            FwpmTransactionAbort0(DeviceContext->EngineHandle);
            goto cleanup;
        }
    }

    // ========================================
    // Stream Callouts (SNI Inspection - port 443 HTTPS)
    // ========================================

    // Register Stream V4 callout
    sCallout.calloutKey = SERENO_CALLOUT_STREAM_V4_GUID;
    sCallout.classifyFn = SerenoClassifyStream;
    sCallout.notifyFn = SerenoNotify;
    sCallout.flowDeleteFn = SerenoFlowDelete;
    sCallout.flags = 0;

    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(DeviceContext->Device),
                                   &sCallout, &DeviceContext->StreamCalloutIdV4);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpsCalloutRegister3 (Stream V4) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Add Stream V4 callout to filter engine
    mCallout.calloutKey = SERENO_CALLOUT_STREAM_V4_GUID;
    mCallout.displayData.name = L"Sereno Stream V4 Callout";
    mCallout.displayData.description = L"Inspects TCP streams for TLS SNI extraction";
    mCallout.providerKey = (GUID*)&SERENO_PROVIDER_GUID;
    mCallout.applicableLayer = FWPM_LAYER_STREAM_V4;

    status = FwpmCalloutAdd0(DeviceContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        SERENO_DBG("FwpmCalloutAdd0 (Stream V4) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Register Stream V6 callout
    sCallout.calloutKey = SERENO_CALLOUT_STREAM_V6_GUID;
    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(DeviceContext->Device),
                                   &sCallout, &DeviceContext->StreamCalloutIdV6);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpsCalloutRegister3 (Stream V6) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    mCallout.calloutKey = SERENO_CALLOUT_STREAM_V6_GUID;
    mCallout.displayData.name = L"Sereno Stream V6 Callout";
    mCallout.applicableLayer = FWPM_LAYER_STREAM_V6;

    status = FwpmCalloutAdd0(DeviceContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        SERENO_DBG("FwpmCalloutAdd0 (Stream V6) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Add Stream filter V4 - only match port 443 (HTTPS)
    // NOTE: Stream layer is TCP-only by definition, no protocol condition needed
    {
        FWPM_FILTER_CONDITION0 streamConditions[1];

        // Condition: Remote port 443 (HTTPS)
        streamConditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        streamConditions[0].matchType = FWP_MATCH_EQUAL;
        streamConditions[0].conditionValue.type = FWP_UINT16;
        streamConditions[0].conditionValue.uint16 = 443;

        filter.filterKey = GUID_NULL;
        filter.layerKey = FWPM_LAYER_STREAM_V4;
        filter.displayData.name = L"Sereno Stream V4 Filter";
        filter.displayData.description = L"Inspects HTTPS traffic for SNI";
        filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;  // Inspect only, don't block
        filter.action.calloutKey = SERENO_CALLOUT_STREAM_V4_GUID;
        filter.subLayerKey = SERENO_SUBLAYER_GUID;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 0xF;
        filter.numFilterConditions = 1;
        filter.filterCondition = streamConditions;

        status = FwpmFilterAdd0(DeviceContext->EngineHandle, &filter, NULL, &DeviceContext->StreamFilterIdV4);
        if (!NT_SUCCESS(status)) {
            SERENO_DBG("FwpmFilterAdd0 (Stream V4) failed: 0x%08X\n", status);
            FwpmTransactionAbort0(DeviceContext->EngineHandle);
            goto cleanup;
        }

        // Add Stream filter V6
        filter.layerKey = FWPM_LAYER_STREAM_V6;
        filter.displayData.name = L"Sereno Stream V6 Filter";
        filter.action.calloutKey = SERENO_CALLOUT_STREAM_V6_GUID;

        status = FwpmFilterAdd0(DeviceContext->EngineHandle, &filter, NULL, &DeviceContext->StreamFilterIdV6);
        if (!NT_SUCCESS(status)) {
            SERENO_DBG("FwpmFilterAdd0 (Stream V6) failed: 0x%08X\n", status);
            FwpmTransactionAbort0(DeviceContext->EngineHandle);
            goto cleanup;
        }
    }

    // ========================================
    // TLM (Transport Layer Module) Callouts - Bandwidth Statistics
    // These callouts count bytes sent/received per connection
    // ========================================

    // Register Transport Outbound V4 callout
    sCallout.calloutKey = SERENO_CALLOUT_TRANSPORT_OUT_V4_GUID;
    sCallout.classifyFn = SerenoClassifyTransportOutbound;
    sCallout.notifyFn = SerenoNotify;
    sCallout.flowDeleteFn = SerenoFlowDelete;
    sCallout.flags = 0;

    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(DeviceContext->Device),
                                   &sCallout, &DeviceContext->TransportOutCalloutIdV4);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpsCalloutRegister3 (Transport Out V4) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Add Transport Outbound V4 callout to filter engine
    mCallout.calloutKey = SERENO_CALLOUT_TRANSPORT_OUT_V4_GUID;
    mCallout.displayData.name = L"Sereno Transport Outbound V4 Callout";
    mCallout.displayData.description = L"Counts bytes sent per connection (TLM bandwidth)";
    mCallout.providerKey = (GUID*)&SERENO_PROVIDER_GUID;
    mCallout.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;

    status = FwpmCalloutAdd0(DeviceContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        SERENO_DBG("FwpmCalloutAdd0 (Transport Out V4) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Register Transport Outbound V6 callout
    sCallout.calloutKey = SERENO_CALLOUT_TRANSPORT_OUT_V6_GUID;
    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(DeviceContext->Device),
                                   &sCallout, &DeviceContext->TransportOutCalloutIdV6);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpsCalloutRegister3 (Transport Out V6) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    mCallout.calloutKey = SERENO_CALLOUT_TRANSPORT_OUT_V6_GUID;
    mCallout.displayData.name = L"Sereno Transport Outbound V6 Callout";
    mCallout.applicableLayer = FWPM_LAYER_OUTBOUND_TRANSPORT_V6;

    status = FwpmCalloutAdd0(DeviceContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        SERENO_DBG("FwpmCalloutAdd0 (Transport Out V6) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Register Transport Inbound V4 callout
    sCallout.calloutKey = SERENO_CALLOUT_TRANSPORT_IN_V4_GUID;
    sCallout.classifyFn = SerenoClassifyTransportInbound;

    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(DeviceContext->Device),
                                   &sCallout, &DeviceContext->TransportInCalloutIdV4);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpsCalloutRegister3 (Transport In V4) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    mCallout.calloutKey = SERENO_CALLOUT_TRANSPORT_IN_V4_GUID;
    mCallout.displayData.name = L"Sereno Transport Inbound V4 Callout";
    mCallout.displayData.description = L"Counts bytes received per connection (TLM bandwidth)";
    mCallout.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V4;

    status = FwpmCalloutAdd0(DeviceContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        SERENO_DBG("FwpmCalloutAdd0 (Transport In V4) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Register Transport Inbound V6 callout
    sCallout.calloutKey = SERENO_CALLOUT_TRANSPORT_IN_V6_GUID;

    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(DeviceContext->Device),
                                   &sCallout, &DeviceContext->TransportInCalloutIdV6);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpsCalloutRegister3 (Transport In V6) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    mCallout.calloutKey = SERENO_CALLOUT_TRANSPORT_IN_V6_GUID;
    mCallout.displayData.name = L"Sereno Transport Inbound V6 Callout";
    mCallout.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V6;

    status = FwpmCalloutAdd0(DeviceContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        SERENO_DBG("FwpmCalloutAdd0 (Transport In V6) failed: 0x%08X\n", status);
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Add TLM filters (no conditions - inspect all transport traffic)
    {
        RtlZeroMemory(&filter, sizeof(filter));
        filter.subLayerKey = SERENO_SUBLAYER_GUID;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 0x5;  // Lower weight than ALE/Stream (less priority)
        filter.numFilterConditions = 0;  // No conditions - all traffic

        // Transport Outbound V4 filter
        filter.filterKey = GUID_NULL;
        filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
        filter.displayData.name = L"Sereno Transport Outbound V4 Filter";
        filter.displayData.description = L"TLM bandwidth counting - outbound";
        filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;  // Inspect only, don't block
        filter.action.calloutKey = SERENO_CALLOUT_TRANSPORT_OUT_V4_GUID;

        status = FwpmFilterAdd0(DeviceContext->EngineHandle, &filter, NULL, &DeviceContext->TransportOutFilterIdV4);
        if (!NT_SUCCESS(status)) {
            SERENO_DBG("FwpmFilterAdd0 (Transport Out V4) failed: 0x%08X\n", status);
            FwpmTransactionAbort0(DeviceContext->EngineHandle);
            goto cleanup;
        }

        // Transport Outbound V6 filter
        filter.layerKey = FWPM_LAYER_OUTBOUND_TRANSPORT_V6;
        filter.displayData.name = L"Sereno Transport Outbound V6 Filter";
        filter.action.calloutKey = SERENO_CALLOUT_TRANSPORT_OUT_V6_GUID;

        status = FwpmFilterAdd0(DeviceContext->EngineHandle, &filter, NULL, &DeviceContext->TransportOutFilterIdV6);
        if (!NT_SUCCESS(status)) {
            SERENO_DBG("FwpmFilterAdd0 (Transport Out V6) failed: 0x%08X\n", status);
            FwpmTransactionAbort0(DeviceContext->EngineHandle);
            goto cleanup;
        }

        // Transport Inbound V4 filter
        filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V4;
        filter.displayData.name = L"Sereno Transport Inbound V4 Filter";
        filter.displayData.description = L"TLM bandwidth counting - inbound";
        filter.action.calloutKey = SERENO_CALLOUT_TRANSPORT_IN_V4_GUID;

        status = FwpmFilterAdd0(DeviceContext->EngineHandle, &filter, NULL, &DeviceContext->TransportInFilterIdV4);
        if (!NT_SUCCESS(status)) {
            SERENO_DBG("FwpmFilterAdd0 (Transport In V4) failed: 0x%08X\n", status);
            FwpmTransactionAbort0(DeviceContext->EngineHandle);
            goto cleanup;
        }

        // Transport Inbound V6 filter
        filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V6;
        filter.displayData.name = L"Sereno Transport Inbound V6 Filter";
        filter.action.calloutKey = SERENO_CALLOUT_TRANSPORT_IN_V6_GUID;

        status = FwpmFilterAdd0(DeviceContext->EngineHandle, &filter, NULL, &DeviceContext->TransportInFilterIdV6);
        if (!NT_SUCCESS(status)) {
            SERENO_DBG("FwpmFilterAdd0 (Transport In V6) failed: 0x%08X\n", status);
            FwpmTransactionAbort0(DeviceContext->EngineHandle);
            goto cleanup;
        }
    }

    SERENO_DBG("TLM callouts registered successfully\n");

    // Commit transaction
    status = FwpmTransactionCommit0(DeviceContext->EngineHandle);
    if (!NT_SUCCESS(status)) {
        SERENO_DBG("FwpmTransactionCommit0 failed: 0x%08X\n", status);
        goto cleanup;
    }

    SERENO_DBG("Callouts registered successfully\n");
    return STATUS_SUCCESS;

cleanup:
    if (DeviceContext->EngineHandle) {
        FwpmEngineClose0(DeviceContext->EngineHandle);
        DeviceContext->EngineHandle = NULL;
    }
    return status;
}

/*
 * SerenoUnregisterCallouts - Remove WFP callouts and filters
 */
VOID
SerenoUnregisterCallouts(
    _In_ PSERENO_DEVICE_CONTEXT DeviceContext
)
{
    SERENO_DBG("Unregistering callouts\n");

    if (DeviceContext->EngineHandle) {
        // Remove connection filters
        if (DeviceContext->ConnectFilterIdV4) {
            FwpmFilterDeleteById0(DeviceContext->EngineHandle, DeviceContext->ConnectFilterIdV4);
        }
        if (DeviceContext->ConnectFilterIdV6) {
            FwpmFilterDeleteById0(DeviceContext->EngineHandle, DeviceContext->ConnectFilterIdV6);
        }

        // Remove DNS filters
        if (DeviceContext->DnsFilterIdV4) {
            FwpmFilterDeleteById0(DeviceContext->EngineHandle, DeviceContext->DnsFilterIdV4);
        }
        if (DeviceContext->DnsFilterIdV6) {
            FwpmFilterDeleteById0(DeviceContext->EngineHandle, DeviceContext->DnsFilterIdV6);
        }

        // Remove Stream filters
        if (DeviceContext->StreamFilterIdV4) {
            FwpmFilterDeleteById0(DeviceContext->EngineHandle, DeviceContext->StreamFilterIdV4);
        }
        if (DeviceContext->StreamFilterIdV6) {
            FwpmFilterDeleteById0(DeviceContext->EngineHandle, DeviceContext->StreamFilterIdV6);
        }

        // Remove TLM (Transport) filters
        if (DeviceContext->TransportOutFilterIdV4) {
            FwpmFilterDeleteById0(DeviceContext->EngineHandle, DeviceContext->TransportOutFilterIdV4);
        }
        if (DeviceContext->TransportOutFilterIdV6) {
            FwpmFilterDeleteById0(DeviceContext->EngineHandle, DeviceContext->TransportOutFilterIdV6);
        }
        if (DeviceContext->TransportInFilterIdV4) {
            FwpmFilterDeleteById0(DeviceContext->EngineHandle, DeviceContext->TransportInFilterIdV4);
        }
        if (DeviceContext->TransportInFilterIdV6) {
            FwpmFilterDeleteById0(DeviceContext->EngineHandle, DeviceContext->TransportInFilterIdV6);
        }

        FwpmEngineClose0(DeviceContext->EngineHandle);
        DeviceContext->EngineHandle = NULL;
    }

    // Unregister connection callouts
    if (DeviceContext->ConnectCalloutIdV4) {
        FwpsCalloutUnregisterById0(DeviceContext->ConnectCalloutIdV4);
        DeviceContext->ConnectCalloutIdV4 = 0;
    }
    if (DeviceContext->ConnectCalloutIdV6) {
        FwpsCalloutUnregisterById0(DeviceContext->ConnectCalloutIdV6);
        DeviceContext->ConnectCalloutIdV6 = 0;
    }

    // Unregister DNS callouts
    if (DeviceContext->DnsCalloutIdV4) {
        FwpsCalloutUnregisterById0(DeviceContext->DnsCalloutIdV4);
        DeviceContext->DnsCalloutIdV4 = 0;
    }
    if (DeviceContext->DnsCalloutIdV6) {
        FwpsCalloutUnregisterById0(DeviceContext->DnsCalloutIdV6);
        DeviceContext->DnsCalloutIdV6 = 0;
    }

    // Unregister Stream callouts
    if (DeviceContext->StreamCalloutIdV4) {
        FwpsCalloutUnregisterById0(DeviceContext->StreamCalloutIdV4);
        DeviceContext->StreamCalloutIdV4 = 0;
    }
    if (DeviceContext->StreamCalloutIdV6) {
        FwpsCalloutUnregisterById0(DeviceContext->StreamCalloutIdV6);
        DeviceContext->StreamCalloutIdV6 = 0;
    }

    // Unregister TLM (Transport) callouts
    if (DeviceContext->TransportOutCalloutIdV4) {
        FwpsCalloutUnregisterById0(DeviceContext->TransportOutCalloutIdV4);
        DeviceContext->TransportOutCalloutIdV4 = 0;
    }
    if (DeviceContext->TransportOutCalloutIdV6) {
        FwpsCalloutUnregisterById0(DeviceContext->TransportOutCalloutIdV6);
        DeviceContext->TransportOutCalloutIdV6 = 0;
    }
    if (DeviceContext->TransportInCalloutIdV4) {
        FwpsCalloutUnregisterById0(DeviceContext->TransportInCalloutIdV4);
        DeviceContext->TransportInCalloutIdV4 = 0;
    }
    if (DeviceContext->TransportInCalloutIdV6) {
        FwpsCalloutUnregisterById0(DeviceContext->TransportInCalloutIdV6);
        DeviceContext->TransportInCalloutIdV6 = 0;
    }

    // Destroy injection handle (for TCP RST injection)
    if (DeviceContext->InjectionHandle) {
        FwpsInjectionHandleDestroy0(DeviceContext->InjectionHandle);
        DeviceContext->InjectionHandle = NULL;
    }

    SERENO_DBG("Callouts unregistered\n");
}

/*
 * SerenoClassifyConnect - Main classification function for connection attempts
 *
 * ASYNC PENDING MODEL:
 * This function uses FwpsPendOperation0/FwpsCompleteOperation0 for async verdict delivery.
 * It NEVER blocks kernel threads - the connection is pended and we return immediately.
 * When user-mode sends a verdict, SerenoCompletePendingRequest calls FwpsCompleteOperation0.
 */
VOID NTAPI
SerenoClassifyConnect(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER3* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    PSERENO_DEVICE_CONTEXT deviceContext = g_DeviceContext;
    PPENDING_REQUEST pendingRequest = NULL;
    KIRQL oldIrql;
    BOOLEAN isIPv6;
    NTSTATUS status;
    UINT32 localAddrV4 = 0, remoteAddrV4 = 0;
    UINT8 localAddrV6[16] = {0}, remoteAddrV6[16] = {0};
    UINT16 localPort, remotePort;
    UINT8 protocol;
    HANDLE processId;
    WCHAR processPath[260];
    ULONG processPathLength = 0;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    // Safety checks
    if (!deviceContext || deviceContext->ShuttingDown) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // If filtering is disabled, permit all
    if (!deviceContext->FilteringEnabled) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Determine IP version
    isIPv6 = (InFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6);

    // Extract connection info based on IP version
    if (isIPv6) {
        // IPv6
        FWP_BYTE_ARRAY16* localAddrPtr = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_ADDRESS].value.byteArray16;
        FWP_BYTE_ARRAY16* remoteAddrPtr = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16;
        if (localAddrPtr) RtlCopyMemory(localAddrV6, localAddrPtr->byteArray16, 16);
        if (remoteAddrPtr) RtlCopyMemory(remoteAddrV6, remoteAddrPtr->byteArray16, 16);
        localPort = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_LOCAL_PORT].value.uint16;
        remotePort = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
        protocol = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;
    } else {
        // IPv4
        localAddrV4 = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
        remoteAddrV4 = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
        localPort = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
        remotePort = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
        protocol = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
    }

    // Get process ID
    if (InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
        processId = (HANDLE)(ULONG_PTR)InMetaValues->processId;
    } else {
        processId = (HANDLE)0;
    }

    // CRITICAL SAFETY BYPASSES
    // These prevent infinite loops and system instability

    // 1. Skip DNS traffic (port 53) - prevents infinite feedback loop
    if (remotePort == 53 || localPort == 53) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // 2. Skip mDNS traffic (port 5353) - multicast DNS, very chatty
    if (remotePort == 5353 || localPort == 5353) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // 3. Skip DHCP traffic (ports 67, 68) - critical for network config
    if (remotePort == 67 || remotePort == 68 || localPort == 67 || localPort == 68) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // 4. Skip multicast addresses
    if (isIPv6) {
        // IPv6 multicast: ff00::/8
        if (remoteAddrV6[0] == 0xFF) {
            ClassifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }
    } else {
        // IPv4 multicast: 224.x.x.x (0xE0000000)
        if ((remoteAddrV4 & 0xF0000000) == 0xE0000000) {
            ClassifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }
    }

    // 5. Skip localhost/loopback traffic
    if (isIPv6) {
        // IPv6 loopback: ::1
        static const UINT8 loopbackV6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        if (RtlCompareMemory(remoteAddrV6, loopbackV6, 16) == 16 ||
            RtlCompareMemory(localAddrV6, loopbackV6, 16) == 16) {
            ClassifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }
    } else {
        // IPv4 loopback: 127.0.0.1
        if (remoteAddrV4 == 0x7F000001 || localAddrV4 == 0x7F000001) {
            ClassifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }
    }

    // 6. Circuit breaker - auto-permit if too many timeouts (system protection)
    if (deviceContext->Stats.TimedOutRequests > CIRCUIT_BREAKER_THRESHOLD) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // 7. Check verdict cache - if we already decided on this connection, reuse verdict
    // This prevents duplicate pending requests for TCP SYN retries
    // Also handles re-auth (where ProcessId may be 0)
    {
        SERENO_VERDICT cachedVerdict;
        UINT32 lookupPid = (UINT32)(ULONG_PTR)processId;

        // Try with actual ProcessId first
        // Note: Domain is not yet known at this point - pass NULL for backwards compatibility
        // Domain-aware cache matching happens when domain is known from SNI/DNS cache
        if (SerenoVerdictCacheLookup(
                deviceContext,
                lookupPid,
                isIPv6,
                remoteAddrV4,
                isIPv6 ? remoteAddrV6 : NULL,
                remotePort,
                NULL,  // Domain not known yet
                0,
                &cachedVerdict)) {
            // Found cached verdict - use it immediately without pending
            SERENO_DBG("Cache HIT pid=%u port=%u verdict=%d", lookupPid, remotePort, cachedVerdict);
            if (cachedVerdict == SERENO_VERDICT_BLOCK) {
                ClassifyOut->actionType = FWP_ACTION_BLOCK;
                ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;  // Make block final
                SERENO_DBG("BLOCKING connection pid=%u port=%u action=0x%X rights=0x%X", 
                    lookupPid, remotePort, ClassifyOut->actionType, ClassifyOut->rights);
                InterlockedIncrement64((LONG64*)&deviceContext->Stats.BlockedConnections);
            } else {
                ClassifyOut->actionType = FWP_ACTION_PERMIT;
                InterlockedIncrement64((LONG64*)&deviceContext->Stats.AllowedConnections);
            }
            return;
        }

        // Re-auth may have ProcessId=0, try wildcard lookup (pid=0 matches any)
        // This is safe because we're matching on (IP, port) which is unique per connection
        if (lookupPid == 0) {
            if (SerenoVerdictCacheLookupByAddress(
                    deviceContext,
                    isIPv6,
                    remoteAddrV4,
                    isIPv6 ? remoteAddrV6 : NULL,
                    remotePort,
                    &cachedVerdict)) {
                SERENO_DBG("Cache HIT (re-auth, pid=0) port=%u verdict=%d", remotePort, cachedVerdict);
                if (cachedVerdict == SERENO_VERDICT_BLOCK) {
                    ClassifyOut->actionType = FWP_ACTION_BLOCK;
                    ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;  // Make block final
                    InterlockedIncrement64((LONG64*)&deviceContext->Stats.BlockedConnections);
                } else {
                    ClassifyOut->actionType = FWP_ACTION_PERMIT;
                    InterlockedIncrement64((LONG64*)&deviceContext->Stats.AllowedConnections);
                }
                return;
            }
            SERENO_DBG("Cache MISS (re-auth, pid=0) port=%u", remotePort);
        }
    }

    // Cache miss - log for debugging
    SERENO_DBG("Cache MISS pid=%u port=%u",
               (UINT32)(ULONG_PTR)processId, remotePort);

    // Update stats
    InterlockedIncrement64((LONG64*)&deviceContext->Stats.TotalConnections);

    // Check if we're at capacity
    if (deviceContext->PendingCount >= MAX_PENDING_REQUESTS) {
        InterlockedIncrement64((LONG64*)&deviceContext->Stats.DroppedRequests);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Check for completion handle - no handle means re-authorization
    // Re-auth normally uses the verdict cache (checked above at step 7).
    // If we reach here with no completion handle, the cache lookup failed
    // (cache expired or full). Permit as safe fallback.
    if (!(InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_COMPLETION_HANDLE)) {
        // Re-auth with no cached verdict - permit to avoid blocking
        SERENO_DBG("RE-AUTH FALLBACK permit (no cache) pid=%u port=%u",
                 (UINT32)(ULONG_PTR)processId, remotePort);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Allocate pending request (only for NEW connections with completion handle)
    pendingRequest = SerenoAllocatePendingRequest(deviceContext);
    if (!pendingRequest) {
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Fill in connection info
    pendingRequest->ConnectionInfo.RequestId = pendingRequest->RequestId;
    pendingRequest->ConnectionInfo.Timestamp = KeQueryInterruptTime();
    pendingRequest->ConnectionInfo.ProcessId = (UINT32)(ULONG_PTR)processId;
    pendingRequest->ConnectionInfo.Protocol = protocol;
    pendingRequest->ConnectionInfo.Direction = SERENO_DIRECTION_OUTBOUND;
    pendingRequest->ConnectionInfo.LocalPort = localPort;
    pendingRequest->ConnectionInfo.RemotePort = remotePort;

    if (isIPv6) {
        pendingRequest->ConnectionInfo.IpVersion = 6;
        RtlCopyMemory(pendingRequest->ConnectionInfo.LocalAddressV6, localAddrV6, 16);
        RtlCopyMemory(pendingRequest->ConnectionInfo.RemoteAddressV6, remoteAddrV6, 16);
    } else {
        pendingRequest->ConnectionInfo.IpVersion = 4;
        pendingRequest->ConnectionInfo.LocalAddressV4 = localAddrV4;
        pendingRequest->ConnectionInfo.RemoteAddressV4 = remoteAddrV4;
    }
    pendingRequest->IsIPv6 = isIPv6;

    // Get process path
    if (processId) {
        status = SerenoGetProcessPath(processId, processPath, sizeof(processPath) / sizeof(WCHAR), &processPathLength);
        if (NT_SUCCESS(status)) {
            RtlCopyMemory(pendingRequest->ConnectionInfo.ApplicationPath, processPath,
                         min(processPathLength * sizeof(WCHAR), sizeof(pendingRequest->ConnectionInfo.ApplicationPath)));
            pendingRequest->ConnectionInfo.ApplicationPathLength = processPathLength;
        }
    }

    // Lookup domain name from DNS cache
    {
        UINT32 domainLength = 0;
        if (SerenoDnsCacheLookup(
                deviceContext,
                isIPv6,
                remoteAddrV4,
                isIPv6 ? remoteAddrV6 : NULL,
                pendingRequest->ConnectionInfo.DomainName,
                sizeof(pendingRequest->ConnectionInfo.DomainName) / sizeof(WCHAR),
                &domainLength)) {
            pendingRequest->ConnectionInfo.DomainNameLength = domainLength;
        }
    }

    // ============================================================
    // ALE-LAYER DOMAIN BLOCKING (Zero-Packet Block)
    //
    // If we resolved the domain from DNS cache and it's in the blocked list,
    // block HERE at ALE layer - no TCP handshake, no packets sent at all.
    // This is more efficient than waiting for Stream layer SNI inspection.
    // ============================================================
    if (pendingRequest->ConnectionInfo.DomainNameLength > 0) {
        if (SerenoBlockedDomainCheck(deviceContext,
                pendingRequest->ConnectionInfo.DomainName,
                pendingRequest->ConnectionInfo.DomainNameLength)) {
            SERENO_DBG("BLOCKED at ALE (DNS cache): %S port=%u",
                pendingRequest->ConnectionInfo.DomainName, remotePort);

            // Cache the block verdict so re-auth and future connections are fast
            SerenoVerdictCacheAdd(
                deviceContext,
                (UINT32)(ULONG_PTR)processId,
                isIPv6,
                remoteAddrV4,
                isIPv6 ? remoteAddrV6 : NULL,
                remotePort,
                pendingRequest->ConnectionInfo.DomainName,
                pendingRequest->ConnectionInfo.DomainNameLength,
                SERENO_VERDICT_BLOCK
            );

            SerenoFreePendingRequest(pendingRequest);
            ClassifyOut->actionType = FWP_ACTION_BLOCK;
            ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            InterlockedIncrement64((LONG64*)&deviceContext->Stats.BlockedConnections);
            return;
        }
    }

    // ============================================================
    // ASYNC PENDING MODEL (Production - Like Little Snitch)
    //
    // We use FwpsPendOperation0 to hold the connection WITHOUT blocking
    // kernel threads. WFP handles the blocking internally. When user-mode
    // sends a verdict, we call FwpsCompleteOperation0 to allow/block.
    // ============================================================

    // Check if we have the right to modify the action
    // Another filter may have already made a final decision
    if (!(ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
        SERENO_DBG("Cannot pend - no FWPS_RIGHT_ACTION_WRITE, rights=0x%X\n", ClassifyOut->rights);
        SerenoFreePendingRequest(pendingRequest);
        // Don't set action - another filter already decided
        return;
    }

    // Debug: Log pend attempt
    SERENO_DBG("PEND attempt pid=%u port=%u handle=0x%p\n",
        (UINT32)(ULONG_PTR)processId, remotePort, InMetaValues->completionHandle);

    // Pend the operation - returns immediately, connection is held by WFP
    status = FwpsPendOperation0(
        InMetaValues->completionHandle,
        &pendingRequest->CompletionContext
    );

    if (!NT_SUCCESS(status)) {
        // Pending failed, permit and continue
        SERENO_DBG("FwpsPendOperation0 failed: 0x%08X handle=0x%p\n", status, InMetaValues->completionHandle);
        SerenoFreePendingRequest(pendingRequest);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    pendingRequest->Completed = FALSE;

    // Log new pending connection
    SERENO_DBG("PEND NEW pid=%u port=%u reqId=%llu",
              pendingRequest->ConnectionInfo.ProcessId,
              pendingRequest->ConnectionInfo.RemotePort,
              pendingRequest->RequestId);

    // Add to pending list for user-mode to process
    KeAcquireSpinLock(&deviceContext->PendingLock, &oldIrql);
    InsertTailList(&deviceContext->PendingList, &pendingRequest->ListEntry);
    deviceContext->PendingCount++;
    KeReleaseSpinLock(&deviceContext->PendingLock, oldIrql);

    // Set ABSORB flag - connection is held, we'll complete it asynchronously
    // FWP_ACTION_BLOCK with ABSORB means "I'll handle this later"
    ClassifyOut->actionType = FWP_ACTION_BLOCK;
    ClassifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;  // Prevent other callouts from changing action
}

/*
 * SerenoNotify - Callout notification function
 */
NTSTATUS NTAPI
SerenoNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER3* Filter
)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
}

/*
 * SerenoFlowDelete - Flow deletion notification (not used for ALE layers)
 */
VOID NTAPI
SerenoFlowDelete(
    _In_ UINT16 LayerId,
    _In_ UINT32 CalloutId,
    _In_ UINT64 FlowContext
)
{
    UNREFERENCED_PARAMETER(LayerId);
    UNREFERENCED_PARAMETER(CalloutId);
    UNREFERENCED_PARAMETER(FlowContext);
}

/*
 * SerenoAllocatePendingRequest - Allocate a new pending request
 *
 * NON-BLOCKING MODEL: No event or completion context needed
 */
PPENDING_REQUEST
SerenoAllocatePendingRequest(
    _In_ PSERENO_DEVICE_CONTEXT Context
)
{
    PPENDING_REQUEST request;

    request = (PPENDING_REQUEST)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PENDING_REQUEST), SERENO_POOL_TAG);
    if (!request) {
        return NULL;
    }

    RtlZeroMemory(request, sizeof(PENDING_REQUEST));
    request->RequestId = InterlockedIncrement64((LONG64*)&Context->NextRequestId);
    request->Timestamp = KeQueryInterruptTime();
    request->Verdict = SERENO_VERDICT_PENDING;
    request->SentToUserMode = FALSE;
    // No event initialization - non-blocking model

    return request;
}

/*
 * SerenoFreePendingRequest - Free a pending request
 */
VOID
SerenoFreePendingRequest(
    _In_ PPENDING_REQUEST Request
)
{
    if (Request) {
        ExFreePoolWithTag(Request, SERENO_POOL_TAG);
    }
}

/*
 * SerenoCompletePendingRequest - Complete a pending request with verdict
 *
 * ASYNC MODEL: Find the request, call FwpsCompleteOperation0 with the verdict,
 * then remove from list and free. This completes the pended connection.
 */
VOID
SerenoCompletePendingRequest(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ UINT64 RequestId,
    _In_ SERENO_VERDICT Verdict
)
{
    PLIST_ENTRY entry;
    PPENDING_REQUEST request = NULL;
    KIRQL oldIrql;
    HANDLE completionContext = NULL;

    KeAcquireSpinLock(&Context->PendingLock, &oldIrql);

    // Find and remove the request
    for (entry = Context->PendingList.Flink;
         entry != &Context->PendingList;
         entry = entry->Flink) {
        PPENDING_REQUEST r = CONTAINING_RECORD(entry, PENDING_REQUEST, ListEntry);
        if (r->RequestId == RequestId) {
            // Check if already completed (double-completion protection)
            if (r->Completed) {
                KeReleaseSpinLock(&Context->PendingLock, oldIrql);
                return;
            }
            r->Completed = TRUE;
            r->Verdict = Verdict;
            completionContext = r->CompletionContext;
            RemoveEntryList(entry);
            Context->PendingCount--;
            request = r;
            break;
        }
    }

    KeReleaseSpinLock(&Context->PendingLock, oldIrql);

    // Complete the pended operation outside the lock
    if (request && completionContext) {
        // CRITICAL: Add verdict to cache BEFORE calling FwpsCompleteOperation0
        // FwpsCompleteOperation0(NULL) triggers immediate re-authorization
        // which will call SerenoClassifyConnect again to check this cache
        SERENO_DBG("CacheAdd pid=%u port=%u verdict=%d (reqId=%llu)",
                 request->ConnectionInfo.ProcessId,
                 request->ConnectionInfo.RemotePort,
                 Verdict,
                 RequestId);

        SerenoVerdictCacheAdd(
            Context,
            request->ConnectionInfo.ProcessId,
            request->IsIPv6,
            request->ConnectionInfo.RemoteAddressV4,
            request->IsIPv6 ? request->ConnectionInfo.RemoteAddressV6 : NULL,
            request->ConnectionInfo.RemotePort,
            request->ConnectionInfo.DomainNameLength > 0 ? request->ConnectionInfo.DomainName : NULL,
            request->ConnectionInfo.DomainNameLength,
            Verdict
        );

        // Update stats
        if (Verdict == SERENO_VERDICT_BLOCK) {
            InterlockedIncrement64((LONG64*)&Context->Stats.BlockedConnections);
        } else {
            InterlockedIncrement64((LONG64*)&Context->Stats.AllowedConnections);
        }

        // Complete the pended operation - triggers re-authorization
        // Re-auth will find our verdict in the cache (added above)
        SERENO_DBG("Calling FwpsCompleteOperation0 (reqId=%llu)", RequestId);
        FwpsCompleteOperation0(completionContext, NULL);

        SerenoFreePendingRequest(request);
    }
}

// ============================================================================
// Verdict Cache - Required for Re-authorization After FwpsCompleteOperation0
// ============================================================================
//
// IMPORTANT: This cache is REQUIRED. FwpsCompleteOperation0(completionContext, NULL)
// always triggers WFP re-authorization. In re-auth, SerenoClassifyConnect is called
// again WITHOUT a completion handle. We must check this cache to know the verdict.
//
// The cache must be large enough and have long enough TTL to handle:
// - Heavy browser load (100+ connections/second)
// - Multiple re-auth attempts for the same connection
// ============================================================================

/*
 * SerenoVerdictCacheAdd - Add a verdict to the cache
 * Called BEFORE FwpsCompleteOperation0 to remember the verdict for re-auth
 *
 * Key: (ProcessId, RemoteIP, RemotePort, DomainName) -> Verdict
 * This ensures blocking evil.com (1.2.3.4:443) doesn't affect google.com (5.6.7.8:443)
 */
VOID
SerenoVerdictCacheAdd(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ UINT32 ProcessId,
    _In_ BOOLEAN IsIPv6,
    _In_ UINT32 RemoteIpV4,
    _In_opt_ const UINT8* RemoteIpV6,
    _In_ UINT16 RemotePort,
    _In_opt_ PCWSTR DomainName,
    _In_ UINT32 DomainLength,
    _In_ SERENO_VERDICT Verdict
)
{
    KIRQL oldIrql;
    UINT64 now = KeQueryInterruptTime();
    UINT32 targetIndex = MAX_VERDICT_CACHE_ENTRIES;
    UINT32 oldestIndex = 0;
    UINT64 oldestTime = MAXUINT64;
    UINT32 i;
    BOOLEAN hasDomain = (DomainName != NULL && DomainLength > 0);

    KeAcquireSpinLock(&Context->VerdictCacheLock, &oldIrql);

    // First pass: look for existing entry with same (pid, ip, port, domain) OR find empty/oldest slot
    for (i = 0; i < MAX_VERDICT_CACHE_ENTRIES; i++) {
        if (!Context->VerdictCache[i].InUse) {
            // Empty slot - candidate for new entry
            if (targetIndex == MAX_VERDICT_CACHE_ENTRIES) {
                oldestIndex = i;
            }
            continue;
        }

        // Check for expired entry
        if ((now - Context->VerdictCache[i].Timestamp) > VERDICT_CACHE_TTL_100NS) {
            Context->VerdictCache[i].InUse = FALSE;
            if (targetIndex == MAX_VERDICT_CACHE_ENTRIES) {
                oldestIndex = i;
            }
            continue;
        }

        // Check if this is an existing entry for same (pid, ip, port, domain) - UPDATE it
        if (Context->VerdictCache[i].ProcessId == ProcessId &&
            Context->VerdictCache[i].RemotePort == RemotePort &&
            Context->VerdictCache[i].IsIPv6 == IsIPv6) {

            // Check IP match
            BOOLEAN ipMatch = FALSE;
            if (IsIPv6) {
                if (RemoteIpV6 != NULL &&
                    RtlCompareMemory(Context->VerdictCache[i].RemoteIpV6, RemoteIpV6, 16) == 16) {
                    ipMatch = TRUE;
                }
            } else {
                if (Context->VerdictCache[i].RemoteIpV4 == RemoteIpV4) {
                    ipMatch = TRUE;
                }
            }

            if (ipMatch) {
                // IP matches, now check domain match
                BOOLEAN cacheDomain = (Context->VerdictCache[i].DomainLength > 0);
                if (hasDomain && cacheDomain) {
                    // Both have domains - must match
                    if (Context->VerdictCache[i].DomainLength == DomainLength &&
                        _wcsnicmp(Context->VerdictCache[i].DomainName, DomainName, DomainLength) == 0) {
                        targetIndex = i;
                    }
                } else if (!hasDomain && !cacheDomain) {
                    // Neither has domain - match
                    targetIndex = i;
                }
                // If one has domain and other doesn't, they're different entries
            }
        }

        // Track oldest for eviction if needed
        if (Context->VerdictCache[i].Timestamp < oldestTime) {
            oldestTime = Context->VerdictCache[i].Timestamp;
            oldestIndex = i;
        }
    }

    // Use existing entry if found, otherwise use empty/oldest slot
    if (targetIndex == MAX_VERDICT_CACHE_ENTRIES) {
        targetIndex = oldestIndex;
    }

    // Store/update in cache
    Context->VerdictCache[targetIndex].Timestamp = now;
    Context->VerdictCache[targetIndex].ProcessId = ProcessId;
    Context->VerdictCache[targetIndex].IsIPv6 = IsIPv6;
    Context->VerdictCache[targetIndex].RemoteIpV4 = RemoteIpV4;
    if (IsIPv6 && RemoteIpV6 != NULL) {
        RtlCopyMemory(Context->VerdictCache[targetIndex].RemoteIpV6, RemoteIpV6, 16);
    } else {
        RtlZeroMemory(Context->VerdictCache[targetIndex].RemoteIpV6, 16);
    }
    Context->VerdictCache[targetIndex].RemotePort = RemotePort;
    Context->VerdictCache[targetIndex].Verdict = Verdict;
    Context->VerdictCache[targetIndex].InUse = TRUE;

    // Store domain if provided
    if (hasDomain) {
        UINT32 copyLen = min(DomainLength, 255);
        RtlCopyMemory(Context->VerdictCache[targetIndex].DomainName, DomainName, copyLen * sizeof(WCHAR));
        Context->VerdictCache[targetIndex].DomainName[copyLen] = L'\0';
        Context->VerdictCache[targetIndex].DomainLength = copyLen;
    } else {
        Context->VerdictCache[targetIndex].DomainName[0] = L'\0';
        Context->VerdictCache[targetIndex].DomainLength = 0;
    }

    KeReleaseSpinLock(&Context->VerdictCacheLock, oldIrql);
}

/*
 * SerenoVerdictCacheLookup - Check if we have a cached verdict for this connection
 * Called during re-authorization (no completion handle available)
 * Returns TRUE if found (and sets Verdict), FALSE if not found
 *
 * Key: (ProcessId, RemoteIP, RemotePort, DomainName) -> Verdict
 * Matches by IP first, then domain if both have it. No fallback to avoid blocking wrong IPs.
 */
BOOLEAN
SerenoVerdictCacheLookup(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ UINT32 ProcessId,
    _In_ BOOLEAN IsIPv6,
    _In_ UINT32 RemoteIpV4,
    _In_opt_ const UINT8* RemoteIpV6,
    _In_ UINT16 RemotePort,
    _In_opt_ PCWSTR DomainName,
    _In_ UINT32 DomainLength,
    _Out_ SERENO_VERDICT* Verdict
)
{
    KIRQL oldIrql;
    UINT64 now = KeQueryInterruptTime();
    UINT32 i;
    BOOLEAN found = FALSE;
    BOOLEAN hasDomain = (DomainName != NULL && DomainLength > 0);

    KeAcquireSpinLock(&Context->VerdictCacheLock, &oldIrql);

    for (i = 0; i < MAX_VERDICT_CACHE_ENTRIES; i++) {
        if (!Context->VerdictCache[i].InUse) {
            continue;
        }

        // Check TTL
        if ((now - Context->VerdictCache[i].Timestamp) > VERDICT_CACHE_TTL_100NS) {
            Context->VerdictCache[i].InUse = FALSE;
            continue;
        }

        // Check ProcessId, RemotePort, and IP version
        if (Context->VerdictCache[i].ProcessId != ProcessId) continue;
        if (Context->VerdictCache[i].RemotePort != RemotePort) continue;
        if (Context->VerdictCache[i].IsIPv6 != IsIPv6) continue;

        // Check IP match - CRITICAL: this is what fixes the "block all domains on port" bug
        BOOLEAN ipMatch = FALSE;
        if (IsIPv6) {
            if (RemoteIpV6 != NULL &&
                RtlCompareMemory(Context->VerdictCache[i].RemoteIpV6, RemoteIpV6, 16) == 16) {
                ipMatch = TRUE;
            }
        } else {
            if (Context->VerdictCache[i].RemoteIpV4 == RemoteIpV4) {
                ipMatch = TRUE;
            }
        }

        if (!ipMatch) continue;

        // IP matches! Now check domain match
        BOOLEAN cacheDomain = (Context->VerdictCache[i].DomainLength > 0);

        if (hasDomain && cacheDomain) {
            // Both have domains - exact match required
            if (Context->VerdictCache[i].DomainLength == DomainLength &&
                _wcsnicmp(Context->VerdictCache[i].DomainName, DomainName, DomainLength) == 0) {
                *Verdict = Context->VerdictCache[i].Verdict;
                found = TRUE;
                break;
            }
        } else if (!hasDomain && !cacheDomain) {
            // Neither has domain - IP match is sufficient
            *Verdict = Context->VerdictCache[i].Verdict;
            found = TRUE;
            break;
        } else if (!cacheDomain) {
            // Cache has no domain but we have one - still match by IP
            // This allows the cached IP verdict to apply even when domain becomes known later
            *Verdict = Context->VerdictCache[i].Verdict;
            found = TRUE;
            break;
        }
        // If cache has domain but we don't, skip (can't verify domain match)
    }

    KeReleaseSpinLock(&Context->VerdictCacheLock, oldIrql);
    return found;
}

/*
 * SerenoVerdictCacheLookupByAddress - Lookup by IP and port (for re-auth with pid=0)
 * This is used when re-authorization doesn't have process context.
 * Returns the most recent verdict for the given IP:port.
 *
 * NOTE: This is a fallback when PID is unavailable. Matching by IP:port is safe
 * because the same IP:port should have the same verdict regardless of process.
 */
BOOLEAN
SerenoVerdictCacheLookupByAddress(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ BOOLEAN IsIPv6,
    _In_ UINT32 RemoteIpV4,
    _In_opt_ const UINT8* RemoteIpV6,
    _In_ UINT16 RemotePort,
    _Out_ SERENO_VERDICT* Verdict
)
{
    KIRQL oldIrql;
    UINT64 now = KeQueryInterruptTime();
    UINT32 i;
    BOOLEAN found = FALSE;
    UINT64 newestTime = 0;

    KeAcquireSpinLock(&Context->VerdictCacheLock, &oldIrql);

    // Find the most recent entry for this IP:port
    for (i = 0; i < MAX_VERDICT_CACHE_ENTRIES; i++) {
        if (!Context->VerdictCache[i].InUse) {
            continue;
        }

        // Check TTL
        if ((now - Context->VerdictCache[i].Timestamp) > VERDICT_CACHE_TTL_100NS) {
            Context->VerdictCache[i].InUse = FALSE;
            continue;
        }

        // Match by IP version and port first
        if (Context->VerdictCache[i].IsIPv6 != IsIPv6) continue;
        if (Context->VerdictCache[i].RemotePort != RemotePort) continue;

        // Check IP match
        BOOLEAN ipMatch = FALSE;
        if (IsIPv6) {
            if (RemoteIpV6 != NULL &&
                RtlCompareMemory(Context->VerdictCache[i].RemoteIpV6, RemoteIpV6, 16) == 16) {
                ipMatch = TRUE;
            }
        } else {
            if (Context->VerdictCache[i].RemoteIpV4 == RemoteIpV4) {
                ipMatch = TRUE;
            }
        }

        if (!ipMatch) continue;

        // Take the most recent verdict for this IP:port
        if (Context->VerdictCache[i].Timestamp > newestTime) {
            newestTime = Context->VerdictCache[i].Timestamp;
            *Verdict = Context->VerdictCache[i].Verdict;
            found = TRUE;
        }
    }

    KeReleaseSpinLock(&Context->VerdictCacheLock, oldIrql);
    return found;
}

/*
 * SerenoGetProcessPath - Get process executable path from process ID
 */
NTSTATUS
SerenoGetProcessPath(
    _In_ HANDLE ProcessId,
    _Out_writes_(PathLength) PWCHAR Path,
    _In_ ULONG PathLength,
    _Out_ PULONG ActualLength
)
{
    NTSTATUS status;
    PEPROCESS process;
    PUNICODE_STRING processName = NULL;

    *ActualLength = 0;
    Path[0] = L'\0';

    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = SeLocateProcessImageName(process, &processName);
    if (NT_SUCCESS(status) && processName && processName->Buffer) {
        ULONG copyLength = min(processName->Length / sizeof(WCHAR), PathLength - 1);
        RtlCopyMemory(Path, processName->Buffer, copyLength * sizeof(WCHAR));
        Path[copyLength] = L'\0';
        *ActualLength = copyLength;
        ExFreePool(processName);
    }

    ObDereferenceObject(process);
    return status;
}

// ============================================================================
// SNI Cache Management - Stores domain from TLS ClientHello
// ============================================================================

/*
 * SerenoSniCacheAdd - Add domain from TLS ClientHello to cache
 * Key: (LocalIP, LocalPort, RemoteIP, RemotePort, IsIPv6) -> Domain
 */
VOID
SerenoSniCacheAdd(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ BOOLEAN IsIPv6,
    _In_ UINT32 LocalIpV4,
    _In_opt_ const UINT8* LocalIpV6,
    _In_ UINT16 LocalPort,
    _In_ UINT32 RemoteIpV4,
    _In_opt_ const UINT8* RemoteIpV6,
    _In_ UINT16 RemotePort,
    _In_ PCWSTR DomainName,
    _In_ UINT32 DomainLength
)
{
    KIRQL oldIrql;
    UINT64 now = KeQueryInterruptTime();
    UINT32 targetIndex = MAX_SNI_CACHE_ENTRIES;
    UINT32 oldestIndex = 0;
    UINT64 oldestTime = MAXUINT64;
    UINT32 i;

    if (DomainLength == 0 || DomainName == NULL) {
        return;
    }

    KeAcquireSpinLock(&Context->SniCacheLock, &oldIrql);

    // Find empty slot or oldest entry to evict
    for (i = 0; i < MAX_SNI_CACHE_ENTRIES; i++) {
        if (!Context->SniCache[i].InUse) {
            if (targetIndex == MAX_SNI_CACHE_ENTRIES) {
                oldestIndex = i;
            }
            continue;
        }

        // Check for expired entry
        if ((now - Context->SniCache[i].Timestamp) > SNI_CACHE_TTL_100NS) {
            Context->SniCache[i].InUse = FALSE;
            if (targetIndex == MAX_SNI_CACHE_ENTRIES) {
                oldestIndex = i;
            }
            continue;
        }

        // Check if this is an existing entry for same 5-tuple - UPDATE it
        if (Context->SniCache[i].IsIPv6 == IsIPv6 &&
            Context->SniCache[i].LocalPort == LocalPort &&
            Context->SniCache[i].RemotePort == RemotePort) {
            if (IsIPv6) {
                if (LocalIpV6 && RtlCompareMemory(Context->SniCache[i].LocalAddressV6, LocalIpV6, 16) == 16 &&
                    RemoteIpV6 && RtlCompareMemory(Context->SniCache[i].RemoteAddressV6, RemoteIpV6, 16) == 16) {
                    targetIndex = i;
                }
            } else {
                if (Context->SniCache[i].LocalAddressV4 == LocalIpV4 &&
                    Context->SniCache[i].RemoteAddressV4 == RemoteIpV4) {
                    targetIndex = i;
                }
            }
        }

        // Track oldest for eviction
        if (Context->SniCache[i].Timestamp < oldestTime) {
            oldestTime = Context->SniCache[i].Timestamp;
            oldestIndex = i;
        }
    }

    if (targetIndex == MAX_SNI_CACHE_ENTRIES) {
        targetIndex = oldestIndex;
    }

    // Store in cache
    Context->SniCache[targetIndex].Timestamp = now;
    Context->SniCache[targetIndex].IsIPv6 = IsIPv6;
    Context->SniCache[targetIndex].LocalPort = LocalPort;
    Context->SniCache[targetIndex].RemotePort = RemotePort;
    Context->SniCache[targetIndex].InUse = TRUE;

    if (IsIPv6) {
        if (LocalIpV6) RtlCopyMemory(Context->SniCache[targetIndex].LocalAddressV6, LocalIpV6, 16);
        if (RemoteIpV6) RtlCopyMemory(Context->SniCache[targetIndex].RemoteAddressV6, RemoteIpV6, 16);
    } else {
        Context->SniCache[targetIndex].LocalAddressV4 = LocalIpV4;
        Context->SniCache[targetIndex].RemoteAddressV4 = RemoteIpV4;
    }

    UINT32 copyLen = min(DomainLength, 255);
    RtlCopyMemory(Context->SniCache[targetIndex].DomainName, DomainName, copyLen * sizeof(WCHAR));
    Context->SniCache[targetIndex].DomainName[copyLen] = L'\0';
    Context->SniCache[targetIndex].DomainLength = copyLen;

    KeReleaseSpinLock(&Context->SniCacheLock, oldIrql);

    SERENO_DBG("SNI Cache ADD: port=%u->%u domain=%S", LocalPort, RemotePort, DomainName);
}

/*
 * SerenoSniCacheLookup - Lookup domain by connection 5-tuple
 */
BOOLEAN
SerenoSniCacheLookup(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ BOOLEAN IsIPv6,
    _In_ UINT32 LocalIpV4,
    _In_opt_ const UINT8* LocalIpV6,
    _In_ UINT16 LocalPort,
    _In_ UINT32 RemoteIpV4,
    _In_opt_ const UINT8* RemoteIpV6,
    _In_ UINT16 RemotePort,
    _Out_writes_(DomainBufferLength) PWCHAR DomainBuffer,
    _In_ UINT32 DomainBufferLength,
    _Out_ PUINT32 DomainLength
)
{
    KIRQL oldIrql;
    UINT64 now = KeQueryInterruptTime();
    UINT32 i;
    BOOLEAN found = FALSE;

    *DomainLength = 0;
    if (DomainBufferLength > 0) {
        DomainBuffer[0] = L'\0';
    }

    KeAcquireSpinLock(&Context->SniCacheLock, &oldIrql);

    for (i = 0; i < MAX_SNI_CACHE_ENTRIES; i++) {
        if (!Context->SniCache[i].InUse) continue;

        // Check TTL
        if ((now - Context->SniCache[i].Timestamp) > SNI_CACHE_TTL_100NS) {
            Context->SniCache[i].InUse = FALSE;
            continue;
        }

        // Match 5-tuple
        if (Context->SniCache[i].IsIPv6 != IsIPv6) continue;
        if (Context->SniCache[i].LocalPort != LocalPort) continue;
        if (Context->SniCache[i].RemotePort != RemotePort) continue;

        if (IsIPv6) {
            if (!LocalIpV6 || !RemoteIpV6) continue;
            if (RtlCompareMemory(Context->SniCache[i].LocalAddressV6, LocalIpV6, 16) != 16) continue;
            if (RtlCompareMemory(Context->SniCache[i].RemoteAddressV6, RemoteIpV6, 16) != 16) continue;
        } else {
            if (Context->SniCache[i].LocalAddressV4 != LocalIpV4) continue;
            if (Context->SniCache[i].RemoteAddressV4 != RemoteIpV4) continue;
        }

        // Found match
        UINT32 copyLen = min(Context->SniCache[i].DomainLength, DomainBufferLength - 1);
        RtlCopyMemory(DomainBuffer, Context->SniCache[i].DomainName, copyLen * sizeof(WCHAR));
        DomainBuffer[copyLen] = L'\0';
        *DomainLength = copyLen;
        found = TRUE;
        break;
    }

    KeReleaseSpinLock(&Context->SniCacheLock, oldIrql);
    return found;
}

// ============================================================================
// SNI Notification Queue - Notify usermode about extracted SNI
// ============================================================================

/*
 * SerenoSniNotifyAdd - Add SNI notification to queue for usermode
 * Ring buffer: overwrites oldest if full
 */
VOID
SerenoSniNotifyAdd(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ BOOLEAN IsIPv6,
    _In_ UINT32 RemoteIpV4,
    _In_opt_ const UINT8* RemoteIpV6,
    _In_ UINT16 LocalPort,
    _In_ UINT16 RemotePort,
    _In_ PCWSTR DomainName,
    _In_ UINT32 DomainLength
)
{
    KIRQL oldIrql;
    UINT32 slot;

    if (DomainLength == 0 || DomainName == NULL) {
        return;
    }

    KeAcquireSpinLock(&Context->SniNotifyLock, &oldIrql);

    // Use head as write slot (ring buffer)
    slot = Context->SniNotifyHead;
    Context->SniNotifyHead = (Context->SniNotifyHead + 1) % MAX_SNI_NOTIFICATIONS;

    // If head catches tail, advance tail (drop oldest)
    if (Context->SniNotifyHead == Context->SniNotifyTail) {
        Context->SniNotifyTail = (Context->SniNotifyTail + 1) % MAX_SNI_NOTIFICATIONS;
    }

    // Fill notification
    RtlZeroMemory(&Context->SniNotifications[slot], sizeof(SERENO_SNI_NOTIFICATION));
    Context->SniNotifications[slot].Timestamp = KeQueryInterruptTime();
    Context->SniNotifications[slot].IpVersion = IsIPv6 ? 6 : 4;
    Context->SniNotifications[slot].LocalPort = LocalPort;
    Context->SniNotifications[slot].RemotePort = RemotePort;

    if (IsIPv6 && RemoteIpV6) {
        RtlCopyMemory(Context->SniNotifications[slot].RemoteAddressV6, RemoteIpV6, 16);
    } else {
        Context->SniNotifications[slot].RemoteAddressV4 = RemoteIpV4;
    }

    UINT32 copyLen = min(DomainLength, 255);
    RtlCopyMemory(Context->SniNotifications[slot].DomainName, DomainName, copyLen * sizeof(WCHAR));
    Context->SniNotifications[slot].DomainName[copyLen] = L'\0';
    Context->SniNotifications[slot].DomainNameLength = copyLen;

    KeReleaseSpinLock(&Context->SniNotifyLock, oldIrql);

    SERENO_DBG("SNI Notify ADD: port=%u domain=%S", RemotePort, DomainName);
}

/*
 * SerenoSniNotifyGet - Get next SNI notification from queue
 * Returns FALSE if queue is empty
 */
BOOLEAN
SerenoSniNotifyGet(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _Out_ PSERENO_SNI_NOTIFICATION Notification
)
{
    KIRQL oldIrql;
    BOOLEAN hasData = FALSE;

    RtlZeroMemory(Notification, sizeof(SERENO_SNI_NOTIFICATION));

    KeAcquireSpinLock(&Context->SniNotifyLock, &oldIrql);

    if (Context->SniNotifyTail != Context->SniNotifyHead) {
        // Queue has data
        RtlCopyMemory(Notification, &Context->SniNotifications[Context->SniNotifyTail], sizeof(SERENO_SNI_NOTIFICATION));
        Context->SniNotifyTail = (Context->SniNotifyTail + 1) % MAX_SNI_NOTIFICATIONS;
        hasData = TRUE;
    }

    KeReleaseSpinLock(&Context->SniNotifyLock, oldIrql);
    return hasData;
}

// ============================================================================
// Blocked Domain Management - For SNI-based blocking at Stream layer
// ============================================================================

/*
 * SerenoBlockedDomainAdd - Add a domain to the blocked list
 * Returns TRUE on success, FALSE if list is full or domain is invalid
 */
BOOLEAN
SerenoBlockedDomainAdd(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ PCWSTR DomainName,
    _In_ UINT32 DomainLength
)
{
    KIRQL oldIrql;
    UINT32 i;
    BOOLEAN added = FALSE;

    if (DomainLength == 0 || DomainLength >= 256) {
        return FALSE;
    }

    KeAcquireSpinLock(&Context->BlockedDomainLock, &oldIrql);

    // Check if already in list (avoid duplicates)
    for (i = 0; i < MAX_BLOCKED_DOMAINS; i++) {
        if (Context->BlockedDomains[i].InUse &&
            Context->BlockedDomains[i].DomainLength == DomainLength) {
            // Case-insensitive compare
            if (_wcsnicmp(Context->BlockedDomains[i].DomainName, DomainName, DomainLength) == 0) {
                // Already exists
                added = TRUE;
                goto done;
            }
        }
    }

    // Find empty slot
    for (i = 0; i < MAX_BLOCKED_DOMAINS; i++) {
        if (!Context->BlockedDomains[i].InUse) {
            Context->BlockedDomains[i].InUse = TRUE;
            RtlCopyMemory(Context->BlockedDomains[i].DomainName, DomainName, DomainLength * sizeof(WCHAR));
            Context->BlockedDomains[i].DomainName[DomainLength] = L'\0';
            Context->BlockedDomains[i].DomainLength = DomainLength;
            Context->BlockedDomainCount++;
            added = TRUE;
            break;
        }
    }

done:
    KeReleaseSpinLock(&Context->BlockedDomainLock, oldIrql);
    return added;
}

/*
 * SerenoBlockedDomainClear - Clear all blocked domains
 */
VOID
SerenoBlockedDomainClear(
    _In_ PSERENO_DEVICE_CONTEXT Context
)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&Context->BlockedDomainLock, &oldIrql);
    RtlZeroMemory(Context->BlockedDomains, sizeof(Context->BlockedDomains));
    Context->BlockedDomainCount = 0;
    KeReleaseSpinLock(&Context->BlockedDomainLock, oldIrql);
}

/*
 * SerenoBlockedDomainCheck - Check if domain is in blocked list
 * Uses suffix matching: "facebook.com" matches "www.facebook.com", "facebook.com", etc.
 * Returns TRUE if domain should be blocked
 */
BOOLEAN
SerenoBlockedDomainCheck(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ PCWSTR DomainName,
    _In_ UINT32 DomainLength
)
{
    KIRQL oldIrql;
    UINT32 i;
    BOOLEAN blocked = FALSE;

    if (DomainLength == 0) {
        return FALSE;
    }

    if (Context->BlockedDomainCount == 0) {
        SERENO_DBG("BlockedDomainCheck: No blocked domains in list");
        return FALSE;
    }

    SERENO_DBG("BlockedDomainCheck: Checking '%S' against %u blocked domains", DomainName, Context->BlockedDomainCount);

    KeAcquireSpinLock(&Context->BlockedDomainLock, &oldIrql);

    for (i = 0; i < MAX_BLOCKED_DOMAINS && !blocked; i++) {
        if (!Context->BlockedDomains[i].InUse) {
            continue;
        }

        UINT32 patternLen = Context->BlockedDomains[i].DomainLength;
        PCWSTR pattern = Context->BlockedDomains[i].DomainName;

        // Suffix match: domain ends with pattern
        // e.g., pattern "facebook.com" matches "www.facebook.com", "facebook.com"
        if (DomainLength >= patternLen) {
            PCWSTR suffix = DomainName + (DomainLength - patternLen);
            if (_wcsnicmp(suffix, pattern, patternLen) == 0) {
                // Also check it's at domain boundary (start of string or after '.')
                if (DomainLength == patternLen ||
                    suffix[-1] == L'.') {
                    blocked = TRUE;
                }
            }
        }
    }

    KeReleaseSpinLock(&Context->BlockedDomainLock, oldIrql);
    return blocked;
}

// ============================================================================
// TLS ClientHello Parsing - Extract SNI from TLS handshake
// ============================================================================

/*
 * SerenoParseTlsClientHello - Parse TLS ClientHello to extract SNI
 *
 * TLS Record:
 *   [1] ContentType (0x16 = Handshake)
 *   [2] Version
 *   [2] Length
 *
 * Handshake:
 *   [1] Type (0x01 = ClientHello)
 *   [3] Length
 *
 * ClientHello:
 *   [2] Version
 *   [32] Random
 *   [1] SessionID Length + data
 *   [2] Cipher Suites Length + data
 *   [1] Compression Methods Length + data
 *   [2] Extensions Length
 *
 * SNI Extension (Type 0x0000):
 *   [2] Type
 *   [2] Length
 *   [2] SNI List Length
 *   [1] Name Type (0x00 = hostname)
 *   [2] Name Length
 *   [N] Hostname (ASCII)
 */
BOOLEAN
SerenoParseTlsClientHello(
    _In_ const UINT8* Data,
    _In_ UINT32 DataLength,
    _Out_writes_(DomainBufferLength) PWCHAR DomainBuffer,
    _In_ UINT32 DomainBufferLength,
    _Out_ PUINT32 DomainLength
)
{
    UINT32 offset = 0;
    UINT32 recordLength;
    UINT32 handshakeLength;
    UINT32 sessionIdLength;
    UINT32 cipherSuitesLength;
    UINT32 compressionMethodsLength;
    UINT32 extensionsLength;
    UINT32 extensionsEnd;

    *DomainLength = 0;
    if (DomainBufferLength > 0) {
        DomainBuffer[0] = L'\0';
    }

    // Minimum TLS record header: 5 bytes
    if (DataLength < 5) {
        return FALSE;
    }

    // Check TLS Record: ContentType = 0x16 (Handshake)
    if (Data[0] != 0x16) {
        return FALSE;
    }

    // Skip Version [2 bytes]
    // Record Length [2 bytes, big-endian]
    recordLength = (Data[3] << 8) | Data[4];
    offset = 5;

    // Check we have enough data
    if (DataLength < offset + recordLength || recordLength < 4) {
        return FALSE;
    }

    // Handshake Header
    // Type [1 byte] = 0x01 (ClientHello)
    if (Data[offset] != 0x01) {
        return FALSE;
    }
    offset++;

    // Handshake Length [3 bytes, big-endian]
    handshakeLength = (Data[offset] << 16) | (Data[offset + 1] << 8) | Data[offset + 2];
    offset += 3;

    // Check we have enough data for ClientHello
    if (DataLength < offset + handshakeLength) {
        return FALSE;
    }

    // ClientHello body
    // Version [2 bytes]
    if (offset + 2 > DataLength) return FALSE;
    offset += 2;

    // Random [32 bytes]
    if (offset + 32 > DataLength) return FALSE;
    offset += 32;

    // Session ID Length [1 byte] + Session ID
    if (offset + 1 > DataLength) return FALSE;
    sessionIdLength = Data[offset];
    offset++;
    if (offset + sessionIdLength > DataLength) return FALSE;
    offset += sessionIdLength;

    // Cipher Suites Length [2 bytes] + Cipher Suites
    if (offset + 2 > DataLength) return FALSE;
    cipherSuitesLength = (Data[offset] << 8) | Data[offset + 1];
    offset += 2;
    if (offset + cipherSuitesLength > DataLength) return FALSE;
    offset += cipherSuitesLength;

    // Compression Methods Length [1 byte] + Compression Methods
    if (offset + 1 > DataLength) return FALSE;
    compressionMethodsLength = Data[offset];
    offset++;
    if (offset + compressionMethodsLength > DataLength) return FALSE;
    offset += compressionMethodsLength;

    // Extensions Length [2 bytes]
    if (offset + 2 > DataLength) return FALSE;
    extensionsLength = (Data[offset] << 8) | Data[offset + 1];
    offset += 2;

    if (offset + extensionsLength > DataLength) return FALSE;
    extensionsEnd = offset + extensionsLength;

    // Parse extensions to find SNI (Type 0x0000)
    while (offset + 4 <= extensionsEnd) {
        UINT16 extType = (Data[offset] << 8) | Data[offset + 1];
        UINT16 extLength = (Data[offset + 2] << 8) | Data[offset + 3];
        offset += 4;

        if (offset + extLength > extensionsEnd) {
            break;
        }

        if (extType == 0x0000) {  // SNI extension
            // SNI extension data:
            // [2] SNI List Length
            // [1] Name Type (0x00 = hostname)
            // [2] Name Length
            // [N] Name (ASCII)
            if (extLength >= 5) {
                UINT16 sniListLength = (Data[offset] << 8) | Data[offset + 1];
                UNREFERENCED_PARAMETER(sniListLength);
                UINT8 nameType = Data[offset + 2];

                if (nameType == 0x00) {  // hostname
                    UINT16 nameLength = (Data[offset + 3] << 8) | Data[offset + 4];
                    if (offset + 5 + nameLength <= extensionsEnd) {
                        // Convert ASCII hostname to wide string
                        UINT32 copyLen = min(nameLength, DomainBufferLength - 1);
                        for (UINT32 j = 0; j < copyLen; j++) {
                            DomainBuffer[j] = (WCHAR)Data[offset + 5 + j];
                        }
                        DomainBuffer[copyLen] = L'\0';
                        *DomainLength = copyLen;
                        return TRUE;
                    }
                }
            }
        }

        offset += extLength;
    }

    return FALSE;
}

// ============================================================================
// Stream Layer Classification - SNI Extraction from TLS ClientHello
// ============================================================================

/*
 * SerenoClassifyStream - Stream layer callout for SNI extraction and blocking
 *
 * Inspects outbound TCP stream data on port 443 for TLS ClientHello.
 * Extracts SNI and stores in cache for later verdict lookup.
 *
 * Phase 2 (SNI-based blocking): After extracting SNI, checks against the
 * blocked domain list. If matched, drops the connection and adds to verdict
 * cache so future connections to that domain are blocked at ALE layer.
 */
VOID NTAPI
SerenoClassifyStream(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER3* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    PSERENO_DEVICE_CONTEXT deviceContext;
    FWPS_STREAM_CALLOUT_IO_PACKET0* streamPacket;
    FWPS_STREAM_DATA0* streamData;
    NET_BUFFER_LIST* netBufferList;
    NET_BUFFER* netBuffer;
    UINT32 dataLength;
    UINT8* dataBuffer = NULL;
    UINT8* allocatedBuffer = NULL;
    BOOLEAN isIPv6;
    UINT32 localAddrV4 = 0;
    UINT32 remoteAddrV4 = 0;
    UINT8 localAddrV6[16] = {0};
    UINT8 remoteAddrV6[16] = {0};
    UINT16 localPort;
    UINT16 remotePort;
    UINT32 flags;
    WCHAR domainBuffer[256];
    UINT32 domainLength;

    UNREFERENCED_PARAMETER(InMetaValues);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    // Always permit - this is inspection only
    ClassifyOut->actionType = FWP_ACTION_CONTINUE;

    // Use global device context (same as ALE classify)
    deviceContext = g_DeviceContext;

    if (!LayerData || !deviceContext) {
        return;
    }

    if (!deviceContext->FilteringEnabled || deviceContext->ShuttingDown) {
        return;
    }

    streamPacket = (FWPS_STREAM_CALLOUT_IO_PACKET0*)LayerData;
    if (!streamPacket) {
        SERENO_DBG("STREAM: Early return - no streamPacket");
        return;
    }

    streamData = streamPacket->streamData;
    if (!streamData) {
        SERENO_DBG("STREAM: Early return - no streamData");
        return;
    }

    // Only inspect outbound data (client -> server, contains ClientHello)
    flags = streamData->flags;
    if (!(flags & FWPS_STREAM_FLAG_SEND)) {
        SERENO_DBG("STREAM: Not outbound (flags=0x%X), skipping", flags);
        return;
    }

    // Get data length
    dataLength = (UINT32)streamData->dataLength;
    SERENO_DBG("STREAM: Outbound data len=%u", dataLength);
    if (dataLength < 10 || dataLength > 16384) {
        // Too small for TLS ClientHello or suspiciously large
        SERENO_DBG("STREAM: Data length out of range (%u), skipping", dataLength);
        return;
    }

    // Determine IPv4 or IPv6
    isIPv6 = (InFixedValues->layerId == FWPS_LAYER_STREAM_V6);

    // Get addresses and ports
    if (isIPv6) {
        FWP_BYTE_ARRAY16* localAddr = InFixedValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_LOCAL_ADDRESS].value.byteArray16;
        FWP_BYTE_ARRAY16* remoteAddr = InFixedValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_REMOTE_ADDRESS].value.byteArray16;
        if (localAddr) RtlCopyMemory(localAddrV6, localAddr->byteArray16, 16);
        if (remoteAddr) RtlCopyMemory(remoteAddrV6, remoteAddr->byteArray16, 16);
        localPort = InFixedValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_LOCAL_PORT].value.uint16;
        remotePort = InFixedValues->incomingValue[FWPS_FIELD_STREAM_V6_IP_REMOTE_PORT].value.uint16;
    } else {
        localAddrV4 = InFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS].value.uint32;
        remoteAddrV4 = InFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS].value.uint32;
        localPort = InFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT].value.uint16;
        remotePort = InFixedValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT].value.uint16;
    }

    // Get the data from NET_BUFFER_LIST
    netBufferList = streamData->netBufferListChain;
    if (!netBufferList) {
        return;
    }

    netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    if (!netBuffer) {
        return;
    }

    // Try to get contiguous data
    dataBuffer = NdisGetDataBuffer(netBuffer, dataLength, NULL, 1, 0);
    if (!dataBuffer) {
        // Data not contiguous - allocate temp buffer
        allocatedBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, dataLength, SERENO_POOL_TAG);
        if (!allocatedBuffer) {
            return;
        }
        dataBuffer = NdisGetDataBuffer(netBuffer, dataLength, allocatedBuffer, 1, 0);
        if (!dataBuffer) {
            ExFreePoolWithTag(allocatedBuffer, SERENO_POOL_TAG);
            return;
        }
    }

    // Parse TLS ClientHello for SNI
    if (SerenoParseTlsClientHello(dataBuffer, dataLength, domainBuffer, 256, &domainLength)) {
        if (domainLength > 0) {
            // Found SNI - add to cache
            SerenoSniCacheAdd(
                deviceContext,
                isIPv6,
                localAddrV4,
                isIPv6 ? localAddrV6 : NULL,
                localPort,
                remoteAddrV4,
                isIPv6 ? remoteAddrV6 : NULL,
                remotePort,
                domainBuffer,
                domainLength
            );

            // Also notify usermode for TUI display update
            SerenoSniNotifyAdd(
                deviceContext,
                isIPv6,
                remoteAddrV4,
                isIPv6 ? remoteAddrV6 : NULL,
                localPort,
                remotePort,
                domainBuffer,
                domainLength
            );

            SERENO_DBG("Stream SNI extracted: %S (port %u)", domainBuffer, remotePort);

            // Phase 2: Check if domain is in blocked list
            if (SerenoBlockedDomainCheck(deviceContext, domainBuffer, domainLength)) {
                SERENO_DBG("BLOCKED by SNI: %S (HOLDING ClientHello - server won't see domain)", domainBuffer);

                // HOLD CLIENTHELLO PATTERN:
                // 1. Consume the data (countBytesEnforced) - prevents forwarding
                // 2. Block the action - tells WFP not to send
                // 3. Abort the flow - terminates the TCP connection
                // Result: Server NEVER sees the ClientHello with our SNI

                // Consume all the data - this is the "hold" part
                streamPacket->countBytesEnforced = dataLength;

                // Set stream action to drop the connection
                streamPacket->streamAction = FWPS_STREAM_ACTION_DROP_CONNECTION;
                ClassifyOut->actionType = FWP_ACTION_BLOCK;
                ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

                // Abort the TCP flow - this terminates the connection
                if (InMetaValues->flowHandle) {
                    NTSTATUS abortStatus = FwpsFlowAbort0(InMetaValues->flowHandle);
                    SERENO_DBG("FwpsFlowAbort0 returned: 0x%08X", abortStatus);
                }

                // Add to verdict cache so future connections are blocked at ALE layer
                // Use process ID 0 to match any process going to this domain
                SerenoVerdictCacheAdd(
                    deviceContext,
                    0,  // ProcessId 0 = any process
                    isIPv6,
                    remoteAddrV4,
                    isIPv6 ? remoteAddrV6 : NULL,
                    remotePort,
                    domainBuffer,
                    domainLength,
                    SERENO_VERDICT_BLOCK
                );

                deviceContext->Stats.BlockedConnections++;

                // Free buffer and return early
                if (allocatedBuffer) {
                    ExFreePoolWithTag(allocatedBuffer, SERENO_POOL_TAG);
                }
                return;
            }
        }
    }

    // Free allocated buffer if any
    if (allocatedBuffer) {
        ExFreePoolWithTag(allocatedBuffer, SERENO_POOL_TAG);
    }
}

// ============================================================================
// DNS Cache Management
// ============================================================================

/*
 * SerenoDnsCacheInit - Initialize the DNS cache
 */
VOID
SerenoDnsCacheInit(
    _In_ PSERENO_DEVICE_CONTEXT Context
)
{
    InitializeListHead(&Context->DnsCacheList);
    KeInitializeSpinLock(&Context->DnsCacheLock);
    Context->DnsCacheCount = 0;
}

/*
 * SerenoDnsCacheCleanup - Free all DNS cache entries
 */
VOID
SerenoDnsCacheCleanup(
    _In_ PSERENO_DEVICE_CONTEXT Context
)
{
    PLIST_ENTRY entry;
    PDNS_CACHE_ENTRY cacheEntry;
    KIRQL oldIrql;

    KeAcquireSpinLock(&Context->DnsCacheLock, &oldIrql);
    while (!IsListEmpty(&Context->DnsCacheList)) {
        entry = RemoveHeadList(&Context->DnsCacheList);
        cacheEntry = CONTAINING_RECORD(entry, DNS_CACHE_ENTRY, ListEntry);
        ExFreePoolWithTag(cacheEntry, SERENO_POOL_TAG);
    }
    Context->DnsCacheCount = 0;
    KeReleaseSpinLock(&Context->DnsCacheLock, oldIrql);
}

/*
 * SerenoDnsCacheAdd - Add a domain->IP mapping to the cache
 */
VOID
SerenoDnsCacheAdd(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ BOOLEAN IsIPv6,
    _In_ UINT32 IpV4,
    _In_opt_ const UINT8* IpV6,
    _In_ PCWSTR DomainName,
    _In_ UINT32 DomainLength
)
{
    PDNS_CACHE_ENTRY newEntry;
    PLIST_ENTRY entry;
    PDNS_CACHE_ENTRY existingEntry;
    KIRQL oldIrql;
    UINT64 now = KeQueryInterruptTime();

    if (DomainLength == 0 || DomainLength >= 256) {
        return;
    }

    // Check if entry already exists
    KeAcquireSpinLock(&Context->DnsCacheLock, &oldIrql);

    for (entry = Context->DnsCacheList.Flink;
         entry != &Context->DnsCacheList;
         entry = entry->Flink) {
        existingEntry = CONTAINING_RECORD(entry, DNS_CACHE_ENTRY, ListEntry);

        BOOLEAN match = FALSE;
        if (IsIPv6 && existingEntry->IsIPv6) {
            if (IpV6 && RtlCompareMemory(existingEntry->IpV6, IpV6, 16) == 16) {
                match = TRUE;
            }
        } else if (!IsIPv6 && !existingEntry->IsIPv6) {
            if (existingEntry->IpV4 == IpV4) {
                match = TRUE;
            }
        }

        if (match) {
            // Update existing entry
            existingEntry->Timestamp = now;
            RtlCopyMemory(existingEntry->DomainName, DomainName, DomainLength * sizeof(WCHAR));
            existingEntry->DomainName[DomainLength] = L'\0';
            existingEntry->DomainLength = DomainLength;
            KeReleaseSpinLock(&Context->DnsCacheLock, oldIrql);
            return;
        }
    }

    // Remove old entries if at capacity
    while (Context->DnsCacheCount >= MAX_DNS_CACHE_ENTRIES && !IsListEmpty(&Context->DnsCacheList)) {
        entry = RemoveTailList(&Context->DnsCacheList);
        existingEntry = CONTAINING_RECORD(entry, DNS_CACHE_ENTRY, ListEntry);
        ExFreePoolWithTag(existingEntry, SERENO_POOL_TAG);
        Context->DnsCacheCount--;
    }

    KeReleaseSpinLock(&Context->DnsCacheLock, oldIrql);

    // Allocate new entry
    newEntry = (PDNS_CACHE_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DNS_CACHE_ENTRY), SERENO_POOL_TAG);
    if (!newEntry) {
        return;
    }

    RtlZeroMemory(newEntry, sizeof(DNS_CACHE_ENTRY));
    newEntry->Timestamp = now;
    newEntry->IsIPv6 = IsIPv6;
    if (IsIPv6 && IpV6) {
        RtlCopyMemory(newEntry->IpV6, IpV6, 16);
    } else {
        newEntry->IpV4 = IpV4;
    }
    RtlCopyMemory(newEntry->DomainName, DomainName, DomainLength * sizeof(WCHAR));
    newEntry->DomainName[DomainLength] = L'\0';
    newEntry->DomainLength = DomainLength;

    // Add to cache
    KeAcquireSpinLock(&Context->DnsCacheLock, &oldIrql);
    InsertHeadList(&Context->DnsCacheList, &newEntry->ListEntry);
    Context->DnsCacheCount++;
    KeReleaseSpinLock(&Context->DnsCacheLock, oldIrql);
}

/*
 * SerenoDnsCacheLookup - Look up a domain name by IP address
 */
BOOLEAN
SerenoDnsCacheLookup(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ BOOLEAN IsIPv6,
    _In_ UINT32 IpV4,
    _In_opt_ const UINT8* IpV6,
    _Out_writes_(DomainBufferLength) PWCHAR DomainBuffer,
    _In_ UINT32 DomainBufferLength,
    _Out_ PUINT32 DomainLength
)
{
    PLIST_ENTRY entry;
    PDNS_CACHE_ENTRY cacheEntry;
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    UINT64 now = KeQueryInterruptTime();

    *DomainLength = 0;
    DomainBuffer[0] = L'\0';

    KeAcquireSpinLock(&Context->DnsCacheLock, &oldIrql);

    for (entry = Context->DnsCacheList.Flink;
         entry != &Context->DnsCacheList;
         entry = entry->Flink) {
        cacheEntry = CONTAINING_RECORD(entry, DNS_CACHE_ENTRY, ListEntry);

        // Check TTL
        if ((now - cacheEntry->Timestamp) > DNS_CACHE_TTL_100NS) {
            continue;
        }

        BOOLEAN match = FALSE;
        if (IsIPv6 && cacheEntry->IsIPv6) {
            if (IpV6 && RtlCompareMemory(cacheEntry->IpV6, IpV6, 16) == 16) {
                match = TRUE;
            }
        } else if (!IsIPv6 && !cacheEntry->IsIPv6) {
            if (cacheEntry->IpV4 == IpV4) {
                match = TRUE;
            }
        }

        if (match) {
            UINT32 copyLen = min(cacheEntry->DomainLength, DomainBufferLength - 1);
            RtlCopyMemory(DomainBuffer, cacheEntry->DomainName, copyLen * sizeof(WCHAR));
            DomainBuffer[copyLen] = L'\0';
            *DomainLength = copyLen;
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&Context->DnsCacheLock, oldIrql);
    return found;
}

// ============================================================================
// DNS Packet Parsing and Interception
// ============================================================================

/*
 * SerenoParseDnsResponse - Parse a DNS response packet and extract domain->IP mappings
 *
 * DNS packet format:
 * - Header (12 bytes): ID, flags, counts
 * - Question section: domain name queries
 * - Answer section: resource records with IP addresses
 */
VOID
SerenoParseDnsResponse(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ const UINT8* DnsData,
    _In_ UINT32 DnsLength
)
{
    // DNS header is 12 bytes minimum
    if (DnsLength < 12) {
        return;
    }

    // Check if this is a response (QR bit set)
    UINT16 flags = (DnsData[2] << 8) | DnsData[3];
    if (!(flags & 0x8000)) {
        // This is a query, not a response
        return;
    }

    // Check RCODE (response code) - 0 means no error
    if ((flags & 0x000F) != 0) {
        return;
    }

    UINT16 qdcount = (DnsData[4] << 8) | DnsData[5];  // Question count
    UINT16 ancount = (DnsData[6] << 8) | DnsData[7];  // Answer count

    if (ancount == 0) {
        return;
    }

    // Parse the question section to get the domain name
    UINT32 offset = 12;
    WCHAR domainName[256];
    UINT32 domainLen = 0;

    // Skip all questions
    for (UINT16 q = 0; q < qdcount && offset < DnsLength; q++) {
        // Parse domain name from first question (we'll use this for all answers)
        if (q == 0) {
            domainLen = 0;
            while (offset < DnsLength) {
                UINT8 labelLen = DnsData[offset++];
                if (labelLen == 0) break;

                // Check for compression pointer
                if ((labelLen & 0xC0) == 0xC0) {
                    offset++;
                    break;
                }

                if (offset + labelLen > DnsLength) break;

                // Add dot separator
                if (domainLen > 0 && domainLen < 255) {
                    domainName[domainLen++] = L'.';
                }

                // Copy label
                for (UINT8 i = 0; i < labelLen && domainLen < 255; i++) {
                    domainName[domainLen++] = (WCHAR)DnsData[offset++];
                }
            }
            domainName[domainLen] = L'\0';
        } else {
            // Skip other questions
            while (offset < DnsLength) {
                UINT8 labelLen = DnsData[offset++];
                if (labelLen == 0) break;
                if ((labelLen & 0xC0) == 0xC0) {
                    offset++;
                    break;
                }
                offset += labelLen;
            }
        }

        // Skip QTYPE (2 bytes) and QCLASS (2 bytes)
        offset += 4;
    }

    if (domainLen == 0) {
        return;
    }

    // Parse answer section
    for (UINT16 a = 0; a < ancount && offset < DnsLength; a++) {
        // Skip name (may be compressed)
        while (offset < DnsLength) {
            UINT8 labelLen = DnsData[offset];
            if (labelLen == 0) {
                offset++;
                break;
            }
            if ((labelLen & 0xC0) == 0xC0) {
                offset += 2;
                break;
            }
            offset += labelLen + 1;
        }

        if (offset + 10 > DnsLength) break;

        UINT16 rtype = (DnsData[offset] << 8) | DnsData[offset + 1];
        // UINT16 rclass = (DnsData[offset + 2] << 8) | DnsData[offset + 3];
        // UINT32 ttl = (DnsData[offset + 4] << 24) | (DnsData[offset + 5] << 16) |
        //              (DnsData[offset + 6] << 8) | DnsData[offset + 7];
        UINT16 rdlength = (DnsData[offset + 8] << 8) | DnsData[offset + 9];
        offset += 10;

        if (offset + rdlength > DnsLength) break;

        // A record (IPv4)
        if (rtype == 1 && rdlength == 4) {
            // DNS packet has IP in network byte order (big-endian)
            // WFP provides IP addresses in network byte order too
            // But the way we construct the uint32 from bytes differs from how WFP stores it
            // WFP stores the raw bytes directly in memory, so on LE it reads as byte-swapped
            // We need to match that format for cache lookups to work
            //
            // Example: IP 142.250.68.46 (bytes: 0x8E, 0xFA, 0x44, 0x2E)
            // DNS parsing (arithmetic): (0x8E<<24)|(0xFA<<16)|(0x44<<8)|0x2E = 0x8EFA442E
            // WFP on LE (raw bytes in memory): reads as 0x2E44FA8E
            // So we need to byte-swap our parsed value to match WFP
            UINT32 ipv4_parsed = (DnsData[offset] << 24) | (DnsData[offset + 1] << 16) |
                          (DnsData[offset + 2] << 8) | DnsData[offset + 3];
            UINT32 ipv4 = RtlUlongByteSwap(ipv4_parsed);
            SerenoDnsCacheAdd(Context, FALSE, ipv4, NULL, domainName, domainLen);
        }
        // AAAA record (IPv6)
        else if (rtype == 28 && rdlength == 16) {
            SerenoDnsCacheAdd(Context, TRUE, 0, &DnsData[offset], domainName, domainLen);
        }

        offset += rdlength;
    }
}

/*
 * SerenoClassifyDns - Classification function for DNS traffic
 *
 * This intercepts inbound UDP port 53 traffic to parse DNS responses.
 * We always permit the traffic - we're just inspecting it.
 *
 * IMPORTANT: At FWPM_LAYER_INBOUND_TRANSPORT_V4/V6, the data includes
 * the UDP header (8 bytes) followed by the payload. We must skip
 * the UDP header to get to the DNS data.
 */
VOID NTAPI
SerenoClassifyDns(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER3* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    PSERENO_DEVICE_CONTEXT deviceContext = g_DeviceContext;
    NET_BUFFER_LIST* netBufferList = (NET_BUFFER_LIST*)LayerData;
    NET_BUFFER* netBuffer;
    UINT8* allocatedBuffer = NULL;
    UINT32 totalLength = 0;
    UINT32 dnsLength = 0;
    PVOID dataBuffer = NULL;
    const UINT8* dnsData = NULL;

    // UDP header size
    const UINT32 UDP_HEADER_SIZE = 8;

    UNREFERENCED_PARAMETER(InFixedValues);
    UNREFERENCED_PARAMETER(InMetaValues);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    // Always permit DNS traffic
    ClassifyOut->actionType = FWP_ACTION_CONTINUE;

    if (!deviceContext || deviceContext->ShuttingDown || !netBufferList) {
        return;
    }

    // Get the first net buffer
    netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
    if (!netBuffer) {
        return;
    }

    // Get total length (UDP header + DNS payload)
    totalLength = NET_BUFFER_DATA_LENGTH(netBuffer);

    // Need at least UDP header (8) + DNS header (12) = 20 bytes
    if (totalLength < UDP_HEADER_SIZE + 12 || totalLength > 65535) {
        return;
    }

    // Calculate DNS payload length
    dnsLength = totalLength - UDP_HEADER_SIZE;

    // Map the data
    dataBuffer = NdisGetDataBuffer(netBuffer, totalLength, NULL, 1, 0);
    if (!dataBuffer) {
        // Data is not contiguous, need to copy
        allocatedBuffer = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, totalLength, SERENO_POOL_TAG);
        if (!allocatedBuffer) {
            return;
        }
        dataBuffer = NdisGetDataBuffer(netBuffer, totalLength, allocatedBuffer, 1, 0);
        if (!dataBuffer) {
            ExFreePoolWithTag(allocatedBuffer, SERENO_POOL_TAG);
            return;
        }
    }

    // Skip UDP header to get to DNS payload
    dnsData = (const UINT8*)dataBuffer + UDP_HEADER_SIZE;

    // Parse the DNS response
    SerenoParseDnsResponse(deviceContext, dnsData, dnsLength);

    // Free temp buffer if we allocated one
    if (allocatedBuffer) {
        ExFreePoolWithTag(allocatedBuffer, SERENO_POOL_TAG);
    }
}

// ============================================================================
// TLM (Transport Layer Module) - Bandwidth Statistics Implementation
// ============================================================================

/*
 * SerenoBandwidthCacheInit - Initialize bandwidth cache spinlock
 */
VOID
SerenoBandwidthCacheInit(
    _In_ PSERENO_DEVICE_CONTEXT Context
)
{
    KeInitializeSpinLock(&Context->BandwidthCacheLock);
    RtlZeroMemory(Context->BandwidthCache, sizeof(Context->BandwidthCache));
    Context->BandwidthCacheCount = 0;
    SERENO_DBG("Bandwidth cache initialized\n");
}

/*
 * SerenoBandwidthAdd - Add or update bandwidth counters for a flow
 *
 * Called from transport layer classify functions for every packet.
 * Uses FlowHandle as primary key; falls back to port matching if no flow.
 * Thread-safe via spinlock.
 */
VOID
SerenoBandwidthAdd(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ UINT64 FlowHandle,
    _In_ UINT32 ProcessId,
    _In_ BOOLEAN IsIPv6,
    _In_ UINT32 LocalAddressV4,
    _In_ UINT32 RemoteAddressV4,
    _In_ UINT16 LocalPort,
    _In_ UINT16 RemotePort,
    _In_ UINT64 BytesSent,
    _In_ UINT64 BytesReceived
)
{
    KIRQL oldIrql;
    UINT32 i;
    UINT64 now = KeQueryInterruptTime();
    UINT32 targetIndex = MAX_BANDWIDTH_ENTRIES;  // Invalid = not found
    UINT32 oldestIndex = 0;
    UINT64 oldestTime = MAXUINT64;
    UINT32 emptyIndex = MAX_BANDWIDTH_ENTRIES;

    if (!Context || Context->ShuttingDown) {
        return;
    }

    KeAcquireSpinLock(&Context->BandwidthCacheLock, &oldIrql);

    // Search for existing entry or find best slot
    for (i = 0; i < MAX_BANDWIDTH_ENTRIES; i++) {
        if (!Context->BandwidthCache[i].InUse) {
            // Track first empty slot
            if (emptyIndex == MAX_BANDWIDTH_ENTRIES) {
                emptyIndex = i;
            }
            continue;
        }

        // Check for expired entry
        if ((now - Context->BandwidthCache[i].Timestamp) > BANDWIDTH_ENTRY_TTL_100NS) {
            Context->BandwidthCache[i].InUse = FALSE;
            Context->BandwidthCacheCount--;
            if (emptyIndex == MAX_BANDWIDTH_ENTRIES) {
                emptyIndex = i;
            }
            continue;
        }

        // Track oldest for eviction if needed
        if (Context->BandwidthCache[i].Timestamp < oldestTime) {
            oldestTime = Context->BandwidthCache[i].Timestamp;
            oldestIndex = i;
        }

        // Match by FlowHandle (best match)
        if (FlowHandle != 0 && Context->BandwidthCache[i].FlowHandle == FlowHandle) {
            targetIndex = i;
            break;
        }

        // Fallback: Match by ports if FlowHandle is 0
        if (FlowHandle == 0 &&
            Context->BandwidthCache[i].LocalPort == LocalPort &&
            Context->BandwidthCache[i].RemotePort == RemotePort &&
            Context->BandwidthCache[i].ProcessId == ProcessId) {
            targetIndex = i;
            break;
        }
    }

    // If found, update existing entry
    if (targetIndex < MAX_BANDWIDTH_ENTRIES) {
        Context->BandwidthCache[targetIndex].BytesSent += BytesSent;
        Context->BandwidthCache[targetIndex].BytesReceived += BytesReceived;
        Context->BandwidthCache[targetIndex].LastActivity = now;
        KeReleaseSpinLock(&Context->BandwidthCacheLock, oldIrql);
        return;
    }

    // Not found - need to create new entry
    // Prefer empty slot, otherwise evict oldest
    if (emptyIndex < MAX_BANDWIDTH_ENTRIES) {
        targetIndex = emptyIndex;
    } else {
        // Evict oldest entry
        targetIndex = oldestIndex;
        Context->BandwidthCacheCount--;  // Will increment below
    }

    // Initialize new entry
    RtlZeroMemory(&Context->BandwidthCache[targetIndex], sizeof(SERENO_BANDWIDTH_ENTRY));
    Context->BandwidthCache[targetIndex].FlowHandle = FlowHandle;
    Context->BandwidthCache[targetIndex].ProcessId = ProcessId;
    Context->BandwidthCache[targetIndex].IsIPv6 = IsIPv6;
    Context->BandwidthCache[targetIndex].LocalAddressV4 = LocalAddressV4;
    Context->BandwidthCache[targetIndex].RemoteAddressV4 = RemoteAddressV4;
    Context->BandwidthCache[targetIndex].LocalPort = LocalPort;
    Context->BandwidthCache[targetIndex].RemotePort = RemotePort;
    Context->BandwidthCache[targetIndex].BytesSent = BytesSent;
    Context->BandwidthCache[targetIndex].BytesReceived = BytesReceived;
    Context->BandwidthCache[targetIndex].StartTime = now;
    Context->BandwidthCache[targetIndex].LastActivity = now;
    Context->BandwidthCache[targetIndex].Timestamp = now;
    Context->BandwidthCache[targetIndex].InUse = TRUE;
    Context->BandwidthCacheCount++;

    KeReleaseSpinLock(&Context->BandwidthCacheLock, oldIrql);
}

/*
 * SerenoBandwidthGetStats - Get bandwidth statistics for usermode
 *
 * Returns a batch of active bandwidth entries.
 * Called via IOCTL_SERENO_GET_BANDWIDTH.
 */
VOID
SerenoBandwidthGetStats(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _Out_ PSERENO_BANDWIDTH_STATS Stats
)
{
    KIRQL oldIrql;
    UINT32 i;
    UINT32 count = 0;
    UINT64 now = KeQueryInterruptTime();

    RtlZeroMemory(Stats, sizeof(SERENO_BANDWIDTH_STATS));

    if (!Context) {
        return;
    }

    KeAcquireSpinLock(&Context->BandwidthCacheLock, &oldIrql);

    Stats->TotalEntries = Context->BandwidthCacheCount;

    for (i = 0; i < MAX_BANDWIDTH_ENTRIES && count < BANDWIDTH_BATCH_SIZE; i++) {
        if (!Context->BandwidthCache[i].InUse) {
            continue;
        }

        // Skip expired entries
        if ((now - Context->BandwidthCache[i].Timestamp) > BANDWIDTH_ENTRY_TTL_100NS) {
            continue;
        }

        // Copy entry to output
        RtlCopyMemory(&Stats->Entries[count], &Context->BandwidthCache[i], sizeof(SERENO_BANDWIDTH_ENTRY));
        count++;
    }

    Stats->ReturnedCount = count;

    KeReleaseSpinLock(&Context->BandwidthCacheLock, oldIrql);
}

/*
 * SerenoClassifyTransportOutbound - Count bytes sent for bandwidth statistics
 *
 * Called for every outbound TCP/UDP packet at transport layer.
 * This is inspection-only - we always permit and just count bytes.
 */
VOID NTAPI
SerenoClassifyTransportOutbound(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER3* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    PSERENO_DEVICE_CONTEXT deviceContext = g_DeviceContext;
    UINT32 packetSize = 0;
    UINT64 flowHandle = 0;
    UINT32 processId = 0;
    UINT16 localPort = 0;
    UINT16 remotePort = 0;
    UINT32 localAddrV4 = 0;
    UINT32 remoteAddrV4 = 0;
    BOOLEAN isIPv6 = FALSE;
    static UINT64 tlmOutCallCount = 0;

    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    // Debug: track that this function is being called at all
    tlmOutCallCount++;
    if ((tlmOutCallCount % 100) == 1) {
        SERENO_DBG("TLM OUTBOUND called: count=%llu\n", tlmOutCallCount);
    }

    // Always permit - TLM is inspection only
    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    if (!deviceContext || !deviceContext->FilteringEnabled || deviceContext->ShuttingDown) {
        return;
    }

    // Get packet size from NET_BUFFER_LIST
    if (LayerData) {
        PNET_BUFFER_LIST nbl = (PNET_BUFFER_LIST)LayerData;
        PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
        if (nb) {
            packetSize = NET_BUFFER_DATA_LENGTH(nb);
        }
    }

    if (packetSize == 0) {
        return;  // Nothing to count
    }

    // Get flow handle for matching
    if (InMetaValues && (InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE)) {
        flowHandle = InMetaValues->flowHandle;
    }

    // Get process ID
    if (InMetaValues && (InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = (UINT32)(ULONG_PTR)InMetaValues->processId;
    }

    // Determine IP version and extract addresses/ports
    if (InFixedValues) {
        // Check layer to determine IP version
        if (InFixedValues->layerId == FWPS_LAYER_OUTBOUND_TRANSPORT_V4) {
            isIPv6 = FALSE;
            localAddrV4 = InFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
            remoteAddrV4 = InFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
            localPort = InFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
            remotePort = InFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
        } else {
            isIPv6 = TRUE;
            localPort = InFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_LOCAL_PORT].value.uint16;
            remotePort = InFixedValues->incomingValue[FWPS_FIELD_OUTBOUND_TRANSPORT_V6_IP_REMOTE_PORT].value.uint16;
            // IPv6 addresses not stored in simple uint32 - leave as 0 for now
        }
    }

    // Update bandwidth counters
    SerenoBandwidthAdd(
        deviceContext,
        flowHandle,
        processId,
        isIPv6,
        localAddrV4,
        remoteAddrV4,
        localPort,
        remotePort,
        packetSize,     // bytes sent
        0               // bytes received
    );
}

/*
 * SerenoClassifyTransportInbound - Count bytes received for bandwidth statistics
 *
 * Called for every inbound TCP/UDP packet at transport layer.
 * This is inspection-only - we always permit and just count bytes.
 */
VOID NTAPI
SerenoClassifyTransportInbound(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER3* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
)
{
    PSERENO_DEVICE_CONTEXT deviceContext = g_DeviceContext;
    UINT32 packetSize = 0;
    UINT64 flowHandle = 0;
    UINT32 processId = 0;
    UINT16 localPort = 0;
    UINT16 remotePort = 0;
    UINT32 localAddrV4 = 0;
    UINT32 remoteAddrV4 = 0;
    BOOLEAN isIPv6 = FALSE;
    static UINT64 tlmInCallCount = 0;

    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    // Debug: track that this function is being called at all
    tlmInCallCount++;
    if ((tlmInCallCount % 100) == 1) {
        SERENO_DBG("TLM INBOUND called: count=%llu\n", tlmInCallCount);
    }

    // Always permit - TLM is inspection only
    ClassifyOut->actionType = FWP_ACTION_PERMIT;

    if (!deviceContext || !deviceContext->FilteringEnabled || deviceContext->ShuttingDown) {
        return;
    }

    // Get packet size from NET_BUFFER_LIST
    if (LayerData) {
        PNET_BUFFER_LIST nbl = (PNET_BUFFER_LIST)LayerData;
        PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
        if (nb) {
            packetSize = NET_BUFFER_DATA_LENGTH(nb);
        }
    }

    if (packetSize == 0) {
        return;  // Nothing to count
    }

    // Get flow handle for matching
    if (InMetaValues && (InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_FLOW_HANDLE)) {
        flowHandle = InMetaValues->flowHandle;
    }

    // Get process ID (may not be available for inbound)
    if (InMetaValues && (InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = (UINT32)(ULONG_PTR)InMetaValues->processId;
    }

    // Determine IP version and extract addresses/ports
    if (InFixedValues) {
        if (InFixedValues->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V4) {
            isIPv6 = FALSE;
            localAddrV4 = InFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_ADDRESS].value.uint32;
            remoteAddrV4 = InFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32;
            localPort = InFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_LOCAL_PORT].value.uint16;
            remotePort = InFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_PORT].value.uint16;
        } else {
            isIPv6 = TRUE;
            localPort = InFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_LOCAL_PORT].value.uint16;
            remotePort = InFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_PORT].value.uint16;
        }
    }

    // Update bandwidth counters
    SerenoBandwidthAdd(
        deviceContext,
        flowHandle,
        processId,
        isIPv6,
        localAddrV4,
        remoteAddrV4,
        localPort,
        remotePort,
        0,              // bytes sent
        packetSize      // bytes received
    );
}
