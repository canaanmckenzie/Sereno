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

// SDDL string for device security (System full access, Administrators full access)
DECLARE_CONST_UNICODE_STRING(SERENO_DEVICE_SDDL, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

// Global device context pointer for callout functions
static PSERENO_DEVICE_CONTEXT g_DeviceContext = NULL;
static WDFDEVICE g_ControlDevice = NULL;

// Forward declaration
EVT_WDF_DRIVER_UNLOAD SerenoEvtDriverUnload;

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

    KdPrint(("Sereno: DriverEntry\n"));

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
        KdPrint(("Sereno: WdfDriverCreate failed: 0x%08X\n", status));
        return status;
    }

    // Allocate a device init structure for our control device
    deviceInit = WdfControlDeviceInitAllocate(driver, &SERENO_DEVICE_SDDL);
    if (deviceInit == NULL) {
        KdPrint(("Sereno: WdfControlDeviceInitAllocate failed\n"));
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set device name
    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: WdfDeviceInitAssignName failed: 0x%08X\n", status));
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
        KdPrint(("Sereno: WdfDeviceCreate failed: 0x%08X\n", status));
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

    // Create symbolic link
    status = WdfDeviceCreateSymbolicLink(g_ControlDevice, &symlinkName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: WdfDeviceCreateSymbolicLink failed: 0x%08X\n", status));
        return status;
    }

    // Create I/O queue
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = SerenoEvtIoDeviceControl;

    status = WdfIoQueueCreate(g_ControlDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: WdfIoQueueCreate failed: 0x%08X\n", status));
        return status;
    }

    // Register WFP callouts
    status = SerenoRegisterCallouts(deviceContext);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: SerenoRegisterCallouts failed: 0x%08X\n", status));
        // Don't fail driver load, just log
    }

    // Finish initializing the control device
    WdfControlFinishInitializing(g_ControlDevice);

    KdPrint(("Sereno: Driver initialized successfully\n"));
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
    KdPrint(("Sereno: Driver unloading\n"));

    // Cleanup is handled by device context cleanup callback
    if (g_ControlDevice != NULL) {
        WdfObjectDelete(g_ControlDevice);
        g_ControlDevice = NULL;
    }
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

    KdPrint(("Sereno: SerenoEvtDeviceContextCleanup\n"));

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
    KdPrint(("Sereno: Cleanup complete\n"));
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
        KdPrint(("Sereno: Filtering enabled (circuit breaker reset)\n"));
        break;
    }

    case IOCTL_SERENO_DISABLE:
    {
        deviceContext->FilteringEnabled = FALSE;
        KdPrint(("Sereno: Filtering disabled\n"));
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

    KdPrint(("Sereno: Registering callouts\n"));

    // Open WFP engine
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &DeviceContext->EngineHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: FwpmEngineOpen0 failed: 0x%08X\n", status));
        return status;
    }

    // Start transaction
    status = FwpmTransactionBegin0(DeviceContext->EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: FwpmTransactionBegin0 failed: 0x%08X\n", status));
        goto cleanup;
    }

    // Add provider
    provider.providerKey = SERENO_PROVIDER_GUID;
    provider.displayData.name = L"Sereno Network Filter";
    provider.displayData.description = L"Sereno Application Firewall Provider";
    provider.flags = 0;

    status = FwpmProviderAdd0(DeviceContext->EngineHandle, &provider, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        KdPrint(("Sereno: FwpmProviderAdd0 failed: 0x%08X\n", status));
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
        KdPrint(("Sereno: FwpmSubLayerAdd0 failed: 0x%08X\n", status));
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
        KdPrint(("Sereno: FwpsCalloutRegister3 (Connect V4) failed: 0x%08X\n", status));
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
        KdPrint(("Sereno: FwpmCalloutAdd0 (Connect V4) failed: 0x%08X\n", status));
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Register Connect V6 callout
    sCallout.calloutKey = SERENO_CALLOUT_CONNECT_V6_GUID;
    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(DeviceContext->Device),
                                   &sCallout, &DeviceContext->ConnectCalloutIdV6);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: FwpsCalloutRegister3 (Connect V6) failed: 0x%08X\n", status));
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    mCallout.calloutKey = SERENO_CALLOUT_CONNECT_V6_GUID;
    mCallout.displayData.name = L"Sereno Connect V6 Callout";
    mCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;

    status = FwpmCalloutAdd0(DeviceContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        KdPrint(("Sereno: FwpmCalloutAdd0 (Connect V6) failed: 0x%08X\n", status));
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
        KdPrint(("Sereno: FwpmFilterAdd0 (Connect V4) failed: 0x%08X\n", status));
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Add filter for Connect V6
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.displayData.name = L"Sereno Connect V6 Filter";
    filter.action.calloutKey = SERENO_CALLOUT_CONNECT_V6_GUID;

    status = FwpmFilterAdd0(DeviceContext->EngineHandle, &filter, NULL, &DeviceContext->ConnectFilterIdV6);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: FwpmFilterAdd0 (Connect V6) failed: 0x%08X\n", status));
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
        KdPrint(("Sereno: FwpsCalloutRegister3 (DNS V4) failed: 0x%08X\n", status));
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
        KdPrint(("Sereno: FwpmCalloutAdd0 (DNS V4) failed: 0x%08X\n", status));
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    // Register DNS V6 callout
    sCallout.calloutKey = SERENO_CALLOUT_DNS_V6_GUID;
    status = FwpsCalloutRegister3(WdfDeviceWdmGetDeviceObject(DeviceContext->Device),
                                   &sCallout, &DeviceContext->DnsCalloutIdV6);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: FwpsCalloutRegister3 (DNS V6) failed: 0x%08X\n", status));
        FwpmTransactionAbort0(DeviceContext->EngineHandle);
        goto cleanup;
    }

    mCallout.calloutKey = SERENO_CALLOUT_DNS_V6_GUID;
    mCallout.displayData.name = L"Sereno DNS V6 Callout";
    mCallout.applicableLayer = FWPM_LAYER_INBOUND_TRANSPORT_V6;

    status = FwpmCalloutAdd0(DeviceContext->EngineHandle, &mCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
        KdPrint(("Sereno: FwpmCalloutAdd0 (DNS V6) failed: 0x%08X\n", status));
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
            KdPrint(("Sereno: FwpmFilterAdd0 (DNS V4) failed: 0x%08X\n", status));
            FwpmTransactionAbort0(DeviceContext->EngineHandle);
            goto cleanup;
        }

        // Add DNS filter V6
        filter.layerKey = FWPM_LAYER_INBOUND_TRANSPORT_V6;
        filter.displayData.name = L"Sereno DNS V6 Filter";
        filter.action.calloutKey = SERENO_CALLOUT_DNS_V6_GUID;

        status = FwpmFilterAdd0(DeviceContext->EngineHandle, &filter, NULL, &DeviceContext->DnsFilterIdV6);
        if (!NT_SUCCESS(status)) {
            KdPrint(("Sereno: FwpmFilterAdd0 (DNS V6) failed: 0x%08X\n", status));
            FwpmTransactionAbort0(DeviceContext->EngineHandle);
            goto cleanup;
        }
    }

    // Commit transaction
    status = FwpmTransactionCommit0(DeviceContext->EngineHandle);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: FwpmTransactionCommit0 failed: 0x%08X\n", status));
        goto cleanup;
    }

    KdPrint(("Sereno: Callouts registered successfully\n"));
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
    KdPrint(("Sereno: Unregistering callouts\n"));

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

    KdPrint(("Sereno: Callouts unregistered\n"));
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

    // Update stats
    InterlockedIncrement64((LONG64*)&deviceContext->Stats.TotalConnections);

    // NOTE: KdPrint removed from hot path - was causing overhead under heavy load
    // Use WinDbg tracing if needed for debugging

    // Check if we're at capacity
    if (deviceContext->PendingCount >= MAX_PENDING_REQUESTS) {
        InterlockedIncrement64((LONG64*)&deviceContext->Stats.DroppedRequests);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // FIX #2: Check for completion handle BEFORE allocating anything
    // No completion handle = re-authorization (shouldn't happen after Fix #1)
    // With Fix #1, we pass verdict directly to FwpsCompleteOperation0, so no re-auth occurs.
    // This check is kept as a safety net - if somehow re-auth happens, just permit.
    if (!(InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_COMPLETION_HANDLE)) {
        // Re-auth path - should never happen with Fix #1, but permit if it does
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
    // ASYNC PENDING MODEL (Production - Like Little Snitch)
    //
    // We use FwpsPendOperation0 to hold the connection WITHOUT blocking
    // kernel threads. WFP handles the blocking internally. When user-mode
    // sends a verdict, we call FwpsCompleteOperation0 to allow/block.
    //
    // With Fix #1, we pass verdict directly to FwpsCompleteOperation0,
    // so no re-authorization occurs. The completion handle check moved
    // earlier (Fix #2) so we never reach here without a valid handle.
    // ============================================================

    // Pend the operation - returns immediately, connection is held by WFP
    status = FwpsPendOperation0(
        InMetaValues->completionHandle,
        &pendingRequest->CompletionContext
    );

    if (!NT_SUCCESS(status)) {
        // Pending failed, permit and continue
        KdPrint(("Sereno: FwpsPendOperation0 failed: 0x%08X\n", status));
        SerenoFreePendingRequest(pendingRequest);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    pendingRequest->Completed = FALSE;

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
        SerenoVerdictCacheAdd(
            Context,
            request->ConnectionInfo.ProcessId,
            request->IsIPv6,
            request->ConnectionInfo.RemoteAddressV4,
            request->IsIPv6 ? request->ConnectionInfo.RemoteAddressV6 : NULL,
            request->ConnectionInfo.RemotePort,
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
 */
VOID
SerenoVerdictCacheAdd(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ UINT32 ProcessId,
    _In_ BOOLEAN IsIPv6,
    _In_ UINT32 RemoteIpV4,
    _In_opt_ const UINT8* RemoteIpV6,
    _In_ UINT16 RemotePort,
    _In_ SERENO_VERDICT Verdict
)
{
    KIRQL oldIrql;
    UINT64 now = KeQueryInterruptTime();
    UINT32 oldestIndex = 0;
    UINT64 oldestTime = MAXUINT64;
    UINT32 i;

    KeAcquireSpinLock(&Context->VerdictCacheLock, &oldIrql);

    // Find empty slot or oldest entry
    for (i = 0; i < MAX_VERDICT_CACHE_ENTRIES; i++) {
        if (!Context->VerdictCache[i].InUse) {
            oldestIndex = i;
            break;
        }
        // Check for expired entry
        if ((now - Context->VerdictCache[i].Timestamp) > VERDICT_CACHE_TTL_100NS) {
            oldestIndex = i;
            break;
        }
        // Track oldest
        if (Context->VerdictCache[i].Timestamp < oldestTime) {
            oldestTime = Context->VerdictCache[i].Timestamp;
            oldestIndex = i;
        }
    }

    // Store in cache
    Context->VerdictCache[oldestIndex].Timestamp = now;
    Context->VerdictCache[oldestIndex].ProcessId = ProcessId;
    Context->VerdictCache[oldestIndex].IsIPv6 = IsIPv6;
    Context->VerdictCache[oldestIndex].RemoteIpV4 = RemoteIpV4;
    if (IsIPv6 && RemoteIpV6) {
        RtlCopyMemory(Context->VerdictCache[oldestIndex].RemoteIpV6, RemoteIpV6, 16);
    }
    Context->VerdictCache[oldestIndex].RemotePort = RemotePort;
    Context->VerdictCache[oldestIndex].Verdict = Verdict;
    Context->VerdictCache[oldestIndex].InUse = TRUE;

    KeReleaseSpinLock(&Context->VerdictCacheLock, oldIrql);
}

/*
 * SerenoVerdictCacheLookup - Check if we have a cached verdict for this connection
 * Called during re-authorization (no completion handle available)
 * Returns TRUE if found (and sets Verdict), FALSE if not found
 */
BOOLEAN
SerenoVerdictCacheLookup(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ UINT32 ProcessId,
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

        // Check match
        if (Context->VerdictCache[i].ProcessId != ProcessId) continue;
        if (Context->VerdictCache[i].RemotePort != RemotePort) continue;
        if (Context->VerdictCache[i].IsIPv6 != IsIPv6) continue;

        if (IsIPv6) {
            if (RemoteIpV6 && RtlCompareMemory(Context->VerdictCache[i].RemoteIpV6, RemoteIpV6, 16) == 16) {
                *Verdict = Context->VerdictCache[i].Verdict;
                // DON'T clear entry - allow multiple re-auths to use same verdict
                // Entry will be cleared by TTL expiration
                found = TRUE;
                break;
            }
        } else {
            if (Context->VerdictCache[i].RemoteIpV4 == RemoteIpV4) {
                *Verdict = Context->VerdictCache[i].Verdict;
                // DON'T clear entry - allow multiple re-auths to use same verdict
                // Entry will be cleared by TTL expiration
                found = TRUE;
                break;
            }
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
