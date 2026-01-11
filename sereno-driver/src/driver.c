/*
 * Sereno WFP Callout Driver - Main Implementation
 *
 * This driver implements synchronous connection filtering using WFP callouts
 * at the ALE (Application Layer Enforcement) layers.
 */

#include "driver.h"

// Global device context pointer for callout functions
static PSERENO_DEVICE_CONTEXT g_DeviceContext = NULL;

/*
 * DriverEntry - Driver initialization
 */
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;

    KdPrint(("Sereno: DriverEntry\n"));

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    WDF_DRIVER_CONFIG_INIT(&config, SerenoEvtDeviceAdd);

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        &attributes,
        &config,
        WDF_NO_HANDLE
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: WdfDriverCreate failed: 0x%08X\n", status));
        return status;
    }

    KdPrint(("Sereno: Driver initialized successfully\n"));
    return STATUS_SUCCESS;
}

/*
 * SerenoEvtDeviceAdd - Create device and initialize WFP
 */
NTSTATUS
SerenoEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    NTSTATUS status;
    WDFDEVICE device;
    PSERENO_DEVICE_CONTEXT deviceContext;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;
    DECLARE_CONST_UNICODE_STRING(deviceName, SERENO_DEVICE_NAME);
    DECLARE_CONST_UNICODE_STRING(symlinkName, SERENO_SYMLINK_NAME);

    UNREFERENCED_PARAMETER(Driver);

    KdPrint(("Sereno: SerenoEvtDeviceAdd\n"));

    // Set device name
    status = WdfDeviceInitAssignName(DeviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: WdfDeviceInitAssignName failed: 0x%08X\n", status));
        return status;
    }

    // Set device type
    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_NETWORK);
    WdfDeviceInitSetCharacteristics(DeviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);

    // Set cleanup callback
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, SERENO_DEVICE_CONTEXT);
    deviceAttributes.EvtCleanupCallback = SerenoEvtDeviceContextCleanup;

    // Create device
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: WdfDeviceCreate failed: 0x%08X\n", status));
        return status;
    }

    // Get device context
    deviceContext = SerenoGetDeviceContext(device);
    RtlZeroMemory(deviceContext, sizeof(SERENO_DEVICE_CONTEXT));
    deviceContext->Device = device;
    g_DeviceContext = deviceContext;

    // Initialize pending list
    InitializeListHead(&deviceContext->PendingList);
    KeInitializeSpinLock(&deviceContext->PendingLock);
    deviceContext->PendingCount = 0;
    deviceContext->NextRequestId = 1;
    deviceContext->FilteringEnabled = FALSE;
    deviceContext->ShuttingDown = FALSE;

    // Create symbolic link
    status = WdfDeviceCreateSymbolicLink(device, &symlinkName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: WdfDeviceCreateSymbolicLink failed: 0x%08X\n", status));
        return status;
    }

    // Create I/O queue
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = SerenoEvtIoDeviceControl;

    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: WdfIoQueueCreate failed: 0x%08X\n", status));
        return status;
    }

    // Register WFP callouts
    status = SerenoRegisterCallouts(deviceContext);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Sereno: SerenoRegisterCallouts failed: 0x%08X\n", status));
        // Don't fail device creation, just log
    }

    KdPrint(("Sereno: Device created successfully\n"));
    return STATUS_SUCCESS;
}

/*
 * SerenoEvtDeviceContextCleanup - Cleanup on device removal
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

    KdPrint(("Sereno: SerenoEvtDeviceContextCleanup\n"));

    deviceContext = SerenoGetDeviceContext(Device);
    deviceContext->ShuttingDown = TRUE;

    // Unregister WFP callouts
    SerenoUnregisterCallouts(deviceContext);

    // Free all pending requests
    KeAcquireSpinLock(&deviceContext->PendingLock, &oldIrql);
    while (!IsListEmpty(&deviceContext->PendingList)) {
        entry = RemoveHeadList(&deviceContext->PendingList);
        request = CONTAINING_RECORD(entry, PENDING_REQUEST, ListEntry);
        KeSetEvent(&request->CompletionEvent, IO_NO_INCREMENT, FALSE);
        // Don't free here - the classify function will free after event is set
    }
    KeReleaseSpinLock(&deviceContext->PendingLock, oldIrql);

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
                if (pendingRequest->Verdict == SERENO_VERDICT_PENDING) {
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
        deviceContext->FilteringEnabled = TRUE;
        KdPrint(("Sereno: Filtering enabled\n"));
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
    FWPM_FILTER_CONDITION0 filterConditions[1] = { 0 };

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
        // Remove filters
        if (DeviceContext->ConnectFilterIdV4) {
            FwpmFilterDeleteById0(DeviceContext->EngineHandle, DeviceContext->ConnectFilterIdV4);
        }
        if (DeviceContext->ConnectFilterIdV6) {
            FwpmFilterDeleteById0(DeviceContext->EngineHandle, DeviceContext->ConnectFilterIdV6);
        }

        FwpmEngineClose0(DeviceContext->EngineHandle);
        DeviceContext->EngineHandle = NULL;
    }

    // Unregister callouts
    if (DeviceContext->ConnectCalloutIdV4) {
        FwpsCalloutUnregisterById0(DeviceContext->ConnectCalloutIdV4);
        DeviceContext->ConnectCalloutIdV4 = 0;
    }
    if (DeviceContext->ConnectCalloutIdV6) {
        FwpsCalloutUnregisterById0(DeviceContext->ConnectCalloutIdV6);
        DeviceContext->ConnectCalloutIdV6 = 0;
    }

    KdPrint(("Sereno: Callouts unregistered\n"));
}

/*
 * SerenoClassifyConnect - Main classification function for connection attempts
 *
 * This is called by WFP for every connection attempt BEFORE it's established.
 * We can BLOCK, PERMIT, or PEND the connection for user-mode decision.
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
    LARGE_INTEGER timeout;
    UINT32 localAddr, remoteAddr;
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
        // IPv6 - TODO: implement
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    } else {
        // IPv4
        localAddr = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
        remoteAddr = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
        localPort = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16;
        remotePort = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
        protocol = InFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;
    }

    // Get process ID
    if (InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
        processId = InMetaValues->processId;
    } else {
        processId = (HANDLE)0;
    }

    // Update stats
    InterlockedIncrement64((LONG64*)&deviceContext->Stats.TotalConnections);

    // Check if we're at capacity
    if (deviceContext->PendingCount >= MAX_PENDING_REQUESTS) {
        InterlockedIncrement64((LONG64*)&deviceContext->Stats.DroppedRequests);
        ClassifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Allocate pending request
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
    pendingRequest->ConnectionInfo.IpVersion = 4;
    pendingRequest->ConnectionInfo.LocalAddressV4 = localAddr;
    pendingRequest->ConnectionInfo.RemoteAddressV4 = remoteAddr;
    pendingRequest->ConnectionInfo.LocalPort = localPort;
    pendingRequest->ConnectionInfo.RemotePort = remotePort;

    // Get process path
    if (processId) {
        status = SerenoGetProcessPath(processId, processPath, sizeof(processPath) / sizeof(WCHAR), &processPathLength);
        if (NT_SUCCESS(status)) {
            RtlCopyMemory(pendingRequest->ConnectionInfo.ApplicationPath, processPath,
                         min(processPathLength * sizeof(WCHAR), sizeof(pendingRequest->ConnectionInfo.ApplicationPath)));
            pendingRequest->ConnectionInfo.ApplicationPathLength = processPathLength;
        }
    }

    // Add to pending list
    KeAcquireSpinLock(&deviceContext->PendingLock, &oldIrql);
    InsertTailList(&deviceContext->PendingList, &pendingRequest->ListEntry);
    deviceContext->PendingCount++;
    KeReleaseSpinLock(&deviceContext->PendingLock, oldIrql);

    // Pend the connection and wait for user-mode verdict
    ClassifyOut->actionType = FWP_ACTION_BLOCK;
    ClassifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;

    // Wait for verdict with timeout
    timeout.QuadPart = -((LONGLONG)REQUEST_TIMEOUT_MS * 10000); // Convert to 100ns units, negative for relative
    status = KeWaitForSingleObject(&pendingRequest->CompletionEvent, Executive, KernelMode, FALSE, &timeout);

    // Remove from pending list
    KeAcquireSpinLock(&deviceContext->PendingLock, &oldIrql);
    RemoveEntryList(&pendingRequest->ListEntry);
    deviceContext->PendingCount--;
    KeReleaseSpinLock(&deviceContext->PendingLock, oldIrql);

    // Apply verdict
    if (status == STATUS_TIMEOUT) {
        // Timeout - default to block
        InterlockedIncrement64((LONG64*)&deviceContext->Stats.TimedOutRequests);
        InterlockedIncrement64((LONG64*)&deviceContext->Stats.BlockedConnections);
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
    } else {
        switch (pendingRequest->Verdict) {
        case SERENO_VERDICT_ALLOW:
            InterlockedIncrement64((LONG64*)&deviceContext->Stats.AllowedConnections);
            ClassifyOut->actionType = FWP_ACTION_PERMIT;
            break;
        case SERENO_VERDICT_BLOCK:
        default:
            InterlockedIncrement64((LONG64*)&deviceContext->Stats.BlockedConnections);
            ClassifyOut->actionType = FWP_ACTION_BLOCK;
            break;
        }
    }

    // Clear absorb flag so our action takes effect
    ClassifyOut->flags &= ~FWPS_CLASSIFY_OUT_FLAG_ABSORB;

    SerenoFreePendingRequest(pendingRequest);
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
    KeInitializeEvent(&request->CompletionEvent, NotificationEvent, FALSE);

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
 */
VOID
SerenoCompletePendingRequest(
    _In_ PSERENO_DEVICE_CONTEXT Context,
    _In_ UINT64 RequestId,
    _In_ SERENO_VERDICT Verdict
)
{
    PLIST_ENTRY entry;
    PPENDING_REQUEST request;
    KIRQL oldIrql;

    KeAcquireSpinLock(&Context->PendingLock, &oldIrql);

    for (entry = Context->PendingList.Flink;
         entry != &Context->PendingList;
         entry = entry->Flink) {
        request = CONTAINING_RECORD(entry, PENDING_REQUEST, ListEntry);
        if (request->RequestId == RequestId) {
            request->Verdict = Verdict;
            KeSetEvent(&request->CompletionEvent, IO_NO_INCREMENT, FALSE);
            break;
        }
    }

    KeReleaseSpinLock(&Context->PendingLock, oldIrql);
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
