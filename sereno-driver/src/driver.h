/*
 * Sereno WFP Callout Driver
 *
 * Kernel-mode driver for synchronous network connection filtering
 * using Windows Filtering Platform (WFP) callouts.
 */

#ifndef SERENO_DRIVER_H
#define SERENO_DRIVER_H

#include <ntddk.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <netiodef.h>
#include <ndis.h>
#include <mstcpip.h>

// Driver name and device
#define SERENO_DRIVER_NAME      L"SerenoFilter"
#define SERENO_DEVICE_NAME      L"\\Device\\SerenoFilter"
#define SERENO_SYMLINK_NAME     L"\\DosDevices\\SerenoFilter"
#define SERENO_POOL_TAG         'oreS'

// Maximum pending requests
#define MAX_PENDING_REQUESTS    1000
#define REQUEST_TIMEOUT_MS      30000

// IOCTL codes
#define FILE_DEVICE_SERENO      0x8000

#define IOCTL_SERENO_GET_PENDING    CTL_CODE(FILE_DEVICE_SERENO, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_SERENO_SET_VERDICT    CTL_CODE(FILE_DEVICE_SERENO, 0x802, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_SERENO_GET_STATS      CTL_CODE(FILE_DEVICE_SERENO, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_SERENO_SET_RULES      CTL_CODE(FILE_DEVICE_SERENO, 0x804, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_SERENO_ENABLE         CTL_CODE(FILE_DEVICE_SERENO, 0x805, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_SERENO_DISABLE        CTL_CODE(FILE_DEVICE_SERENO, 0x806, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// Verdict values
typedef enum _SERENO_VERDICT {
    SERENO_VERDICT_PENDING = 0,
    SERENO_VERDICT_ALLOW = 1,
    SERENO_VERDICT_BLOCK = 2,
} SERENO_VERDICT;

// Connection direction
typedef enum _SERENO_DIRECTION {
    SERENO_DIRECTION_OUTBOUND = 0,
    SERENO_DIRECTION_INBOUND = 1,
} SERENO_DIRECTION;

// Protocol
typedef enum _SERENO_PROTOCOL {
    SERENO_PROTOCOL_TCP = 6,
    SERENO_PROTOCOL_UDP = 17,
    SERENO_PROTOCOL_ICMP = 1,
} SERENO_PROTOCOL;

#pragma pack(push, 1)

// Connection request sent to user-mode
typedef struct _SERENO_CONNECTION_REQUEST {
    UINT64      RequestId;
    UINT64      Timestamp;
    UINT32      ProcessId;
    UINT8       Protocol;
    UINT8       Direction;
    UINT8       IpVersion;      // 4 or 6
    UINT8       Reserved;

    // IPv4 addresses (network byte order)
    UINT32      LocalAddressV4;
    UINT32      RemoteAddressV4;

    // IPv6 addresses
    UINT8       LocalAddressV6[16];
    UINT8       RemoteAddressV6[16];

    UINT16      LocalPort;      // host byte order
    UINT16      RemotePort;     // host byte order

    // Process information
    WCHAR       ApplicationPath[260];
    UINT32      ApplicationPathLength;

    // DNS info (if available from SNI or DNS query)
    WCHAR       DomainName[256];
    UINT32      DomainNameLength;
} SERENO_CONNECTION_REQUEST, *PSERENO_CONNECTION_REQUEST;

// Verdict response from user-mode
typedef struct _SERENO_VERDICT_RESPONSE {
    UINT64      RequestId;
    UINT32      Verdict;        // SERENO_VERDICT
    UINT32      Reserved;
} SERENO_VERDICT_RESPONSE, *PSERENO_VERDICT_RESPONSE;

// Statistics
typedef struct _SERENO_STATS {
    UINT64      TotalConnections;
    UINT64      AllowedConnections;
    UINT64      BlockedConnections;
    UINT64      PendingRequests;
    UINT64      TimedOutRequests;
    UINT64      DroppedRequests;
} SERENO_STATS, *PSERENO_STATS;

#pragma pack(pop)

// Pending request structure (internal)
typedef struct _PENDING_REQUEST {
    LIST_ENTRY      ListEntry;
    UINT64          RequestId;
    UINT64          Timestamp;
    UINT64          ClassifyHandle;
    BOOLEAN         IsIPv6;
    SERENO_VERDICT  Verdict;
    KEVENT          CompletionEvent;
    SERENO_CONNECTION_REQUEST ConnectionInfo;
} PENDING_REQUEST, *PPENDING_REQUEST;

// Driver context
typedef struct _SERENO_DEVICE_CONTEXT {
    WDFDEVICE       Device;
    HANDLE          EngineHandle;
    HANDLE          InjectionHandle;

    // Callout IDs
    UINT32          ConnectCalloutIdV4;
    UINT32          ConnectCalloutIdV6;
    UINT32          RecvAcceptCalloutIdV4;
    UINT32          RecvAcceptCalloutIdV6;

    // Filter IDs
    UINT64          ConnectFilterIdV4;
    UINT64          ConnectFilterIdV6;
    UINT64          RecvAcceptFilterIdV4;
    UINT64          RecvAcceptFilterIdV6;

    // Pending requests
    LIST_ENTRY      PendingList;
    KSPIN_LOCK      PendingLock;
    UINT32          PendingCount;
    UINT64          NextRequestId;

    // Statistics
    SERENO_STATS    Stats;

    // State
    BOOLEAN         FilteringEnabled;
    BOOLEAN         ShuttingDown;
} SERENO_DEVICE_CONTEXT, *PSERENO_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(SERENO_DEVICE_CONTEXT, SerenoGetDeviceContext)

// GUIDs for our WFP objects
// {53455245-4E4F-4452-5601-000000000001} Sereno Provider
DEFINE_GUID(SERENO_PROVIDER_GUID,
    0x53455245, 0x4E4F, 0x4452,
    0x56, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

// {53455245-4E4F-5355-4201-000000000001} Sereno Sublayer
DEFINE_GUID(SERENO_SUBLAYER_GUID,
    0x53455245, 0x4E4F, 0x5355,
    0x42, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

// {53455245-4E4F-434F-4E01-000000000001} Connect Callout V4
DEFINE_GUID(SERENO_CALLOUT_CONNECT_V4_GUID,
    0x53455245, 0x4E4F, 0x434F,
    0x4E, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

// {53455245-4E4F-434F-4E02-000000000001} Connect Callout V6
DEFINE_GUID(SERENO_CALLOUT_CONNECT_V6_GUID,
    0x53455245, 0x4E4F, 0x434F,
    0x4E, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

// {53455245-4E4F-5245-4301-000000000001} Recv Accept Callout V4
DEFINE_GUID(SERENO_CALLOUT_RECV_V4_GUID,
    0x53455245, 0x4E4F, 0x5245,
    0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

// {53455245-4E4F-5245-4302-000000000001} Recv Accept Callout V6
DEFINE_GUID(SERENO_CALLOUT_RECV_V6_GUID,
    0x53455245, 0x4E4F, 0x5245,
    0x43, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

// Function prototypes
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD SerenoEvtDeviceAdd;
EVT_WDF_DEVICE_CONTEXT_CLEANUP SerenoEvtDeviceContextCleanup;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL SerenoEvtIoDeviceControl;

// WFP callout functions
NTSTATUS SerenoRegisterCallouts(_In_ PSERENO_DEVICE_CONTEXT DeviceContext);
VOID SerenoUnregisterCallouts(_In_ PSERENO_DEVICE_CONTEXT DeviceContext);

// Callout classify function
VOID NTAPI SerenoClassifyConnect(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER3* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
);

// Callout notify function
NTSTATUS NTAPI SerenoNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER3* Filter
);

// Callout flow delete function (not used for ALE)
VOID NTAPI SerenoFlowDelete(
    _In_ UINT16 LayerId,
    _In_ UINT32 CalloutId,
    _In_ UINT64 FlowContext
);

// Pending request management
PPENDING_REQUEST SerenoAllocatePendingRequest(_In_ PSERENO_DEVICE_CONTEXT Context);
VOID SerenoFreePendingRequest(_In_ PPENDING_REQUEST Request);
PPENDING_REQUEST SerenoFindPendingRequest(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ UINT64 RequestId);
VOID SerenoCompletePendingRequest(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ UINT64 RequestId, _In_ SERENO_VERDICT Verdict);

// Process info helpers
NTSTATUS SerenoGetProcessPath(_In_ HANDLE ProcessId, _Out_writes_(PathLength) PWCHAR Path, _In_ ULONG PathLength, _Out_ PULONG ActualLength);

#endif // SERENO_DRIVER_H
