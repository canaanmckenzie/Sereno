/*
 * Sereno WFP Callout Driver
 *
 * Kernel-mode driver for synchronous network connection filtering
 * using Windows Filtering Platform (WFP) callouts.
 */

#ifndef SERENO_DRIVER_H
#define SERENO_DRIVER_H

// NDIS version must be defined before includes for WFP
#define NDIS683

// Suppress expected warnings from Windows SDK headers
#pragma warning(push)
#pragma warning(disable: 4201) // nameless struct/union

#include <ntifs.h>
#include <ntddk.h>
#include <ndis.h>
#include <wdf.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <guiddef.h>

#pragma warning(pop)

// GUID_NULL may not be defined in kernel mode
#ifndef GUID_NULL
DEFINE_GUID(GUID_NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
#endif

// Driver name and device
#define SERENO_DRIVER_NAME      L"SerenoFilter"
#define SERENO_DEVICE_NAME      L"\\Device\\SerenoFilter"
#define SERENO_SYMLINK_NAME     L"\\DosDevices\\SerenoFilter"
#define SERENO_POOL_TAG         'oreS'

// Maximum pending requests (async model - NO kernel thread blocking)
// FwpsPendOperation0/FwpsCompleteOperation0 holds connections without blocking
// Can be high since we're only limited by memory, not thread count
#define MAX_PENDING_REQUESTS    500

// Request timeout - NOT USED in async model (kept for reference/fallback)
#define REQUEST_TIMEOUT_MS      60000

// Circuit breaker - auto-permit after this many timeouts
// In async model this is rarely triggered - mainly for cleanup
#define CIRCUIT_BREAKER_THRESHOLD   100

// DNS cache settings
#define MAX_DNS_CACHE_ENTRIES   1000
#define DNS_CACHE_TTL_100NS     (5LL * 60 * 1000 * 10000)  // 5 minutes in 100ns units
#define DNS_MAX_DOMAIN_LENGTH   253

// Verdict cache for re-authorization (async pending model)
// When FwpsCompleteOperation0 triggers re-auth, we need to know what verdict to apply
// INCREASED: 1024 entries and 5 minutes to handle heavy browser load (100+ conn/sec)
// Modern browsers open many connections; VS Code, Teams, etc. are also chatty
#define MAX_VERDICT_CACHE_ENTRIES   1024
#define VERDICT_CACHE_TTL_100NS     (5LL * 60 * 1000 * 10000)  // 5 minutes in 100ns units

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

// DNS cache entry (internal) - maps IP addresses to domain names
typedef struct _DNS_CACHE_ENTRY {
    LIST_ENTRY      ListEntry;
    UINT64          Timestamp;          // When this entry was added
    BOOLEAN         IsIPv6;
    UINT32          IpV4;               // IPv4 address (network byte order)
    UINT8           IpV6[16];           // IPv6 address
    WCHAR           DomainName[256];    // Domain name (null-terminated)
    UINT32          DomainLength;       // Length in characters (excluding null)
} DNS_CACHE_ENTRY, *PDNS_CACHE_ENTRY;

// Verdict cache entry - for re-authorization after FwpsCompleteOperation0
// Key: (ProcessId, RemoteIP, RemotePort) -> Verdict
typedef struct _VERDICT_CACHE_ENTRY {
    UINT64          Timestamp;
    UINT32          ProcessId;
    BOOLEAN         IsIPv6;
    UINT32          RemoteIpV4;
    UINT8           RemoteIpV6[16];
    UINT16          RemotePort;
    SERENO_VERDICT  Verdict;
    BOOLEAN         InUse;
} VERDICT_CACHE_ENTRY, *PVERDICT_CACHE_ENTRY;

// Pending request structure (internal)
// ASYNC MODEL: Uses FwpsPendOperation0/FwpsCompleteOperation0 - NO kernel thread blocking
typedef struct _PENDING_REQUEST {
    LIST_ENTRY      ListEntry;
    UINT64          RequestId;
    UINT64          Timestamp;
    HANDLE          CompletionContext;  // From FwpsPendOperation0, used in FwpsCompleteOperation0
    SERENO_VERDICT  Verdict;            // Result from user-mode
    BOOLEAN         IsIPv6;
    BOOLEAN         SentToUserMode;     // TRUE once sent via GET_PENDING
    BOOLEAN         Completed;          // TRUE once verdict applied
    SERENO_CONNECTION_REQUEST ConnectionInfo;
} PENDING_REQUEST, *PPENDING_REQUEST;

// Driver context
typedef struct _SERENO_DEVICE_CONTEXT {
    WDFDEVICE       Device;
    HANDLE          EngineHandle;
    HANDLE          InjectionHandle;

    // Callout IDs - Connection filtering
    UINT32          ConnectCalloutIdV4;
    UINT32          ConnectCalloutIdV6;
    UINT32          RecvAcceptCalloutIdV4;
    UINT32          RecvAcceptCalloutIdV6;

    // Callout IDs - DNS interception
    UINT32          DnsCalloutIdV4;
    UINT32          DnsCalloutIdV6;

    // Filter IDs - Connection filtering
    UINT64          ConnectFilterIdV4;
    UINT64          ConnectFilterIdV6;
    UINT64          RecvAcceptFilterIdV4;
    UINT64          RecvAcceptFilterIdV6;

    // Filter IDs - DNS interception
    UINT64          DnsFilterIdV4;
    UINT64          DnsFilterIdV6;

    // Pending requests
    LIST_ENTRY      PendingList;
    KSPIN_LOCK      PendingLock;
    UINT32          PendingCount;
    UINT64          NextRequestId;

    // DNS cache - maps IP addresses to domain names
    LIST_ENTRY      DnsCacheList;
    KSPIN_LOCK      DnsCacheLock;
    UINT32          DnsCacheCount;

    // Verdict cache - for re-authorization after FwpsCompleteOperation0
    VERDICT_CACHE_ENTRY VerdictCache[MAX_VERDICT_CACHE_ENTRIES];
    KSPIN_LOCK      VerdictCacheLock;

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

// {53455245-4E4F-444E-5301-000000000001} DNS Callout V4
DEFINE_GUID(SERENO_CALLOUT_DNS_V4_GUID,
    0x53455245, 0x4E4F, 0x444E,
    0x53, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

// {53455245-4E4F-444E-5302-000000000001} DNS Callout V6
DEFINE_GUID(SERENO_CALLOUT_DNS_V6_GUID,
    0x53455245, 0x4E4F, 0x444E,
    0x53, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

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

// DNS cache management
VOID SerenoDnsCacheInit(_In_ PSERENO_DEVICE_CONTEXT Context);
VOID SerenoDnsCacheCleanup(_In_ PSERENO_DEVICE_CONTEXT Context);
VOID SerenoDnsCacheAdd(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ BOOLEAN IsIPv6, _In_ UINT32 IpV4, _In_opt_ const UINT8* IpV6, _In_ PCWSTR DomainName, _In_ UINT32 DomainLength);
BOOLEAN SerenoDnsCacheLookup(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ BOOLEAN IsIPv6, _In_ UINT32 IpV4, _In_opt_ const UINT8* IpV6, _Out_writes_(DomainBufferLength) PWCHAR DomainBuffer, _In_ UINT32 DomainBufferLength, _Out_ PUINT32 DomainLength);

// Verdict cache management (for async pending re-authorization)
VOID SerenoVerdictCacheAdd(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ UINT32 ProcessId, _In_ BOOLEAN IsIPv6, _In_ UINT32 RemoteIpV4, _In_opt_ const UINT8* RemoteIpV6, _In_ UINT16 RemotePort, _In_ SERENO_VERDICT Verdict);
BOOLEAN SerenoVerdictCacheLookup(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ UINT32 ProcessId, _In_ BOOLEAN IsIPv6, _In_ UINT32 RemoteIpV4, _In_opt_ const UINT8* RemoteIpV6, _In_ UINT16 RemotePort, _Out_ SERENO_VERDICT* Verdict);

// DNS packet classify function
VOID NTAPI SerenoClassifyDns(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER3* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
);

// DNS parsing helpers
VOID SerenoParseDnsResponse(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ const UINT8* DnsData, _In_ UINT32 DnsLength);

// Process info helpers
NTSTATUS SerenoGetProcessPath(_In_ HANDLE ProcessId, _Out_writes_(PathLength) PWCHAR Path, _In_ ULONG PathLength, _Out_ PULONG ActualLength);

#endif // SERENO_DRIVER_H
