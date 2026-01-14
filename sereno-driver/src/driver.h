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
#include <ntstrsafe.h>
#include <stdarg.h>

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
#define IOCTL_SERENO_GET_SNI        CTL_CODE(FILE_DEVICE_SERENO, 0x807, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_SERENO_ADD_BLOCKED_DOMAIN CTL_CODE(FILE_DEVICE_SERENO, 0x808, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_SERENO_CLEAR_BLOCKED_DOMAINS CTL_CODE(FILE_DEVICE_SERENO, 0x809, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_SERENO_GET_BANDWIDTH      CTL_CODE(FILE_DEVICE_SERENO, 0x80A, METHOD_BUFFERED, FILE_READ_ACCESS)

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

// Block reason - indicates WHY and at WHICH LAYER a connection was blocked
typedef enum _SERENO_BLOCK_REASON {
    BLOCK_REASON_NONE = 0,

    // ALE Layer blocks (pre-connection, immediate)
    BLOCK_REASON_PROCESS = 1,       // Process/app is blocked
    BLOCK_REASON_IP = 2,            // IP address is blocked
    BLOCK_REASON_PORT = 3,          // Port is blocked
    BLOCK_REASON_DOMAIN_DNS = 4,    // Domain blocked (via DNS cache → IP lookup)

    // Stream Layer blocks (post-handshake, ~50-100ms)
    BLOCK_REASON_SNI = 5,           // Domain blocked (via TLS SNI inspection)

    // TLM Layer blocks (during transfer) - FUTURE
    BLOCK_REASON_BANDWIDTH = 6,     // Exceeded bandwidth limit
    BLOCK_REASON_PATTERN = 7,       // Matched packet pattern

    // Rule/User blocks
    BLOCK_REASON_RULE = 10,         // Explicit rule match
    BLOCK_REASON_USER = 11,         // User clicked Block in TUI
} SERENO_BLOCK_REASON;

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

// SNI notification - sent to usermode when SNI is extracted from TLS ClientHello
// Allows TUI to update display with real domain name after connection is established
typedef struct _SERENO_SNI_NOTIFICATION {
    UINT64      Timestamp;
    UINT32      ProcessId;          // Process that made the connection
    UINT8       IpVersion;          // 4 or 6
    UINT8       Reserved[3];
    UINT32      RemoteAddressV4;    // Remote IP (for matching)
    UINT8       RemoteAddressV6[16];
    UINT16      LocalPort;          // Local port (for matching)
    UINT16      RemotePort;         // Remote port (for matching)
    WCHAR       DomainName[256];    // Extracted SNI domain
    UINT32      DomainNameLength;   // Length in characters
} SERENO_SNI_NOTIFICATION, *PSERENO_SNI_NOTIFICATION;

// Blocked domain request - sent from usermode to add domain to blocklist
typedef struct _SERENO_BLOCKED_DOMAIN_REQUEST {
    WCHAR       DomainName[256];    // Domain pattern to block (e.g., "facebook.com")
    UINT32      DomainNameLength;   // Length in characters
} SERENO_BLOCKED_DOMAIN_REQUEST, *PSERENO_BLOCKED_DOMAIN_REQUEST;

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

// SNI cache settings - stores domain extracted from TLS ClientHello
// Key: connection 5-tuple (LocalIP, LocalPort, RemoteIP, RemotePort, IsIPv6)
// Value: Domain name from SNI extension
#define MAX_SNI_CACHE_ENTRIES   512
#define SNI_CACHE_TTL_100NS     (60LL * 1000 * 10000)  // 60 seconds in 100ns units

// SNI notification queue - ring buffer for notifying usermode of extracted SNI
#define MAX_SNI_NOTIFICATIONS   64

// Blocked domain list - domains that should be blocked at Stream layer
// Populated from usermode rules, checked when SNI is extracted
#define MAX_BLOCKED_DOMAINS     256

// SNI cache entry - maps connection 5-tuple to domain from TLS ClientHello
typedef struct _SNI_CACHE_ENTRY {
    UINT64          Timestamp;
    UINT32          LocalAddressV4;
    UINT32          RemoteAddressV4;
    UINT8           LocalAddressV6[16];
    UINT8           RemoteAddressV6[16];
    UINT16          LocalPort;
    UINT16          RemotePort;
    BOOLEAN         IsIPv6;
    BOOLEAN         InUse;
    WCHAR           DomainName[256];
    UINT32          DomainLength;
} SNI_CACHE_ENTRY, *PSNI_CACHE_ENTRY;

// Blocked domain entry - for SNI-based blocking at Stream layer
// Simple substring matching: if SNI contains this domain, block it
typedef struct _BLOCKED_DOMAIN_ENTRY {
    BOOLEAN         InUse;
    WCHAR           DomainName[256];    // Domain pattern to block (e.g., "facebook.com")
    UINT32          DomainLength;       // Length in characters
} BLOCKED_DOMAIN_ENTRY, *PBLOCKED_DOMAIN_ENTRY;

// ============================================================================
// TLM (Transport Layer Module) - Bandwidth Statistics
// ============================================================================

// Bandwidth cache settings - tracks bytes sent/received per connection flow
// Key: FlowHandle (assigned by WFP at ALE layer)
// Updated by: OUTBOUND_TRANSPORT and INBOUND_TRANSPORT callouts
#define MAX_BANDWIDTH_ENTRIES       1024
#define BANDWIDTH_ENTRY_TTL_100NS   (10LL * 60 * 1000 * 10000)  // 10 minutes in 100ns units

// Bandwidth entry - tracks traffic statistics for a single connection flow
typedef struct _SERENO_BANDWIDTH_ENTRY {
    UINT64          FlowHandle;         // WFP flow identifier (from InMetaValues->flowHandle)
    UINT64          BytesSent;          // Total bytes sent (outbound)
    UINT64          BytesReceived;      // Total bytes received (inbound)
    UINT64          StartTime;          // When connection started (100ns units)
    UINT64          LastActivity;       // Last packet timestamp (100ns units)
    UINT64          Timestamp;          // For TTL expiration and LRU eviction (100ns units)
    UINT32          ProcessId;          // Process that owns this flow
    UINT16          LocalPort;          // Local port (for matching to connections)
    UINT16          RemotePort;         // Remote port (for matching to connections)
    UINT32          LocalAddressV4;     // Local IP (for matching)
    UINT32          RemoteAddressV4;    // Remote IP (for matching)
    BOOLEAN         IsIPv6;             // TRUE if IPv6 connection
    BOOLEAN         InUse;              // Slot is active
} SERENO_BANDWIDTH_ENTRY, *PSERENO_BANDWIDTH_ENTRY;

// Bandwidth stats response - returned via IOCTL_SERENO_GET_BANDWIDTH
// Contains a batch of bandwidth entries for usermode polling
#define BANDWIDTH_BATCH_SIZE    64

typedef struct _SERENO_BANDWIDTH_STATS {
    UINT32          TotalEntries;       // Total active entries in cache
    UINT32          ReturnedCount;      // Number of entries in this batch
    UINT32          StartIndex;         // For pagination (future)
    UINT32          Reserved;
    SERENO_BANDWIDTH_ENTRY Entries[BANDWIDTH_BATCH_SIZE];
} SERENO_BANDWIDTH_STATS, *PSERENO_BANDWIDTH_STATS;

// Verdict cache entry - for re-authorization after FwpsCompleteOperation0
// Key: (ProcessId, RemotePort, DomainName) -> Verdict
// UPDATED: Now includes domain name to allow different verdicts for different domains
// on the same port (e.g., allow google.com:443, block evil.com:443)
// Fallback: If domain is empty, matches by (ProcessId, RemotePort) only for backwards compatibility
typedef struct _VERDICT_CACHE_ENTRY {
    UINT64          Timestamp;
    UINT32          ProcessId;
    UINT16          RemotePort;
    WCHAR           DomainName[256];    // Domain from SNI or DNS cache
    UINT32          DomainLength;       // 0 = no domain (match by port only)
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

    // Callout IDs - Stream inspection (SNI extraction)
    UINT32          StreamCalloutIdV4;
    UINT32          StreamCalloutIdV6;

    // Callout IDs - TLM (Transport Layer Module - Bandwidth)
    UINT32          TransportOutCalloutIdV4;
    UINT32          TransportOutCalloutIdV6;
    UINT32          TransportInCalloutIdV4;
    UINT32          TransportInCalloutIdV6;

    // Filter IDs - Connection filtering
    UINT64          ConnectFilterIdV4;
    UINT64          ConnectFilterIdV6;
    UINT64          RecvAcceptFilterIdV4;
    UINT64          RecvAcceptFilterIdV6;

    // Filter IDs - DNS interception
    UINT64          DnsFilterIdV4;
    UINT64          DnsFilterIdV6;

    // Filter IDs - Stream inspection (SNI extraction)
    UINT64          StreamFilterIdV4;
    UINT64          StreamFilterIdV6;

    // Filter IDs - TLM (Transport Layer Module - Bandwidth)
    UINT64          TransportOutFilterIdV4;
    UINT64          TransportOutFilterIdV6;
    UINT64          TransportInFilterIdV4;
    UINT64          TransportInFilterIdV6;

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

    // SNI cache - maps connection 5-tuple to domain from TLS ClientHello
    SNI_CACHE_ENTRY SniCache[MAX_SNI_CACHE_ENTRIES];
    KSPIN_LOCK      SniCacheLock;

    // SNI notification queue - ring buffer for sending SNI to usermode
    SERENO_SNI_NOTIFICATION SniNotifications[MAX_SNI_NOTIFICATIONS];
    UINT32          SniNotifyHead;      // Next slot to write
    UINT32          SniNotifyTail;      // Next slot to read
    KSPIN_LOCK      SniNotifyLock;

    // Blocked domain list - for SNI-based blocking at Stream layer
    BLOCKED_DOMAIN_ENTRY BlockedDomains[MAX_BLOCKED_DOMAINS];
    UINT32          BlockedDomainCount;
    KSPIN_LOCK      BlockedDomainLock;

    // TLM Bandwidth cache - tracks bytes sent/received per connection flow
    SERENO_BANDWIDTH_ENTRY BandwidthCache[MAX_BANDWIDTH_ENTRIES];
    KSPIN_LOCK      BandwidthCacheLock;
    UINT32          BandwidthCacheCount;    // Number of active entries

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

// {53455245-4E4F-5354-5201-000000000001} Stream Callout V4 (SNI Inspection)
// "STRE" = 0x53545245, but using pattern {SERE-NO-ST-R1/R2}
DEFINE_GUID(SERENO_CALLOUT_STREAM_V4_GUID,
    0x53455245, 0x4E4F, 0x5354,
    0x52, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

// {53455245-4E4F-5354-5202-000000000001} Stream Callout V6 (SNI Inspection)
DEFINE_GUID(SERENO_CALLOUT_STREAM_V6_GUID,
    0x53455245, 0x4E4F, 0x5354,
    0x52, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

// ============================================================================
// TLM (Transport Layer Module) GUIDs - Bandwidth Statistics
// ============================================================================

// {53455245-4E4F-544C-4D01-000000000001} Transport Outbound V4
DEFINE_GUID(SERENO_CALLOUT_TRANSPORT_OUT_V4_GUID,
    0x53455245, 0x4E4F, 0x544C,
    0x4D, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

// {53455245-4E4F-544C-4D02-000000000001} Transport Outbound V6
DEFINE_GUID(SERENO_CALLOUT_TRANSPORT_OUT_V6_GUID,
    0x53455245, 0x4E4F, 0x544C,
    0x4D, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

// {53455245-4E4F-544C-4D03-000000000001} Transport Inbound V4
DEFINE_GUID(SERENO_CALLOUT_TRANSPORT_IN_V4_GUID,
    0x53455245, 0x4E4F, 0x544C,
    0x4D, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

// {53455245-4E4F-544C-4D04-000000000001} Transport Inbound V6
DEFINE_GUID(SERENO_CALLOUT_TRANSPORT_IN_V6_GUID,
    0x53455245, 0x4E4F, 0x544C,
    0x4D, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01);

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
// UPDATED: Now includes domain name for domain-aware verdict caching
VOID SerenoVerdictCacheAdd(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ UINT32 ProcessId, _In_ BOOLEAN IsIPv6, _In_ UINT32 RemoteIpV4, _In_opt_ const UINT8* RemoteIpV6, _In_ UINT16 RemotePort, _In_opt_ PCWSTR DomainName, _In_ UINT32 DomainLength, _In_ SERENO_VERDICT Verdict);
BOOLEAN SerenoVerdictCacheLookup(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ UINT32 ProcessId, _In_ BOOLEAN IsIPv6, _In_ UINT32 RemoteIpV4, _In_opt_ const UINT8* RemoteIpV6, _In_ UINT16 RemotePort, _In_opt_ PCWSTR DomainName, _In_ UINT32 DomainLength, _Out_ SERENO_VERDICT* Verdict);
BOOLEAN SerenoVerdictCacheLookupByAddress(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ BOOLEAN IsIPv6, _In_ UINT32 RemoteIpV4, _In_opt_ const UINT8* RemoteIpV6, _In_ UINT16 RemotePort, _Out_ SERENO_VERDICT* Verdict);

// SNI cache management (stores domain from TLS ClientHello)
VOID SerenoSniCacheAdd(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ BOOLEAN IsIPv6, _In_ UINT32 LocalIpV4, _In_opt_ const UINT8* LocalIpV6, _In_ UINT16 LocalPort, _In_ UINT32 RemoteIpV4, _In_opt_ const UINT8* RemoteIpV6, _In_ UINT16 RemotePort, _In_ PCWSTR DomainName, _In_ UINT32 DomainLength);
BOOLEAN SerenoSniCacheLookup(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ BOOLEAN IsIPv6, _In_ UINT32 LocalIpV4, _In_opt_ const UINT8* LocalIpV6, _In_ UINT16 LocalPort, _In_ UINT32 RemoteIpV4, _In_opt_ const UINT8* RemoteIpV6, _In_ UINT16 RemotePort, _Out_writes_(DomainBufferLength) PWCHAR DomainBuffer, _In_ UINT32 DomainBufferLength, _Out_ PUINT32 DomainLength);

// SNI notification queue - notify usermode about extracted SNI
VOID SerenoSniNotifyAdd(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ BOOLEAN IsIPv6, _In_ UINT32 RemoteIpV4, _In_opt_ const UINT8* RemoteIpV6, _In_ UINT16 LocalPort, _In_ UINT16 RemotePort, _In_ PCWSTR DomainName, _In_ UINT32 DomainLength);
BOOLEAN SerenoSniNotifyGet(_In_ PSERENO_DEVICE_CONTEXT Context, _Out_ PSERENO_SNI_NOTIFICATION Notification);

// Blocked domain management - for SNI-based blocking at Stream layer
BOOLEAN SerenoBlockedDomainAdd(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ PCWSTR DomainName, _In_ UINT32 DomainLength);
VOID SerenoBlockedDomainClear(_In_ PSERENO_DEVICE_CONTEXT Context);
BOOLEAN SerenoBlockedDomainCheck(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ PCWSTR DomainName, _In_ UINT32 DomainLength);

// TLS ClientHello parsing for SNI extraction
BOOLEAN SerenoParseTlsClientHello(_In_ const UINT8* Data, _In_ UINT32 DataLength, _Out_writes_(DomainBufferLength) PWCHAR DomainBuffer, _In_ UINT32 DomainBufferLength, _Out_ PUINT32 DomainLength);

// Stream layer classify function (SNI extraction from TLS ClientHello)
VOID NTAPI SerenoClassifyStream(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER3* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
);

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

// ============================================================================
// TLM (Transport Layer Module) - Bandwidth Statistics
// ============================================================================

// TLM Outbound classify function - counts bytes sent per connection
VOID NTAPI SerenoClassifyTransportOutbound(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER3* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
);

// TLM Inbound classify function - counts bytes received per connection
VOID NTAPI SerenoClassifyTransportInbound(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER3* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
);

// Bandwidth cache management
VOID SerenoBandwidthCacheInit(_In_ PSERENO_DEVICE_CONTEXT Context);
VOID SerenoBandwidthAdd(
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
);
VOID SerenoBandwidthGetStats(_In_ PSERENO_DEVICE_CONTEXT Context, _Out_ PSERENO_BANDWIDTH_STATS Stats);

// DNS parsing helpers
VOID SerenoParseDnsResponse(_In_ PSERENO_DEVICE_CONTEXT Context, _In_ const UINT8* DnsData, _In_ UINT32 DnsLength);

// Process info helpers
NTSTATUS SerenoGetProcessPath(_In_ HANDLE ProcessId, _Out_writes_(PathLength) PWCHAR Path, _In_ ULONG PathLength, _Out_ PULONG ActualLength);

#endif // SERENO_DRIVER_H
