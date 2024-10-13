#pragma once


#include <Windows.h>

// Define constants for system information class
#define SystemHandleInformation 16
#define ObjectTypeInformation 2
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth



typedef struct _FUNCTION_ADDRESSES {
    PVOID NtWaitForSingleObjectAddress;
    PVOID NtTestAlertAddress;
    PVOID MessageBoxAddress;
    PVOID ResumeThreadAddress;
} FUNCTION_ADDRESSES, * PFUNCTION_ADDRESSES;

typedef struct _CORE_ARGUMENTS {

    PBYTE myBase; 
    HANDLE sacDLLHandle;
    HANDLE malDLLHandle;
    SIZE_T viewSize; 

} CORE_ARGUMENTS, * PCORE_ARGUMENTS;

typedef NTSTATUS(NTAPI* NtQuerySystemInformationFunc)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );


typedef struct _OBJECT_TYPE_INFORMATION {
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    ULONG PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef enum _WORKERFACTORYINFOCLASS
{
    WorkerFactoryTimeout, // LARGE_INTEGER
    WorkerFactoryRetryTimeout, // LARGE_INTEGER
    WorkerFactoryIdleTimeout, // s: LARGE_INTEGER
    WorkerFactoryBindingCount, // s: ULONG
    WorkerFactoryThreadMinimum, // s: ULONG
    WorkerFactoryThreadMaximum, // s: ULONG
    WorkerFactoryPaused, // ULONG or BOOLEAN
    WorkerFactoryBasicInformation, // q: WORKER_FACTORY_BASIC_INFORMATION
    WorkerFactoryAdjustThreadGoal,
    WorkerFactoryCallbackType,
    WorkerFactoryStackInformation, // 10
    WorkerFactoryThreadBasePriority, // s: ULONG
    WorkerFactoryTimeoutWaiters, // s: ULONG, since THRESHOLD
    WorkerFactoryFlags, // s: ULONG
    WorkerFactoryThreadSoftMaximum, // s: ULONG
    WorkerFactoryThreadCpuSets, // since REDSTONE5
    MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, * PWORKERFACTORYINFOCLASS;

typedef struct _ALPC_WORK_ON_BEHALF_TICKET
{
    ULONG ThreadId;
    ULONG ThreadCreationTimeLow;
} ALPC_WORK_ON_BEHALF_TICKET, * PALPC_WORK_ON_BEHALF_TICKET;

typedef struct _TP_TASK_CALLBACKS
{
    void* ExecuteCallback;
    void* Unposted;
} TP_TASK_CALLBACKS, * PTP_TASK_CALLBACKS;


typedef struct _TP_TASK
{
    struct _TP_TASK_CALLBACKS* Callbacks;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char Padding_242[3];
    struct _LIST_ENTRY ListEntry;
} TP_TASK, * PTP_TASK;


typedef struct _TPP_REFCOUNT
{
    volatile INT32 Refcount;
} TPP_REFCOUNT, * PTPP_REFCOUNT;


typedef struct _TPP_CALLER
{
    void* ReturnAddress;
} TPP_CALLER, * PTPP_CALLER;


typedef struct _TPP_PH
{
    struct _TPP_PH_LINKS* Root;
} TPP_PH, * PTPP_PH;


typedef struct _TP_DIRECT
{
    struct _TP_TASK Task;
    UINT64 Lock;
    struct _LIST_ENTRY IoCompletionInformationList;
    void* Callback;
    UINT32 NumaNode;
    UINT8 IdealProcessor;
    char __PADDING__[3];
} TP_DIRECT, * PTP_DIRECT;


typedef struct _TPP_TIMER_SUBQUEUE
{
    INT64 Expiration;
    struct _TPP_PH WindowStart;
    struct _TPP_PH WindowEnd;
    void* Timer;
    void* TimerPkt;
    struct _TP_DIRECT Direct;
    UINT32 ExpirationWindow;
    INT32 __PADDING__[1];
} TPP_TIMER_SUBQUEUE, * PTPP_TIMER_SUBQUEUE;


typedef struct _TPP_TIMER_QUEUE
{
    struct _RTL_SRWLOCK Lock;
    struct _TPP_TIMER_SUBQUEUE AbsoluteQueue;
    struct _TPP_TIMER_SUBQUEUE RelativeQueue;
    INT32 AllocatedTimerCount;
    INT32 __PADDING__[1];
} TPP_TIMER_QUEUE, * PTPP_TIMER_QUEUE;


typedef struct _TPP_NUMA_NODE
{
    INT32 WorkerCount;
} TPP_NUMA_NODE, * PTPP_NUMA_NODE;


typedef union _TPP_POOL_QUEUE_STATE
{
    union
    {
        INT64 Exchange;
        struct
        {
            INT32 RunningThreadGoal : 16;
            UINT32 PendingReleaseCount : 16;
            UINT32 QueueLength;
        };
    };
} TPP_POOL_QUEUE_STATE, * PTPP_POOL_QUEUE_STATE;


typedef struct _TPP_QUEUE
{
    struct _LIST_ENTRY Queue;
    struct _RTL_SRWLOCK Lock;
} TPP_QUEUE, * PTPP_QUEUE;


typedef struct _FULL_TP_POOL
{
    struct _TPP_REFCOUNT Refcount;
    long Padding_239;
    union _TPP_POOL_QUEUE_STATE QueueState;
    struct _TPP_QUEUE* TaskQueue[3];
    struct _TPP_NUMA_NODE* NumaNode;
    struct _GROUP_AFFINITY* ProximityInfo;
    void* WorkerFactory;
    void* CompletionPort;
    struct _RTL_SRWLOCK Lock;
    struct _LIST_ENTRY PoolObjectList;
    struct _LIST_ENTRY WorkerList;
    struct _TPP_TIMER_QUEUE TimerQueue;
    struct _RTL_SRWLOCK ShutdownLock;
    UINT8 ShutdownInitiated;
    UINT8 Released;
    UINT16 PoolFlags;
    long Padding_240;
    struct _LIST_ENTRY PoolLinks;
    struct _TPP_CALLER AllocCaller;
    struct _TPP_CALLER ReleaseCaller;
    volatile INT32 AvailableWorkerCount;
    volatile INT32 LongRunningWorkerCount;
    UINT32 LastProcCount;
    volatile INT32 NodeStatus;
    volatile INT32 BindingCount;
    UINT32 CallbackChecksDisabled : 1;
    UINT32 TrimTarget : 11;
    UINT32 TrimmedThrdCount : 11;
    UINT32 SelectedCpuSetCount;
    long Padding_241;
    struct _RTL_CONDITION_VARIABLE TrimComplete;
    struct _LIST_ENTRY TrimmedWorkerList;
} FULL_TP_POOL, * PFULL_TP_POOL;

typedef union _TPP_WORK_STATE
{
    union
    {
        INT32 Exchange;
        UINT32 Insertable : 1;
        UINT32 PendingCallbackCount : 31;
    };
} TPP_WORK_STATE, * PTPP_WORK_STATE;


typedef struct _TPP_ITE_WAITER
{
    struct _TPP_ITE_WAITER* Next;
    void* ThreadId;
} TPP_ITE_WAITER, * PTPP_ITE_WAITER;

typedef struct _TPP_PH_LINKS
{
    struct _LIST_ENTRY Siblings;
    struct _LIST_ENTRY Children;
    INT64 Key;
} TPP_PH_LINKS, * PTPP_PH_LINKS;


typedef struct _TPP_ITE
{
    struct _TPP_ITE_WAITER* First;
} TPP_ITE, * PTPP_ITE;


typedef union _TPP_FLAGS_COUNT
{
    union
    {
        UINT64 Count : 60;
        UINT64 Flags : 4;
        INT64 Data;
    };
} TPP_FLAGS_COUNT, * PTPP_FLAGS_COUNT;


typedef struct _TPP_BARRIER
{
    volatile union _TPP_FLAGS_COUNT Ptr;
    struct _RTL_SRWLOCK WaitLock;
    struct _TPP_ITE WaitList;
} TPP_BARRIER, * PTPP_BARRIER;


typedef struct _TP_CLEANUP_GROUP
{
    struct _TPP_REFCOUNT Refcount;
    INT32 Released;
    struct _RTL_SRWLOCK MemberLock;
    struct _LIST_ENTRY MemberList;
    struct _TPP_BARRIER Barrier;
    struct _RTL_SRWLOCK CleanupLock;
    struct _LIST_ENTRY CleanupList;
} TP_CLEANUP_GROUP, * PTP_CLEANUP_GROUP;


typedef struct _TPP_CLEANUP_GROUP_MEMBER
{
    struct _TPP_REFCOUNT Refcount;
    long Padding_233;
    const struct _TPP_CLEANUP_GROUP_MEMBER_VFUNCS* VFuncs;
    struct _TP_CLEANUP_GROUP* CleanupGroup;
    void* CleanupGroupCancelCallback;
    void* FinalizationCallback;
    struct _LIST_ENTRY CleanupGroupMemberLinks;
    struct _TPP_BARRIER CallbackBarrier;
    union
    {
        void* Callback;
        void* WorkCallback;
        void* SimpleCallback;
        void* TimerCallback;
        void* WaitCallback;
        void* IoCallback;
        void* AlpcCallback;
        void* AlpcCallbackEx;
        void* JobCallback;
    };
    void* Context;
    struct _ACTIVATION_CONTEXT* ActivationContext;
    void* SubProcessTag;
    struct _GUID ActivityId;
    struct _ALPC_WORK_ON_BEHALF_TICKET WorkOnBehalfTicket;
    void* RaceDll;
    FULL_TP_POOL* Pool;
    struct _LIST_ENTRY PoolObjectLinks;
    union
    {
        volatile INT32 Flags;
        UINT32 LongFunction : 1;
        UINT32 Persistent : 1;
        UINT32 UnusedPublic : 14;
        UINT32 Released : 1;
        UINT32 CleanupGroupReleased : 1;
        UINT32 InCleanupGroupCleanupList : 1;
        UINT32 UnusedPrivate : 13;
    };
    long Padding_234;
    struct _TPP_CALLER AllocCaller;
    struct _TPP_CALLER ReleaseCaller;
    enum _TP_CALLBACK_PRIORITY CallbackPriority;
    INT32 __PADDING__[1];
} TPP_CLEANUP_GROUP_MEMBER, * PTPP_CLEANUP_GROUP_MEMBER;


typedef struct _FULL_TP_WORK
{
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    struct _TP_TASK Task;
    volatile union _TPP_WORK_STATE WorkState;
    INT32 __PADDING__[1];
} FULL_TP_WORK, * PFULL_TP_WORK;


typedef struct _FULL_TP_TIMER
{
    struct _FULL_TP_WORK Work;
    struct _RTL_SRWLOCK Lock;
    union
    {
        struct _TPP_PH_LINKS WindowEndLinks;
        struct _LIST_ENTRY ExpirationLinks;
    };
    struct _TPP_PH_LINKS WindowStartLinks;
    INT64 DueTime;
    struct _TPP_ITE Ite;
    UINT32 Window;
    UINT32 Period;
    UINT8 Inserted;
    UINT8 WaitTimer;
    union
    {
        UINT8 TimerStatus;
        UINT8 InQueue : 1;
        UINT8 Absolute : 1;
        UINT8 Cancelled : 1;
    };
    UINT8 BlockInsert;
    INT32 __PADDING__[1];
} FULL_TP_TIMER
, * PFULL_TP_TIMER;


typedef struct _FULL_TP_WAIT
{
    struct _FULL_TP_TIMER Timer;
    void* Handle;
    void* WaitPkt;
    void* NextWaitHandle;
    union _LARGE_INTEGER NextWaitTimeout;
    struct _TP_DIRECT Direct;
    union
    {
        union
        {
            UINT8 AllFlags;
            UINT8 NextWaitActive : 1;
            UINT8 NextTimeoutActive : 1;
            UINT8 CallbackCounted : 1;
            UINT8 Spare : 5;
        };
    } WaitFlags;
    char __PADDING__[7];
} FULL_TP_WAIT, * PFULL_TP_WAIT;


typedef struct _FULL_TP_IO
{
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    struct _TP_DIRECT Direct;
    void* File;
    volatile INT32 PendingIrpCount;
    INT32 __PADDING__[1];
} FULL_TP_IO, * PFULL_TP_IO;


typedef struct _FULL_TP_ALPC
{
    struct _TP_DIRECT Direct;
    struct _TPP_CLEANUP_GROUP_MEMBER CleanupGroupMember;
    void* AlpcPort;
    INT32 DeferredSendCount;
    INT32 LastConcurrencyCount;
    union
    {
        UINT32 Flags;
        UINT32 ExTypeCallback : 1;
        UINT32 CompletionListRegistered : 1;
        UINT32 Reserved : 30;
    };
    INT32 __PADDING__[1];
} FULL_TP_ALPC, * PFULL_TP_ALPC;


typedef struct _WORKER_FACTORY_BASIC_INFORMATION
{
    LARGE_INTEGER Timeout;
    LARGE_INTEGER RetryTimeout;
    LARGE_INTEGER IdleTimeout;
    BOOLEAN Paused;
    BOOLEAN TimerSet;
    BOOLEAN QueuedToExWorker;
    BOOLEAN MayCreate;
    BOOLEAN CreateInProgress;
    BOOLEAN InsertedIntoQueue;
    BOOLEAN Shutdown;
    ULONG BindingCount;
    ULONG ThreadMinimum;
    ULONG ThreadMaximum;
    ULONG PendingWorkerCount;
    ULONG WaitingWorkerCount;
    ULONG TotalWorkerCount;
    ULONG ReleaseCount;
    LONGLONG InfiniteWaitGoal;
    PVOID StartRoutine;
    PVOID StartParameter;
    HANDLE ProcessId;
    SIZE_T StackReserve;
    SIZE_T StackCommit;
    NTSTATUS LastThreadCreationStatus;
} WORKER_FACTORY_BASIC_INFORMATION, * PWORKER_FACTORY_BASIC_INFORMATION;


typedef NTSTATUS(NTAPI* NtQueryObjectFunc)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* NtQueryInformationWorkerFactoryFunc)(
    _In_ HANDLE WorkerFactoryHandle,
    _In_ WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    _Out_writes_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
    _In_ ULONG WorkerFactoryInformationLength,
    _Out_opt_ PULONG ReturnLength
    );




typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
    );

typedef VOID(NTAPI* PPS_APC_ROUTINE)(
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef enum _EVENT_TYPE
{
    NotificationEvent,
    SynchronizationEvent
} EVENT_TYPE;

typedef PVOID PACTIVATION_CONTEXT;

typedef struct _BASE_RELOCATION_ENTRY {
    WORD	Offset : 12;  // Specifies where the base relocation is to be applied.
    WORD	Type : 4;   // Indicates the type of base relocation to be applied.
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct {
    DWORD	Length;
    DWORD	MaximumLength;
    PVOID	Buffer;
} USTRING;

typedef struct _API_SET_NAMESPACE {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;

typedef struct _API_SET_HASH_ENTRY {
    ULONG Hash;
    ULONG Index;
} API_SET_HASH_ENTRY, * PAPI_SET_HASH_ENTRY;

typedef struct _API_SET_NAMESPACE_ENTRY {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG HashedLength;
    ULONG ValueOffset;
    ULONG ValueCount;
} API_SET_NAMESPACE_ENTRY, * PAPI_SET_NAMESPACE_ENTRY;

typedef struct _API_SET_VALUE_ENTRY {
    ULONG Flags;
    ULONG NameOffset;
    ULONG NameLength;
    ULONG ValueOffset;
    ULONG ValueLength;
} API_SET_VALUE_ENTRY, * PAPI_SET_VALUE_ENTRY;

// https://www.nirsoft.net/kernel_struct/vista/PEB_LDR_DATA.html

typedef struct _PEBC_LDR_DATA {
    ULONG                   Length;
    ULONG                   Initialized;
    PVOID                   SsHandle;
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
} PEBC_LDR_DATA, * PPEBC_LDR_DATA;

typedef struct _DLL_HEADER {
    DWORD header; //4 bytes header
    DWORD key; //4 bytes encryption key
    SIZE_T funcSize; //8 bytes

} DLL_HEADER, * PDLL_HEADER;

typedef struct _SYSCALL_ENTRY {

    FARPROC funcAddr;
    PBYTE sysretAddr;
    int SSN;

} SYSCALL_ENTRY, * PSYSCALL_ENTRY;

// https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html

typedef struct _LDR_DATA_TABLE_ENTRYC {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PACTIVATION_CONTEXT EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRYC, * PLDR_DATA_TABLE_ENTRYC;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

typedef struct _PEBC
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        };
    };

    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PSLIST_HEADER AtlThunkSListPtr;
    PVOID IFEOKey;

    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ProcessImagesHotPatched : 1; // REDSTONE5
            ULONG ReservedBits0 : 24;
        };
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved;
    ULONG AtlThunkSListPtr32;
    PAPI_SET_NAMESPACE ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];

    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData; // HotpatchInformation
    PVOID* ReadOnlyStaticServerData;

    PVOID AnsiCodePageData; // PCPTABLEINFO
    PVOID OemCodePageData; // PCPTABLEINFO
    PVOID UnicodeCaseTableData; // PNLSTABLEINFO

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    ULARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps; // PHEAP

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    KAFFINITY ActiveProcessAffinityMask;
    ULONG GdiHandleBuffer[60];
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
    PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

    SIZE_T MinimumStackCommit;

    PVOID SparePointers[2]; // 19H1 (previously FlsCallback to FlsHighIndex)
    PVOID PatchLoaderData;
    PVOID ChpeV2ProcessInfo; // _CHPEV2_PROCESS_INFO

    ULONG AppModelFeatureState;
    ULONG SpareUlongs[2];

    USHORT ActiveCodePage;
    USHORT OemCodePage;
    USHORT UseCaseMapping;
    USHORT UnusedNlsField;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;

    union
    {
        PVOID pContextData; // WIN7
        PVOID pUnused; // WIN10
        PVOID EcCodeBitMap; // WIN11
    };

    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        };
    };
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    PRTL_CRITICAL_SECTION TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID WaitOnAddressHashTable[128];
    PVOID TelemetryCoverageHeader; // REDSTONE3
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags; // REDSTONE4
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    struct _LEAP_SECOND_DATA* LeapSecondData; // REDSTONE5
    union
    {
        ULONG LeapSecondFlags;
        struct
        {
            ULONG SixtySecondEnabled : 1;
            ULONG Reserved : 31;
        };
    };
    ULONG NtGlobalFlag2;
    ULONGLONG ExtendedFeatureDisableMask; // since WIN11
} PEBC, * PPEBC;


typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
    VmPrefetchInformation,
    VmPagePriorityInformation,
    VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation, // UNICODE_STRING
    MemoryRegionInformation, // MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
    MemorySharedCommitInformation // MEMORY_SHARED_COMMIT_INFORMATION
} MEMORY_INFORMATION_CLASS;

typedef enum _INDIRECT_SYSCALL_FUNC
{
    ZwAllocateVirtualMemoryF,
    ZwProtectVirtualMemoryF,
    ZwFlushInstructionCacheF,
    ZwCreateSectionF,
    ZwMapViewOfSectionF,
    ZwUnmapViewOfSectionF,
    ZwQuerySystemInformationF,
    ZwQueryObjectF,
    ZwQueryVirtualMemoryF,
    ZwFreeVirtualMemoryF,
    ZwSetContextThreadF,
    ZwGetContextThreadF,
    AmountofSyscalls

} INDIRECT_SYSCALL_FUNC;

typedef struct _VM_INFORMATION
{
    DWORD                    dwNumberOfOffsets;
    PULONG                    plOutput;
    PCFG_CALL_TARGET_INFO    ptOffsets;
    PVOID                    pMustBeZero;
    PVOID                    pMoarZero;
} VM_INFORMATION, * PVM_INFORMATION;

typedef struct _MEMORY_RANGE_ENTRY
{
    PVOID  VirtualAddress;
    SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, * PMEMORY_RANGE_ENTRY;



typedef NTSTATUS(NTAPI* NtSetContextThreadFunc)(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
    );

typedef NTSTATUS(NTAPI* NtResumeThreadFunc)(
    HANDLE ThreadHandle,
    PULONG SuspendCount
    );

typedef NTSTATUS(NTAPI* NtQuerySystemInformationFunc)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* NtCreateEventFunc)(
    _Out_ PHANDLE EventHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ EVENT_TYPE EventType,
    _In_ BOOLEAN InitialState
    );

typedef NTSTATUS(NTAPI* NtCreateThreadExFunc)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
    );

typedef NTSTATUS(NTAPI* NtGetContextThreadFunc)(
    _In_ HANDLE ThreadHandle,
    _Inout_ PCONTEXT ThreadContext
    );

typedef NTSTATUS(NTAPI* NtWaitForSingleObjectFunc)(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

typedef NTSTATUS(NTAPI* NtQueueApcThreadFunc)(
    _In_ HANDLE ThreadHandle,
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );

typedef NTSTATUS(NTAPI* NtAlertResumeThreadFunc)(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG PreviousSuspendCount
    );

typedef UINT(CALLBACK* fnMessageBoxA)(
    HWND   hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT   uType
    );

typedef HMODULE(WINAPI* fnLoadLibraryExA)(
    LPCSTR lpLibFileName,
    HANDLE hFile,
    DWORD  dwFlags
    );

typedef HMODULE(WINAPI* fnLoadLibraryA)(
    LPCSTR lpLibFileName
    );

typedef HMODULE(WINAPI* fnLoadLibraryW)(
    LPCWSTR lpLibFileName
    );

typedef BOOL(WINAPI* fnVirtualProtect)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    PDWORD  flProtect
    );


typedef BOOL(WINAPI* fnRtlAddFunctionTable)(
    PRUNTIME_FUNCTION FunctionTable,
    DWORD             EntryCount,
    DWORD64           BaseAddress
    );

typedef BOOL(WINAPI* fnDllMain)(
    HINSTANCE,
    DWORD,
    LPVOID
    );

typedef BOOL(WINAPI* fnVirtualFree)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  dwFreeType
    );

typedef BOOL(WINAPI* fnCloseHandle)(

    HANDLE hObject
    );

typedef HANDLE(WINAPI* fnCreateTimerQueue)(

    );

typedef BOOL(WINAPI* fnCreateTimerQueueTimer)(

    OUT PHANDLE phNewTimer,
    IN HANDLE TimerQueue,
    IN WAITORTIMERCALLBACK Callback,
    IN PVOID Parameter,
    IN DWORD DueTime,
    IN DWORD Period,
    IN ULONG Flags
    );

typedef HANDLE(WINAPI* fnCreateEventW)(
    IN LPSECURITY_ATTRIBUTES lpEventAttributes,
    IN BOOL bManualResest,
    IN BOOL bInitialState,
    IN LPCWSTR lpName

    );

typedef DWORD(WINAPI* fnWaitForSingleObject)(
    HANDLE hHandle,
    DWORD dwMilliseconds
    );

typedef DWORD(WINAPI* fnGetProcessId)(
    IN HANDLE Process
    );

typedef BOOL(WINAPI* fnSetProcessValidCallTargets)(
    HANDLE hProcess,
    PVOID VirtualAddress,
    SIZE_T RegionSize,
    ULONG NumberOfOffsets,
    OUT PCFG_CALL_TARGET_INFO OffsetInformation
    );

typedef NTSTATUS(NTAPI* NtSetInformationVirtualMemory)(
    HANDLE								hProcess,
    ULONG	VmInformationClass,
    ULONG_PTR							NumberOfEntries,
    PMEMORY_RANGE_ENTRY					VirtualAddresses,
    PVOID								VmInformation,
    ULONG								VmInformationLength
    );

typedef DWORD(WINAPI* fnGetMappedFileNameA)(
    HANDLE hProcess,
    LPVOID lpv,
    LPSTR  lpFilename,
    DWORD  nSize
    );

typedef PVOID(WINAPI* fnAddVectoredExceptionHanlder)(
    ULONG First,
    PVECTORED_EXCEPTION_HANDLER Handler
    );

typedef ULONG(WINAPI* fnRemoveVectoredExceptionHandler)(
    PVOID Handle
    );


typedef struct _NT_FUNCTIONS
{
    NtWaitForSingleObjectFunc NtWaitForSingleObject;
    NtQueueApcThreadFunc NtQueueApcThread;
    NtGetContextThreadFunc NtGetContextThread;
    NtSetContextThreadFunc NtSetContextThread;
    NtCreateThreadExFunc NtCreateThreadEx; // Added
    NtCreateEventFunc NtCreateEvent;
    NtResumeThreadFunc NtResumeThread; // Added
} NT_FUNCTIONS, * PNT_FUNCTIONS;