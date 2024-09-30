#pragma once

#include <Windows.h>
#include "headers.h"

/*----------------FUNCTION ALIASES----------------------*/

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


typedef HANDLE(WINAPI* fnCreateFileA)(
    LPCSTR lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    );

typedef BOOL(WINAPI* fnWriteFile)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
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

