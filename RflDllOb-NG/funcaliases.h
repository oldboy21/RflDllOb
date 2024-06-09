#pragma once

#include <Windows.h>
#include "headers.h"

/*----------------FUNCTION ALIASES----------------------*/


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

typedef NTSTATUS(NTAPI* _NtSetInformationVirtualMemory)(
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

