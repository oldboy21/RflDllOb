#pragma once

#include <Windows.h>
#include "headers.h"
#include "misc.h"

EXTERN_C NTSTATUS ZwAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect,
    IN DWORD ssn,
    IN PBYTE syscallret);

EXTERN_C NTSTATUS ZwProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect,
    IN DWORD ssn,
    IN PBYTE syscallret);

EXTERN_C NTSTATUS ZwFlushInstructionCache(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN ULONG NumberOfBytesToFlush,
    IN DWORD ssn,
    IN PBYTE syscallret);

EXTERN_C NTSTATUS ZwCreateSection(
    OUT PHANDLE	SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN PLARGE_INTEGER MaximumSize,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN  HANDLE FileHandle,
    IN DWORD ssn, //8
    IN PBYTE syscallret //9
);

EXTERN_C NTSTATUS ZwMapViewOfSection(

    IN HANDLE SectionHandle,
    IN HANDLE ProcessHandle,
    IN OUT	PVOID* BaseAddress,
    IN SIZE_T ZeroBits,
    IN SIZE_T CommitSize,
    IN OUT	PLARGE_INTEGER	SectionOffset,
    IN OUT	PSIZE_T	ViewSize,
    IN SECTION_INHERIT InheritDisposition,
    IN ULONG AllocationType,
    IN ULONG Protect,
    IN DWORD ssn, //11
    IN PBYTE syscallret //12
);

EXTERN_C NTSTATUS ZwUnmapViewOfSection(
    IN HANDLE ProcessHandle, //RCX
    IN PVOID BaseAddress, //RDX
    IN DWORD ssn, //R8
    IN PBYTE syscallret); //R9

EXTERN_C NTSTATUS ZwQuerySystemInformation(
    IN ULONG SystemInformationClass, //RCX
    OUT PVOID SystemInformation, //RDX
    IN ULONG SystemInformationLength, //R8
    OUT PULONG ReturnLength, //R9
    IN DWORD ssn, //RSP + 40
    IN PBYTE syscallret //RSP + 48
);

EXTERN_C NTSTATUS ZwQueryObject(
    IN HANDLE Handle,
    IN ULONG ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength,
    IN DWORD ssn,
    IN PBYTE syscallret);

EXTERN_C NTSTATUS ZwQueryVirtualMemory(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress,
    IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
    OUT PVOID MemoryInformation,
    IN SIZE_T MemoryInformationLength,
    OUT PSIZE_T ReturnLength,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwFreeVirtualMemory(
    IN HANDLE  ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG   FreeType,
    IN DWORD ssn, //RSP + 40
    IN PBYTE syscallret //RSP + 48
);

EXTERN_C NTSTATUS ZwSetContextThread(
    IN HANDLE ThreadHandle,
    OUT PCONTEXT Context,
    IN DWORD ssn,
    IN PBYTE syscallret
);

EXTERN_C NTSTATUS ZwGetContextThread(
    IN HANDLE ThreadHandle,
    OUT PCONTEXT Context,
    IN DWORD ssn,
    IN PBYTE syscallret
);


/*-----------------RANDOMNESS--------------------------*/

int generateRandomFromAddress(ULONG_PTR ptr) {
    uintptr_t address = (uintptr_t)ptr;

    // Extract lower bits from the address and scale to fit the range 1-480
    int randomNumber = ((address >> 3) & 0xFFFFF) % 400 + 1;

    return randomNumber;
}

//retrieve syscall instructions address
PBYTE retrieveSCAddr(PBYTE funcStar) {

    int emergencybreak = 0;
    while (emergencybreak < 2048) {
        //taking into account indianess crazyness
        if (funcStar[0] == 0x0f && funcStar[1] == 0x05 && funcStar[2] == 0xc3) {

            return funcStar;
        }
        funcStar++;
        emergencybreak++;
    }
    return NULL;
}


/*------------------FIND ZW FUNCTIONS------------------*/

void RetrieveZwFunctions(IN HMODULE hModule, IN PSYSCALL_ENTRY syscalls) {


    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return;

    IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    //variables for syscall
    CHAR zw[] = { 'Z','w' };
    CHAR ZwAllocateVirtualMemory[] = { 'Z', 'w', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR ZwProtectVirtualMemory[] = { 'Z', 'w', 'P', 'r', 'o', 't', 'e', 'c', 't', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR ZwFlushInstructionCache[] = { 'Z','w','F','l','u','s','h','I','n','s','t','r','u','c','t','i','o','n','C','a','c','h','e','\0' };
    CHAR ZwCreateSection[] = { 'Z', 'w', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };
    CHAR ZwMapViewOfSection[] = { 'Z', 'w', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };
    CHAR ZwUnmapViewOfSection[] = { 'Z', 'w', 'U', 'n', 'm', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };
    CHAR ZwQuerySystemInformation[] = { 'Z', 'w', 'Q', 'u', 'e', 'r', 'y', 'S', 'y', 's', 't', 'e', 'm', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', '\0' };
    CHAR ZwQueryObject[] = { 'Z', 'w', 'Q', 'u', 'e', 'r', 'y', 'O', 'b', 'j', 'e', 'c', 't', '\0' };
    CHAR ZwQueryVirtualMemory[] = { 'Z', 'w', 'Q', 'u', 'e', 'r', 'y', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR ZwFreeVirtualMemory[] = { 'Z', 'w', 'F', 'r', 'e', 'e', 'V', 'i', 'r', 't', 'u', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', '\0' };
    CHAR ZwSetContextThread[] = { 'Z', 'w', 'S', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };
    CHAR ZwGetContextThread[] = { 'Z', 'w', 'G', 'e', 't', 'C', 'o', 'n', 't', 'e', 'x', 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0' };

    int zwCounter = 0;
    int syscallEntries = 0;
    DWORD syscallHalf[500] = { 0 };
    PBYTE functionAddress = NULL;
    uintptr_t addressValue = 0;
    DWORD baseAddress = 0x0;
    DWORD temp = 0x0;

    // looping through all the exported functions
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        // getting the name of the function
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);



        // searching for the function specified
        if (CompareNStringASCII(zw, pFunctionName, 2)) {
            functionAddress = (PBYTE)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
            //here i have to fill the struct with function names, address of syscall/ret and ssn
            addressValue = (uintptr_t)functionAddress;
            syscallHalf[zwCounter] = (DWORD)(addressValue & 0xFFFFFFFF);
            zwCounter++;
            //what i still need to do is to retrieve the syscall instruction to jump to

            if (CompareStringASCII(ZwAllocateVirtualMemory, pFunctionName)) {

                syscalls[0].funcAddr = (FARPROC)functionAddress;
                syscalls[0].sysretAddr = NULL;
                syscalls[0].SSN = 0;
                syscallEntries++;

            }
            if (CompareStringASCII(ZwProtectVirtualMemory, pFunctionName)) {

                syscalls[1].funcAddr = (FARPROC)functionAddress;
                syscalls[1].sysretAddr = NULL;
                syscalls[1].SSN = 0;
                syscallEntries++;

            }
            if (CompareStringASCII(ZwFlushInstructionCache, pFunctionName)) {

                syscalls[2].funcAddr = (FARPROC)functionAddress;
                syscalls[2].sysretAddr = NULL;
                syscalls[2].SSN = 0;
                syscallEntries++;

            }
            if (CompareStringASCII(ZwCreateSection, pFunctionName)) {

                syscalls[3].funcAddr = (FARPROC)functionAddress;
                syscalls[3].sysretAddr = NULL;
                syscalls[3].SSN = 0;
                syscallEntries++;

            }
            if (CompareStringASCII(ZwMapViewOfSection, pFunctionName)) {

                syscalls[4].funcAddr = (FARPROC)functionAddress;
                syscalls[4].sysretAddr = NULL;
                syscalls[4].SSN = 0;
                syscallEntries++;

            }
            if (CompareStringASCII(ZwUnmapViewOfSection, pFunctionName)) {

                syscalls[5].funcAddr = (FARPROC)functionAddress;
                syscalls[5].sysretAddr = NULL;
                syscalls[5].SSN = 0;
                syscallEntries++;

            }
            if (CompareStringASCII(ZwQuerySystemInformation, pFunctionName)) {

                syscalls[6].funcAddr = (FARPROC)functionAddress;
                syscalls[6].sysretAddr = NULL;
                syscalls[6].SSN = 0;
                syscallEntries++;

            }
            if (CompareStringASCII(ZwQueryObject, pFunctionName)) {

                syscalls[7].funcAddr = (FARPROC)functionAddress;
                syscalls[7].sysretAddr = NULL;
                syscalls[7].SSN = 0;
                syscallEntries++;

            }
            if (CompareStringASCII(ZwQueryVirtualMemory, pFunctionName)) {

                syscalls[8].funcAddr = (FARPROC)functionAddress;
                syscalls[8].sysretAddr = NULL;
                syscalls[8].SSN = 0;
                syscallEntries++;

            }
            if (CompareStringASCII(ZwFreeVirtualMemory, pFunctionName)) {

                syscalls[9].funcAddr = (FARPROC)functionAddress;
                syscalls[9].sysretAddr = NULL;
                syscalls[9].SSN = 0;
                syscallEntries++;

            }
            if (CompareStringASCII(ZwSetContextThread, pFunctionName)) {

                syscalls[10].funcAddr = (FARPROC)functionAddress;
                syscalls[10].sysretAddr = NULL;
                syscalls[10].SSN = 0;
                syscallEntries++;

            }
            if (CompareStringASCII(ZwGetContextThread, pFunctionName)) {

                syscalls[11].funcAddr = (FARPROC)functionAddress;
                syscalls[11].sysretAddr = NULL;
                syscalls[11].SSN = 0;
                syscallEntries++;

            }
        }

    }
    //this base address i need only once
    baseAddress = (DWORD)(addressValue >> 32);

    //bubble sort really slow sorting 
    for (int i = 0; i < zwCounter; i++) {
        for (int j = 0; j < zwCounter - 1 - i; j++) {
            if (syscallHalf[j] > syscallHalf[j + 1]) {
                temp = syscallHalf[j + 1];
                syscallHalf[j + 1] = syscallHalf[j];
                syscallHalf[j] = temp;

            }
        }

    }
    //i can put the base address at the end
    syscallHalf[zwCounter++] = baseAddress;

    //here i can go through the list of the half-addresses that i have and pick two 
    //random syscall/ret
    ULONG_PTR currentAddress = (ULONG_PTR)&RetrieveZwFunctions;
    while (syscalls[0].sysretAddr == NULL || syscalls[1].sysretAddr == NULL || syscalls[2].sysretAddr == NULL || syscalls[3].sysretAddr == NULL || syscalls[4].sysretAddr == NULL || syscalls[5].sysretAddr == NULL || syscalls[6].sysretAddr == NULL || syscalls[7].sysretAddr == NULL || syscalls[8].sysretAddr == NULL || syscalls[9].sysretAddr == NULL || syscalls[10].sysretAddr == NULL || syscalls[11].sysretAddr == NULL) {


        syscalls[0].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
        currentAddress = currentAddress + 46;
        syscalls[1].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
        currentAddress = currentAddress + 46;
        syscalls[2].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
        currentAddress = currentAddress + 46;
        syscalls[3].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
        currentAddress = currentAddress + 46;
        syscalls[4].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
        currentAddress = currentAddress + 46;
        syscalls[5].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
        currentAddress = currentAddress + 46;
        syscalls[6].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
        currentAddress = currentAddress + 46;
        syscalls[7].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
        currentAddress = currentAddress + 46;
        syscalls[8].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
        currentAddress = currentAddress + 46;
        syscalls[9].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
        currentAddress = currentAddress + 46;
        syscalls[10].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));
        currentAddress = currentAddress + 46;
        syscalls[11].sysretAddr = retrieveSCAddr((PBYTE)((uintptr_t)baseAddress << 32 | syscallHalf[generateRandomFromAddress(currentAddress)]));


    }

    //here i can go through the list of the functions looking for what i want and then match it 
    //in my array
    for (int i = 0; i < zwCounter - 1; i++) {

        for (int j = 0; j < syscallEntries; j++) {

            //recycling variables here for comparing purposes 
            addressValue = (uintptr_t)syscalls[j].funcAddr;
            //if the address of the syscall we want matches any half of those we want, we know that's the right SSN
            if (syscallHalf[i] == (DWORD)(addressValue & 0xFFFFFFFF)) {
                syscalls[j].SSN = i;

            }
        }

    }
}
