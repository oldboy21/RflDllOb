#include <Windows.h>
#include <winternl.h>

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)


typedef PVOID PACTIVATION_CONTEXT;

typedef struct _BASE_RELOCATION_ENTRY {
    WORD	Offset : 12; 
    WORD	Type : 4; 
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;


typedef struct _API_SET_NAMESPACE {
    ULONG Version;
    ULONG Size;
    ULONG Flags;
    ULONG Count;
    ULONG EntryOffset;
    ULONG HashOffset;
    ULONG HashFactor;
} API_SET_NAMESPACE, * PAPI_SET_NAMESPACE;


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
    DWORD header;
    CHAR key;

} DLL_HEADER, * PDLL_HEADER;

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
    PVOID SharedData; 
    PVOID* ReadOnlyStaticServerData;

    PVOID AnsiCodePageData; 
    PVOID OemCodePageData; 
    PVOID UnicodeCaseTableData;

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    ULARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps; 

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
    PVOID AppCompatInfo; 

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData; 
    PVOID ProcessAssemblyStorageMap; 
    PVOID SystemDefaultActivationContextData; 
    PVOID SystemAssemblyStorageMap; 

    SIZE_T MinimumStackCommit;

    PVOID SparePointers[2]; 
    PVOID PatchLoaderData;
    PVOID ChpeV2ProcessInfo; 

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
        PVOID pContextData; 
        PVOID pUnused; 
        PVOID EcCodeBitMap; 
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
    PVOID TelemetryCoverageHeader; 
    ULONG CloudFileFlags;
    ULONG CloudFileDiagFlags; 
    CHAR PlaceholderCompatibilityMode;
    CHAR PlaceholderCompatibilityModeReserved[7];
    struct _LEAP_SECOND_DATA* LeapSecondData;
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
    ULONGLONG ExtendedFeatureDisableMask; 
} PEBC, * PPEBC;

/*---------FUNCTIONS PROTOTYPES--------------*/
FARPROC GPARO(IN HMODULE hModule, IN int ordinal);

/*----------------FUNCTION ALIASES----------------------*/

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

typedef LPVOID(WINAPI* fnVirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
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

typedef NTSTATUS(NTAPI* fnNtFlushInstructionCache)(
    HANDLE hProcess,
    PVOID BaseAddress,
    ULONG NumberOfBytesToFlush
    );

typedef BOOL(WINAPI* fnVirtualFree)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  dwFreeType
    );

typedef BOOL(WINAPI* fnCloseHandle)(
    
    HANDLE hObject
    );

/*----------------GENERIC FUNCTIONS--------------------*/

void* custom_malloc(size_t size, fnVirtualAlloc VA) {
    
   
    void* allocated_memory = VA(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return allocated_memory;
}


void* custom_memcpy(void* pDestination, void* pSource, size_t sLength) {

    PBYTE D = (PBYTE)pDestination;
    PBYTE S = (PBYTE)pSource;

    while (sLength--)
        *D++ = *S++;

    return pDestination;
}


void ToLowerCaseWIDE(WCHAR str[]) {

   
    
    size_t i = 0;
    
    while (str[i] != L'\0') {
        if (str[i] >= L'A' && str[i] <= L'Z') {
            str[i] = str[i] + 32; // Convert uppercase to lowercase
        }
        
        
        i++;
    }
    //return str;
    
}


bool ComprareStringASCII(CHAR str1[], CHAR str2[]) {

    
    int i = 0;
    while (str1[i] && str2[i]) {

        if (str1[i] != str2[i]) {
            return false; // Characters don't match, strings are different
        }
        i++;
    }

    // Check if both strings have reached the null terminator at the same time
    return true;
}

bool CompareStringWIDE(WCHAR str1[], WCHAR str2[]) {
    
    int i = 0;
    
    while (str1[i] && str2[i]) {
        
        if (str1[i] != str2[i]) {
            return false; // Characters don't match, strings are different
        }
        i++;
    }
    
    return true;
}


int custom_stoi(char str[]) {
   

    int result = 0;
    int i = 0;

    // Iterate through the string and convert characters to integers
    while (str[i] != '\0') {
        if (str[i] >= '0' && str[i] <= '9') {
            result = result * 10 + (str[i] - '0');
        }
        i++;
    }

    return result;
}

//----------------GET MODULE HANDLE---------------------
HMODULE GMHR(IN WCHAR szModuleName[]) {
    
    PPEBC					pPeb = (PEBC*)(__readgsqword(0x60));


    // geting Ldr
    PPEBC_LDR_DATA			pLdr = (PPEBC_LDR_DATA)(pPeb->Ldr);
    // getting the first element in the linked list (contains information about the first module)
    PLDR_DATA_TABLE_ENTRYC	pDte = (PLDR_DATA_TABLE_ENTRYC)(pLdr->InMemoryOrderModuleList.Flink);

    
    while (pDte) {

        // if not null
        if (pDte->FullDllName.Length != NULL) {
            
            // check if both equal
            ToLowerCaseWIDE(pDte->FullDllName.Buffer);
            ToLowerCaseWIDE(szModuleName);
            if (CompareStringWIDE(pDte->FullDllName.Buffer, szModuleName)) {
                
                return (HMODULE)(pDte->InInitializationOrderLinks.Flink);

            }
        }
        else {
            break;
        }

        // next element in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRYC*)(pDte);

    }
   
    return NULL;
}

/*----------------SUPPORT FUNCTIONS------------------------*/
void ParseForwarder(CHAR forwarder[], CHAR dll[], CHAR function[]) {
    
    int i = 0;
    while (forwarder[i]) {
        if (forwarder[i] == '.') {
            break;
        }
        i++;
    }
    for (int j = 0; j <= i; j++) {
        dll[j] = forwarder[j];
    }
    dll[i + 1] = 'd';
    dll[i + 2] = 'l';
    dll[i + 3] = 'l';
    dll[i + 4] = '\0';
    i++;
    int z = 0;
    while (forwarder[i]) {
        function[z] = forwarder[i];
        i++;
        z++;
    }
    function[z + 1] = '\0';
}

/*------------------GET PROC ADDRESS-------------------*/

FARPROC GPAR(IN HMODULE hModule, IN CHAR lpApiName[]) {

    
    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    //variables for forwarding
    WCHAR kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    CHAR loadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    fnLoadLibraryA LLA = NULL;
    PBYTE functionAddress = NULL;
    CHAR forwarder[260] = { 0 };
    CHAR dll[260] = { 0 };
    CHAR function[260] = { 0 };
    


    // looping through all the exported functions
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        // getting the name of the function
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);



        // searching for the function specified
        if (ComprareStringASCII(lpApiName, pFunctionName)) {
            functionAddress = (PBYTE)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

            if (functionAddress >= (PBYTE)pImgExportDir && functionAddress < (PBYTE)(pImgExportDir + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)) {
            
                //here i have to get a substring
                ParseForwarder((CHAR*)functionAddress, dll, function);
                if ((LLA = (fnLoadLibraryA)GPAR(GMHR(kernel32), loadLibraryA)) == NULL)
                    return NULL;
                if (function[0] == '#') {

                    return GPARO(LLA(dll), custom_stoi(function));
                }
                else {
                    return GPAR(LLA(dll), function);
                }
            
            }
            else {

                return (FARPROC)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

            }

        }

    }

    return NULL;
}



FARPROC GPARO(IN HMODULE hModule, IN int ordinal) {

    // we do this to avoid casting at each time we use 'hModule'
    PBYTE pBase = (PBYTE)hModule;
   
    // getting the dos header and doing a signature check
    PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    // getting the nt headers and doing a signature check
    PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    // getting the optional header
    IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;

    // we can get the optional header like this as well																								
    // PIMAGE_OPTIONAL_HEADER	pImgOptHdr	= (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)pImgNtHdrs + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));

    // getting the image export table
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    //getting the base = first ordinal value in the export table (DWORD 4 bytes)
    int base = (int)pImgExportDir->Base;
    int NumberOfFunctions = (int)pImgExportDir->NumberOfFunctions;

    //variables for forwarding
    WCHAR kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    CHAR loadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    fnLoadLibraryA LLA = NULL;
    PBYTE functionAddress = NULL;
    CHAR forwarder[260] = { 0 };
    CHAR dll[260] = { 0 };
    CHAR function[260] = { 0 };


    //check if the ordinal falls into the range of ordinals of functions exported by the DLL
    if (ordinal < base || ordinal >= base + NumberOfFunctions) {

        return NULL;
    }

    // getting the function's names array pointer
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    // getting the function's addresses array pointer
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    // getting the function's ordinal array pointer
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
    // as specified here https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
    // If the address specified is not within the export section (as defined by the address and length that are indicated
    // in the optional header), the field is an export RVA, which is an actual address in code or data. Otherwise, the field is a forwarder RVA,
    // // which names a symbol in another DLL.
    functionAddress = (PBYTE)(pBase + FunctionAddressArray[ordinal]);
    if (functionAddress >= (PBYTE)pImgExportDir && functionAddress < (PBYTE)(pImgExportDir + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)) {
    
        //here i have to get a substring
        ParseForwarder((CHAR*)functionAddress, dll, function);
        if ((LLA = (fnLoadLibraryA)GPAR(GMHR(kernel32), loadLibraryA)) == NULL)
            return NULL;
        if (function[0] == '#') {

            return GPARO(LLA(dll), custom_stoi(function));
        }
        else {
            return GPAR(LLA(dll), function);
        }
    
    }

    return (FARPROC)(pBase + FunctionAddressArray[ordinal]);

}


/*-------------------REFLECTIVE LOADER----------------------------*/

EXTERN_DLL_EXPORT bool ReflectiveFunction() {

    
    
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
    

    //dll entry point 
    fnDllMain pDllMain = NULL;
    
    //fix Memory Protection variables
    DWORD dwOldProtection = 0x00;
    DWORD dwProtection = 0x00;
    

    //locate DLL in memory
    PDLL_HEADER pDllHeader = NULL;
    ULONG_PTR dllBaseAddress = NULL;

    //new PE in memory
    PBYTE pebase = NULL;
    
    //function prototpyes
    fnVirtualAlloc VA = NULL;
    fnLoadLibraryA LLA = NULL;
    fnVirtualProtect VP = NULL;
    fnRtlAddFunctionTable RAFT = NULL;
    fnNtFlushInstructionCache FIC = NULL;

    //stack strings for PIC
    WCHAR kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    WCHAR ntdll[] = { L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', L'l', L'\0' };
    WCHAR user32[] = { L'U', L's', L'e', L'r', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    CHAR virtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', '\0' };
    CHAR virtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', '\0' };
    CHAR rtladdFunctionTable[] = { 'R', 't', 'l', 'A', 'd', 'd', 'F', 'u', 'n', 'c', 't', 'i', 'o', 'n', 'T', 'a', 'b', 'l', 'e', '\0' };
    CHAR ntFlushInstructionCache[] = { 'N', 't', 'F', 'l', 'u', 's', 'h', 'I', 'n', 's', 't', 'r', 'u', 'c', 't', 'i', 'o', 'n', 'C', 'a', 'c', 'h', 'e', '\0' };
    CHAR loadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', '\0' };
    
    
    if ((VA = (fnVirtualAlloc)GPAR(GMHR(kernel32), virtualAlloc)) == NULL)
        return FALSE;
    if ((LLA = (fnLoadLibraryA)GPAR(GMHR(kernel32), loadLibraryA)) == NULL)
        return FALSE;
    if (!(VP = (fnVirtualProtect)GPAR(GMHR(kernel32), virtualProtect)))
        return FALSE;
    if (!(RAFT = (fnRtlAddFunctionTable)GPAR(GMHR(kernel32), rtladdFunctionTable)))
        return FALSE;
    if (!(FIC = (fnNtFlushInstructionCache)GPAR(GMHR(ntdll), ntFlushInstructionCache)))
        return FALSE;
    
   
    
    /*--------------BRUTE FORCE DLL BASE ADDRESS--------------*/
    
    dllBaseAddress = (ULONG_PTR)ReflectiveFunction;

    while (TRUE)
    {
        
        pDllHeader = (PDLL_HEADER)dllBaseAddress;
        
        //whatever i use as header, needs to be compared as reversed
        //since little-endian 
        if (pDllHeader->header == 0x44434241) {

   
            //the fifth byte is supposed to be the encryption key (unused so far but keeping track of ideas)
            pImgDosHdr = (PIMAGE_DOS_HEADER)(dllBaseAddress + (5*sizeof(CHAR)));
            if (pImgDosHdr->e_magic == IMAGE_DOS_SIGNATURE)
            {

               pImgNtHdrs = (PIMAGE_NT_HEADERS)(dllBaseAddress + pImgDosHdr->e_lfanew + (5 * sizeof(CHAR)));

               if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE) {
                    
                    break;
                }
                
            }
            
        }
        
        dllBaseAddress--;
    }

    if (!dllBaseAddress)
        return FALSE;
    
    //fixing the baseAddress including the 5 bytes of header
    dllBaseAddress = dllBaseAddress + (5 * sizeof(CHAR));
   
    //setting some headers for new steps
    PIMAGE_OPTIONAL_HEADER pImgOptHdr = (PIMAGE_OPTIONAL_HEADER)((ULONG_PTR)pImgNtHdrs + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
    ImgFileHdr = pImgNtHdrs->FileHeader;
    /*--------------COPY SECTIONS IN MEMORY---------------------------*/
    
    //allocating memory for the PE in memory
    if ((pebase = (PBYTE)VA(NULL, pImgOptHdr->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) == NULL)
        return FALSE;
    
    //allocate memory for an array of SECTION HEADERS
    peSections = (PIMAGE_SECTION_HEADER*)custom_malloc((sizeof(PIMAGE_SECTION_HEADER) * ImgFileHdr.NumberOfSections), VA);
    if (peSections == NULL)
        return FALSE;
    
    
    for (int i = 0; i < ImgFileHdr.NumberOfSections; i++) {

       
        peSections[i] = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdrs) + 4 + 20 + ImgFileHdr.SizeOfOptionalHeader + (i * IMAGE_SIZEOF_SECTION_HEADER));
    }
    
    for (int i = 0; i < ImgFileHdr.NumberOfSections; i++) {

        custom_memcpy(
            (PVOID)(pebase + peSections[i]->VirtualAddress),// Destination
            (PVOID)(dllBaseAddress + peSections[i]->PointerToRawData),// Source
            peSections[i]->SizeOfRawData// Size
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
        //removing headers size and dividing by entry size
        entriesCount = (int)((pImgRelocation->SizeOfBlock - 8) / 2);

        //loop through relocation entries 
        for (int i = 0; i < entriesCount; i++) {

            switch (pRelocEntry->Type) {
            case IMAGE_REL_BASED_DIR64://if it's equal to A meaning = 10
            {//The base relocation applies the difference to the 64-bit field at offset.
                //so i need to add the delta to the 64-bit value at that offset

                ULONGLONG* toAdjust = (ULONGLONG*)(pebase + pImgRelocation->VirtualAddress + pRelocEntry->Offset);
                *toAdjust += (ULONGLONG)delta;
                break;
            }
            case IMAGE_REL_BASED_HIGHLOW:
                //The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
            {

                DWORD* toAdjust = (DWORD*)(pebase + pImgRelocation->VirtualAddress + pRelocEntry->Offset);
                *toAdjust += (DWORD)delta;
            }
            break;
            case IMAGE_REL_BASED_HIGH:
                //The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
            {
                WORD* toAdjust = (WORD*)(pebase + pImgRelocation->VirtualAddress + pRelocEntry->Offset);
                *toAdjust += HIWORD(delta);

            }
            break;
            case IMAGE_REL_BASED_LOW:
                //The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word. 
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
        if (!VP((PVOID)(pebase + peSections[i]->VirtualAddress), peSections[i]->SizeOfRawData, dwProtection, &dwOldProtection)) {
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

        //so what we do here is finding the address of these functions and executing them before
        //hitting the entrypoint 
        pImgTlsDirectory = (PIMAGE_TLS_DIRECTORY)(pebase + pImgOptHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        //pointer to pointer is array. remember uni days? 
        arrayOfCallbacks = (PIMAGE_TLS_CALLBACK*)(pImgTlsDirectory->AddressOfCallBacks);

        int i = 0;
        while (arrayOfCallbacks[i] != NULL) {

            arrayOfCallbacks[i]((LPVOID)pebase, DLL_PROCESS_ATTACH, NULL);

        }
    }

    /*--------------FLUSHING INSTRUCTION CACHE ALLA FEWER*/

    
    FIC((HANDLE)-1, NULL, 0x00);
    
    /*--------------EXECUTE ENTRY POINT--------------*/
    pDllMain = (fnDllMain)(pebase + pImgNtHdrs->OptionalHeader.AddressOfEntryPoint);
    return pDllMain((HMODULE)pebase, DLL_PROCESS_ATTACH, NULL);
    
}


VOID PayloadFunction() {
    MessageBoxA(NULL, "Ciao Grande", "Ciao Grande from DllMain!", MB_OK | MB_ICONINFORMATION);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        PayloadFunction();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

