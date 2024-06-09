#pragma once

#include <Windows.h>
#include "syscalls.h"
#include "headers.h"
#include "funcaliases.h"

/*--------------------FUNCTION TO ENUMERATE SECTION HANDLES-------------*/

HANDLE FindSectionHandle(PSYSCALL_ENTRY zwFunctions, fnGetProcessId GPID) {

    //THIS WORKS and can be used for debugging 
    CHAR msg[] = { 'f', 'r', 'e', 'k', '\0' };
    WCHAR kernel32[] = { L'K', L'e', L'r', L'n', L'e', L'l', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    CHAR messageBox[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', '\0' };
    WCHAR user32[] = { L'U', L's', L'e', L'r', L'3', L'2', L'.', L'd', L'l', L'l', L'\0' };
    CHAR createFileA[] = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'A', '\0' };
    CHAR filePath[] = { 'C', ':', '\\', 'U', 's', 'e', 'r', 's', '\\', 'v', 's', 'a', 'n', 't', '\\', 'f', 'r', 'e', 'n', 'k', '.', 't', 'x', 't', '\0' };
    CHAR writeFile[] = { 'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', '\0' };
    CHAR closeHandle[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0' };

    fnWriteFile WF = (fnWriteFile)GPAR(GMHR(kernel32), writeFile);
    fnCreateFileA CF = (fnCreateFileA)GPAR(GMHR(kernel32), createFileA);
    fnCloseHandle CH = (fnCloseHandle)GPAR(GMHR(kernel32), closeHandle);
    CHAR buffersmg[256] = { 0x00 };


    /*----variables-----*/
    WCHAR section[] = { L'S', L'e', L'c', L't', L'i', L'o', L'n', L'\0' };
    WCHAR SRH[] = { L'S',L'R',L'H',L'.',L'd',L'l',L'l',L'\0' };
    SIZE_T bufferSize = 0x10000; // Initial buffer size
    PVOID buffer = NULL;
    NTSTATUS STATUS = 0x00;
    SIZE_T viewSize = 0x00;
    PVOID viewBase = NULL;
    //viewSize = 1;

    //first allocation
    if ((STATUS = ZwAllocateVirtualMemory(((HANDLE)(LONG_PTR)-1), &buffer, 0, &bufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, zwFunctions[ZwAllocateVirtualMemoryF].SSN, zwFunctions[ZwAllocateVirtualMemoryF].sysretAddr)) != 0) {

        return FALSE;
    }
    //find the right size, even if i think it won't be needed due to the fact the memory allocated will be rounded to 4096
    while ((STATUS = ZwQuerySystemInformation(16, buffer, bufferSize, NULL, zwFunctions[ZwQuerySystemInformationF].SSN, zwFunctions[ZwQuerySystemInformationF].sysretAddr)) == 0xc0000004) {

        //free and re-allocate
        if (STATUS = ZwFreeVirtualMemory(((HANDLE)(LONG_PTR)-1), &buffer, 0, MEM_RELEASE, zwFunctions[ZwFreeVirtualMemoryF].SSN, zwFunctions[ZwFreeVirtualMemoryF].sysretAddr) == 0) {

            return FALSE;
        }
        //reset variables 
        buffer = NULL;
        bufferSize *= 2;
        if ((STATUS = ZwAllocateVirtualMemory(((HANDLE)(LONG_PTR)-1), &buffer, 0, &bufferSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, zwFunctions[ZwAllocateVirtualMemoryF].SSN, zwFunctions[ZwAllocateVirtualMemoryF].sysretAddr)) != 0) {

            return FALSE;
        }
    }

    /*----variables allocation second phase--------------*/
    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer;
    //
    PVOID objectTypeInfoTemp = NULL;
    SIZE_T objectTypeInfoSize = 0x1000;
    POBJECT_TYPE_INFORMATION objectTypeInfo = NULL;

    PVOID objectNameInfo = NULL;
    SIZE_T objectNameInfoSize = 0x1000;

    UNICODE_STRING objectName = { 0x00 };
    ULONG returnLength = 0x00;
    SIZE_T returnLengthS = 0x00;
    PVOID buffermeminfo = NULL;
    SIZE_T buffermeminfosize = 0x00;
    SIZE_T returnLengthMem = 0x00;
    PUNICODE_STRING memoryinfo = NULL;

    //variables for string manipulation 
    int position = 0;
    wchar_t* result = NULL;

    if ((STATUS = ZwAllocateVirtualMemory(((HANDLE)(LONG_PTR)-1), &objectTypeInfoTemp, 0, &objectTypeInfoSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, zwFunctions[ZwAllocateVirtualMemoryF].SSN, zwFunctions[ZwAllocateVirtualMemoryF].sysretAddr)) != 0) {

        return FALSE;
    }
    if ((STATUS = ZwAllocateVirtualMemory(((HANDLE)(LONG_PTR)-1), &objectNameInfo, 0, &objectNameInfoSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, zwFunctions[ZwAllocateVirtualMemoryF].SSN, zwFunctions[ZwAllocateVirtualMemoryF].sysretAddr)) != 0) {

        return FALSE;
    }
    objectTypeInfo = (POBJECT_TYPE_INFORMATION)objectTypeInfoTemp;

    //to retrieve mapped section information
    SYSTEM_HANDLE handle = { 0x00 };
    DWORD PID = GPID(((HANDLE)(LONG_PTR)-1));
    for (ULONG_PTR i = 0; i < handleInfo->HandleCount; i++) {

        handle = handleInfo->Handles[i];

        if (handle.ProcessId == PID) {

            if ((STATUS = ZwQueryObject((void*)handle.Handle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL, zwFunctions[ZwQueryObjectF].SSN, zwFunctions[ZwQueryObjectF].sysretAddr)) != 0) {

                continue;
            }

            //check if i got an handle to a section object

            if (ComprareNStringWIDE(objectTypeInfo->Name.Buffer, section, (objectTypeInfo->Name.Length / sizeof(WCHAR))) == TRUE) {

                //comparing with IMAGE NOT AT BASE because that is the return value in status if i try to re-map the DLL, but it is actually mapped

                if ((STATUS = ZwMapViewOfSection((void*)handle.Handle, ((HANDLE)(LONG_PTR)-1), &viewBase, NULL, NULL, NULL, &viewSize, ViewShare, 0, PAGE_READONLY, zwFunctions[ZwMapViewOfSectionF].SSN, zwFunctions[ZwMapViewOfSectionF].sysretAddr)) != 0x40000003) {

                    //if it actually was successfully but not for our DLL i need to clean up and continue

                    if (STATUS == 0) {

                        if (STATUS = ZwUnmapViewOfSection(((HANDLE)(LONG_PTR)-1), viewBase, zwFunctions[ZwUnmapViewOfSectionF].SSN, zwFunctions[ZwUnmapViewOfSectionF].sysretAddr) != 0) {

                            return FALSE;

                        }
                    }
                    //it always needs to be null for the ZwMapViewOfSection to work
                    viewBase = NULL;
                    continue;
                }


                if (viewBase != NULL) {


                    //here need to query the memory
                    buffermeminfo = NULL;
                    buffermeminfosize = 0x100;
                    if ((STATUS = ZwAllocateVirtualMemory(((HANDLE)(LONG_PTR)-1), &buffermeminfo, 0, &buffermeminfosize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, zwFunctions[ZwAllocateVirtualMemoryF].SSN, zwFunctions[ZwAllocateVirtualMemoryF].sysretAddr)) != 0) {


                        return FALSE;
                    }

                    if (STATUS = ZwQueryVirtualMemory(((HANDLE)(LONG_PTR)-1), viewBase, MemoryMappedFilenameInformation, buffermeminfo, buffermeminfosize, &returnLengthMem, zwFunctions[ZwQueryVirtualMemoryF].SSN, zwFunctions[ZwQueryVirtualMemoryF].sysretAddr) == 0x80000005) {


                        //free and re-allocate
                        // FREE  
                        if (STATUS = ZwFreeVirtualMemory(((HANDLE)(LONG_PTR)-1), &buffermeminfo, 0, MEM_RELEASE, zwFunctions[ZwFreeVirtualMemoryF].SSN, zwFunctions[ZwFreeVirtualMemoryF].sysretAddr) == 0) {


                            return FALSE;
                        }
                        //re-allocate
                        buffermeminfosize = returnLengthMem;
                        if ((STATUS = ZwAllocateVirtualMemory(((HANDLE)(LONG_PTR)-1), &buffermeminfo, 0, &buffermeminfosize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, zwFunctions[ZwAllocateVirtualMemoryF].SSN, zwFunctions[ZwAllocateVirtualMemoryF].sysretAddr)) != 0) {


                            return FALSE;
                        }
                        //query memory again
                        if (STATUS = ZwQueryVirtualMemory(((HANDLE)(LONG_PTR)-1), viewBase, MemoryMappedFilenameInformation, buffermeminfo, buffermeminfosize, &returnLengthMem, zwFunctions[ZwQueryVirtualMemoryF].SSN, zwFunctions[ZwQueryVirtualMemoryF].sysretAddr) == 0x80000005) {


                            return FALSE;

                        }

                    }
                    else if (STATUS != 0) {
                        //if it's not buffer overflow but actual error i unmap the dll and continue
                        if (STATUS = ZwUnmapViewOfSection(((HANDLE)(LONG_PTR)-1), viewBase, zwFunctions[ZwUnmapViewOfSectionF].SSN, zwFunctions[ZwUnmapViewOfSectionF].sysretAddr) != 0) {

                            return FALSE;

                        }
                        viewBase = NULL;
                        continue;

                    }

                    memoryinfo = (PUNICODE_STRING)buffermeminfo;

                    //ConvertPointerToString(viewBase,buffersmg,20 );

                    if (memoryinfo->Buffer != NULL) {

                        //this print the string correctly
                        custom_wcstombs(buffersmg, memoryinfo->Buffer, memoryinfo->Length / sizeof(WCHAR));

                        //if the path contains the SRH.dll 
                        if (containsSubstringUnicode(memoryinfo->Buffer, SRH, memoryinfo->Length / sizeof(WCHAR), 8)) {

                            //i free the buffer memory
                            if (STATUS = ZwFreeVirtualMemory(((HANDLE)(LONG_PTR)-1), &buffermeminfo, 0, MEM_RELEASE, zwFunctions[ZwFreeVirtualMemoryF].SSN, zwFunctions[ZwFreeVirtualMemoryF].sysretAddr) == 0) {

                                return FALSE;
                            }
                            //i unmap the section since i do not need it anymore
                            if (STATUS = ZwUnmapViewOfSection(((HANDLE)(LONG_PTR)-1), viewBase, zwFunctions[ZwUnmapViewOfSectionF].SSN, zwFunctions[ZwUnmapViewOfSectionF].sysretAddr) != 0) {

                                return FALSE;

                            }
                            // i return the handle i found
                            return (void*)handle.Handle;
                        }

                    }
                    // i haven't found any match
                    if (STATUS = ZwFreeVirtualMemory(((HANDLE)(LONG_PTR)-1), &buffermeminfo, 0, MEM_RELEASE, zwFunctions[ZwFreeVirtualMemoryF].SSN, zwFunctions[ZwFreeVirtualMemoryF].sysretAddr) == 0) {

                        return FALSE;
                    }
                    if (STATUS = ZwUnmapViewOfSection(((HANDLE)(LONG_PTR)-1), viewBase, zwFunctions[ZwUnmapViewOfSectionF].SSN, zwFunctions[ZwUnmapViewOfSectionF].sysretAddr) != 0) {

                        // MB(NULL, msg, msg, MB_OK | MB_ICONINFORMATION);//1
                        return FALSE;

                    }

                }

            }
        }

    }


}