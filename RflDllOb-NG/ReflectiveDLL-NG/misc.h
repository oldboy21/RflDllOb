#pragma once

#include <Windows.h>
#include "funcaliases.h"

/*---------FUNCTIONS PROTOTYPES--------------*/
FARPROC GPARO(IN HMODULE hModule, IN int ordinal);

/*----------------GENERIC FUNCTIONS--------------------*/

size_t custom_wcstombs(CHAR dest[], WCHAR src[], size_t n) {
    size_t i = 0;
    for (i = 0; src[i] != L'\0' && i < n; ++i) {
        dest[i] = (char)src[i]; // Convert ASCII characters directly
    }
    dest[i] = '\0'; // Null-terminate the wide character string
    return i; // Return the number of converted characters
}

size_t custom_strlen(char str[]) {


    size_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len++;
}

size_t custom_wcslen(const wchar_t* str) {
    if (!str)
        return 0;

    size_t len = 0;

    while (str[len] != L'\0') {
        len++;
    }

    return len++;
}

void custom_wsstr(WCHAR str[], int start, int length, WCHAR result[]) {
    int i = 0;
    while (i < length && str[start + i] != L'\0') {
        result[i] = str[start + i];
        i++;
    }
    result[i] = L'\0'; // Null-terminate the result string
}

void custom_wsstr_end(WCHAR str[], int start, int length, WCHAR result[]) {
    int i = 0;
    while (i < length && str[start + i] != L'\0') {
        result[i] = str[start + i];
        i++;
    }
    result[i] = L'\0'; // Null-terminate the result string
}

void custom_sstr(CHAR str[], int start, int length, CHAR result[]) {
    int i = 0;
    while (i < length && str[start + i] != '\0') {
        result[i] = str[start + i];
        i++;
    }
    result[i] = '\0'; // Null-terminate the result string
}



void* custom_memcpy(void* pDestination, void* pSource, size_t sLength, PBYTE toZero, SIZE_T lentgh) {

    PBYTE D = (PBYTE)pDestination;
    PBYTE S = (PBYTE)pSource;

    while (sLength--) {
        if (S > toZero && S < (toZero + (DWORD)lentgh))
        {
            *D++ = 0x0;
        }
        else {
            *D++ = *S++;
        }
    }

    return pDestination;
}

void custom_memcpy_classic(void* pDestination, void* pSource, size_t sLength) {

    PBYTE D = (PBYTE)pDestination;
    PBYTE S = (PBYTE)pSource;

    while (sLength--) {

        *D++ = *S++;
    }


}


void custom_memset_zero(void* pDestination, size_t sLength) {

    PBYTE D = (PBYTE)pDestination;
    while (sLength--) {

        *D++ = 0x00;
    }

}

void custom_wcscpy(wchar_t* dest, const wchar_t* src) {
    while ((*dest++ = *src++) != L'\0') {
        // Copy characters until the null-terminator is encountered
    }
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

bool CompareNStringASCII(CHAR str1[], CHAR str2[], int n) {


    int i = 0;
    while (str1[i] && str2[i] && i < n) {

        if (str1[i] != str2[i]) {
            return FALSE; // Characters don't match, strings are different
        }
        i++;
    }

    // Check if both strings have reached the null terminator at the same time
    return TRUE;
}

void ConvertDWORDToString(DWORD value, char* buffer, size_t bufferSize) {
    const char hexDigits[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };


    // Add "0x" prefix
    buffer[0] = '0';
    buffer[1] = 'x';

    // Convert each nibble to a hexadecimal digit
    for (int i = 7; i >= 0; --i) {
        buffer[2 + (7 - i)] = hexDigits[(value >> (i * 4)) & 0xF];
    }

    // Null-terminate the string
    buffer[10] = '\n';
    buffer[11] = '\0';
}

bool ComprareNStringWIDE(WCHAR str1[], WCHAR str2[], int n) {


    int i = 0;
    while (str1[i] && str2[i] && i < n) {

        if (str1[i] != str2[i]) {
            return FALSE; // Characters don't match, strings are different
        }
        i++;
    }

    // Check if both strings have reached the null terminator at the same time
    return TRUE;
}

bool CompareStringASCII(CHAR str1[], CHAR str2[]) {

    if (custom_strlen(str1) != custom_strlen(str2)) {
        return false;
    }

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

BOOL ComprareStringWIDE(WCHAR str1[], WCHAR str2[]) {

    int i = 0;

    while (str1[i] && str2[i]) {

        if (str1[i] != str2[i]) {
            return FALSE; // Characters don't match, strings are different
        }
        i++;
    }

    return TRUE;
}

BOOL containsSubstringUnicode(PWSTR str, WCHAR substring[], int strLen, int subLen) {


    CHAR dest[100] = { 0 };

    if (subLen > strLen)
        return FALSE;

    for (size_t i = 0; i <= (strLen - subLen + 1); ++i) {

        for (int j = 0; j < subLen; j++) {

            if (str[i + j] != substring[j]) {

                break;
            }

            if (j == (subLen - 1)) {

                return TRUE;

            }

        }
    }

    return FALSE;
}

BOOL containsSubstringASCII(CHAR str[], CHAR substring[]) {

    size_t strLen = 0;
    size_t subLen = 0;
    strLen = custom_strlen(str);
    subLen = custom_strlen(substring);


    //if (subLen > strLen)
    //    return FALSE;

    for (size_t i = 0; i <= strLen - subLen; i++) {
        //MB(NULL, msg, msg, MB_OK | MB_ICONINFORMATION);
        if (CompareNStringASCII(str + i, substring, subLen) == 0)
            return TRUE;
    }

    return FALSE;
}




errno_t custom_wcscpy_s(WCHAR dest[], size_t destsz, WCHAR src[]) {


    size_t i = 0;
    while (i < destsz - 1 && src[i] != L'\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = L'\0'; // Null-terminate the destination string

    return 0; // Success
}

int custom_wcsstr(WCHAR string[], WCHAR sub[]) {

    int index = 0;
    int index_sub = 0;
    while (string[index] != L'\0') {


        while (string[index] == sub[index_sub] && string[index] != L'\0' && sub[index_sub] != L'\0') {
            index++;
            index_sub++;
        }

        if (sub[index_sub] == L'\0') {
            return (index - index_sub);
        }

        index++;
        index_sub = 0;
    }

    return 0;
}

int custom_csstr(CHAR string[], CHAR sub[]) {

    int index = 0;
    int index_sub = 0;
    while (string[index] != '\0') {


        while (string[index] == sub[index_sub] && string[index] != '\0' && sub[index_sub] != '\0') {
            index++;
            index_sub++;
        }

        if (sub[index_sub] == '\0') {
            return (index - index_sub);
        }

        index++;
        index_sub = 0;
    }

    return 0;
}

int custom_find(char str[], char ch) {


    int index = 0;
    while (str[index] != '\0') {
        if (str[index] == ch) {
            return index; // Character found; return its position (index)
        }
        index++;
    }

    return -1; // Character not found
}

VOID custom_find_wide_reverse(WCHAR str[], WCHAR ch, int len, int* result) {



    int index = len - 1;
    while (index >= 0) {

        if (str[index] == ch) {

            *result = index; // Character found; return its position (index)
        }
        index--;
    }
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

void custom_itoa(unsigned int value, CHAR buffer[]) {
    int i = 0;

    // Process individual digits
    do {
        buffer[i++] = '0' + value % 10;
        value /= 10;
    } while (value);

    buffer[i] = '\0'; // Null-terminate the string

    // Reverse the string
    int start = 0;
    int end = i - 1;
    while (start < end) {
        char temp = buffer[start];
        buffer[start] = buffer[end];
        buffer[end] = temp;
        start++;
        end--;
    }
}



errno_t custom_memcpy_s(void* dest, size_t destsz, void* src, size_t count) {
    if (!dest || !src || destsz < count) {
        return EINVAL; // Invalid parameters or insufficient space
    }

    PBYTE d = (PBYTE)dest;
    PBYTE s = (PBYTE)src;

    while (count--) {
        *d++ = *s++; // Copy bytes from source to destination
    }

    return 0; // Success
}

char* custom_strcat(char dest[], char src[]) {
    size_t dest_len = custom_strlen(dest);
    size_t i;

    for (i = 0; src[i] != '\0'; ++i) {
        dest[dest_len + i] = src[i];
    }
    dest[dest_len + i] = '\0'; // Null-terminate the concatenated string

    return dest;
}

size_t custom_mbstowcs(WCHAR dest[], CHAR src[], size_t n) {
    size_t i = 0;
    for (i = 0; src[i] != '\0' && i < n; ++i) {
        dest[i] = (wchar_t)src[i]; // Convert ASCII characters directly
    }
    dest[i] = L'\0'; // Null-terminate the wide character string
    return i; // Return the number of converted characters
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
            if (ComprareStringWIDE(pDte->FullDllName.Buffer, szModuleName)) {

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

/*-------------------PEB STOMPING---------------------------*/

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
        if (CompareStringASCII(lpApiName, pFunctionName)) {
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



