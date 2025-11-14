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
        PROCESS_VM_READ |      // Read memory
        PROCESS_VM_WRITE |     // Write memory  
        PROCESS_VM_OPERATION,  // Allocate/protect
        FALSE,                 // Don't inherit
        dwPid
    );
    
    // STEP 2: VALIDATE
    if (hProcess == NULL) {
        DWORD err = GetLastError();
        wprintf(L"Failed: 0x%08X\\n", err);
        
        if (err == ERROR_ACCESS_DENIED) {
            wprintf(L"Need admin rights!\\n");
        }
        return 1;
    }
    
    wprintf(L"Handle: 0x%p\\n", hProcess);
    
    // STEP 3: USE
    // Query process info
    DWORD exitCode;
    GetExitCodeProcess(hProcess, &exitCode);
    
    if (exitCode == STILL_ACTIVE) {
        wprintf(L"Process running\\n");
    }
    
    // Read memory
    BYTE buf[100];
    SIZE_T read;
    ReadProcessMemory(
        hProcess,
        (LPCVOID)0x400000,
        buf, sizeof(buf), &read
    );
    
    // STEP 4: CLOSE - CRITICAL!
    CloseHandle(hProcess);
    // After this, hProcess is invalid!
    
    return 0;
}

// ACCESS RIGHTS EXPLAINED
// =======================

// Minimal rights (query only)
HANDLE h1 = OpenProcess(
    PROCESS_QUERY_INFORMATION,
    FALSE, pid
);

// Injection rights
HANDLE h2 = OpenProcess(
    PROCESS_CREATE_THREAD |
    PROCESS_VM_OPERATION |
    PROCESS_VM_WRITE,
    FALSE, pid
);

// Everything
HANDLE h3 = OpenProcess(
    PROCESS_ALL_ACCESS,
    FALSE, pid
);

// HANDLE INHERITANCE
// ==================
SECURITY_ATTRIBUTES sa;
sa.nLength = sizeof(sa);
sa.bInheritHandle = TRUE;
sa.lpSecurityDescriptor = NULL;

HANDLE hFile = CreateFileW(
    L"log.txt",
    GENERIC_WRITE,
    0, &sa,  // Inheritable!
    CREATE_ALWAYS, 0, NULL
);

// Child process can inherit this
STARTUPINFOW si = {0};
PROCESS_INFORMATION pi = {0};
CreateProcessW(
    NULL, L"child.exe",
    NULL, NULL,
    TRUE,  // Inherit handles!
    0, NULL, NULL,
    &si, &pi
);`,
          language: "c"
        },
        {
          title: "3. Error Handling - Professional Approach",
          content: `Every Windows API can fail. GetLastError() retrieves the thread-local error code set by the last failed call. This is CRITICAL for debugging and production code.

KEY PRINCIPLES:
1. Check return values ALWAYS
2. Call GetLastError() IMMEDIATELY after failure
3. GetLastError() is overwritten by next API call
4. Different APIs use different failure indicators (NULL, FALSE, INVALID_HANDLE_VALUE)
5. Error codes are in winerror.h

NTSTATUS vs GetLastError():
• Win32 APIs (kernel32.dll) use GetLastError() → ERROR_* codes
• Native APIs (ntdll.dll) return NTSTATUS → STATUS_* codes
• You need to handle both in advanced code`,
          code: `#include <windows.h>
#include <stdio.h>

// ERROR HANDLING PATTERNS
// =======================

// Pattern 1: Basic
void BasicPattern() {
    HANDLE h = CreateFileW(
        L"test.txt",
        GENERIC_READ, 0, NULL,
        OPEN_EXISTING, 0, NULL
    );
    
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        wprintf(L"Error: %lu\\n", err);
        
        switch(err) {
            case ERROR_FILE_NOT_FOUND:
                wprintf(L"File not found\\n");
                break;
            case ERROR_ACCESS_DENIED:
                wprintf(L"Access denied\\n");
                break;
            case ERROR_SHARING_VIOLATION:
                wprintf(L"File in use\\n");
                break;
        }
        return;
    }
    
    // Success path
    CloseHandle(h);
}

// Pattern 2: Human-readable errors
void PrintError(DWORD code) {
    LPWSTR msg = NULL;
    
    FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, code,
        MAKELANGID(LANG_NEUTRAL, 
                   SUBLANG_DEFAULT),
        (LPWSTR)&msg, 0, NULL
    );
    
    if (msg) {
        wprintf(L"Error %lu: %s", code, msg);
        LocalFree(msg);
    }
}

// Pattern 3: Production-ready
BOOL SecureOpen(LPCWSTR path, 
                HANDLE *pHandle) {
    *pHandle = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (*pHandle == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        
        wprintf(L"[ERROR] Failed: %s\\n", 
                path);
        PrintError(err);
        
        // Actionable hints
        if (err == ERROR_ACCESS_DENIED) {
            wprintf(L"Try: Run as admin\\n");
        } else if (err == ERROR_FILE_NOT_FOUND) {
            wprintf(L"Try: Check path\\n");
        }
        
        return FALSE;
    }
    
    return TRUE;
}

// NTSTATUS HANDLING
// =================
#include <winternl.h>
#include <ntstatus.h>

typedef NTSTATUS (NTAPI *pNtQSI)(
    ULONG, PVOID, ULONG, PULONG);

void NativeAPIExample() {
    HMODULE hNtdll = 
        GetModuleHandleW(L"ntdll.dll");
    
    pNtQSI NtQuerySystemInformation =
        (pNtQSI)GetProcAddress(
            hNtdll, 
            "NtQuerySystemInformation"
        );
    
    BYTE buf[1024];
    ULONG ret;
    
    NTSTATUS status = 
        NtQuerySystemInformation(
            0, buf, sizeof(buf), &ret);
    
    if (!NT_SUCCESS(status)) {
        wprintf(L"NTSTATUS: 0x%08X\\n", 
                status);
        
        if (status == STATUS_ACCESS_DENIED) {
            wprintf(L"Access denied\\n");
        } else if (status == 
                   STATUS_BUFFER_TOO_SMALL) {
            wprintf(L"Need %lu bytes\\n", 
                    ret);
        }
        return;
    }
    
    wprintf(L"Success\\n");
}

// COMMON ERROR CODES
// ==================
/*
ERROR_SUCCESS            0
ERROR_FILE_NOT_FOUND     2
ERROR_ACCESS_DENIED      5
ERROR_INVALID_HANDLE     6
ERROR_NOT_ENOUGH_MEMORY  8
ERROR_INVALID_PARAMETER  87
ERROR_INSUFFICIENT_BUFFER 122
*/`,
          language: "c"
        },
        {
          title: "4. Strings & Unicode - ANSI vs Wide",
          content: `Windows is fully Unicode internally (UTF-16). Every string API has two versions:
• CreateFileA() - ANSI (char*) - slow, limited
• CreateFileW() - Wide (wchar_t*) - fast, full Unicode

The "generic" name (CreateFile) is a macro that picks one based on UNICODE definition.

RULE FOR MODERN CODE: ALWAYS use W variants explicitly!

Why? ANSI functions convert to Unicode internally anyway, so they're slower. Plus they can't handle emoji, Asian languages, etc.

Wide strings:
• Use wchar_t (2 bytes per char)
• Prefix with L: L"Hello"
• Use wcs* functions: wcslen, wcscpy_s, etc.`,
          code: `#include <windows.h>
#include <stdio.h>

// STRING FUNDAMENTALS
// ===================

// ANSI (old, avoid)
char ansi[] = "Hello";
LPSTR pAnsi = ansi;
LPCSTR pConstAnsi = "Hello";

// WIDE (use this!)
wchar_t wide[] = L"Hello";
LPWSTR pWide = wide;
LPCWSTR pConstWide = L"Hello";

// API USAGE
// =========

// BAD: ANSI version
HANDLE hA = CreateFileA(
    "C:\\\\file.txt",
    GENERIC_READ, 0, NULL,
    OPEN_EXISTING, 0, NULL
);

// GOOD: Wide version
HANDLE hW = CreateFileW(
    L"C:\\\\file.txt",
    GENERIC_READ, 0, NULL,
    OPEN_EXISTING, 0, NULL
);

// CONVERSION
// ==========

// ANSI → Wide
void A2W() {
    char ansi[] = "Hello, 世界";
    wchar_t wide[256];
    
    int len = MultiByteToWideChar(
        CP_UTF8,      // UTF-8
        0,            // Flags
        ansi,         // Source
        -1,           // Null-terminated
        wide,         // Destination
        256           // Size in wchars
    );
    
    if (len == 0) {
        wprintf(L"Failed: %lu\\n", 
                GetLastError());
        return;
    }
    
    wprintf(L"Result: %s\\n", wide);
    wprintf(L"Length: %d chars\\n", len);
}

// Wide → ANSI
void W2A() {
    wchar_t wide[] = L"Hello, 世界";
    char ansi[256];
    
    int len = WideCharToMultiByte(
        CP_UTF8,      // UTF-8
        0,            // Flags
        wide,         // Source
        -1,           // Null-terminated
        ansi,         // Destination
        256,          // Size in bytes
        NULL, NULL    // Defaults
    );
    
    if (len == 0) {
        printf("Failed: %lu\\n", 
               GetLastError());
        return;
    }
    
    printf("Result: %s\\n", ansi);
    printf("Length: %d bytes\\n", len);
}

// STRING OPERATIONS
// =================

void StringOps() {
    wchar_t buf[MAX_PATH];
    
    // Length
    size_t len = wcslen(L"test");
    
    // Copy (SAFE!)
    wcscpy_s(buf, MAX_PATH, L"Hello");
    
    // Concatenate
    wcscat_s(buf, MAX_PATH, L" World");
    
    // Compare
    int cmp = wcscmp(L"A", L"B");
    // < 0: first < second
    // = 0: equal
    // > 0: first > second
    
    // Case-insensitive
    int icmp = _wcsicmp(L"hello", 
                        L"HELLO");
    // Returns 0 (equal)
    
    // Find substring
    wchar_t *pos = wcsstr(
        L"Hello World", L"World");
    // pos points to "World"
    
    // Find character
    wchar_t *chr = wcschr(
        L"Hello", L'e');
    // chr points to "ello"
}

// FORMATTING
// ==========

void Formatting() {
    wchar_t buf[256];
    
    // Basic format
    swprintf_s(buf, 256, 
        L"PID: %lu", 1234);
    
    // Multiple values
    swprintf_s(buf, 256,
        L"Addr: 0x%p Size: 0x%zX",
        (void*)0x400000, 
        (size_t)0x1000);
    
    // Build path
    wchar_t dir[] = L"C:\\\\Temp";
    wchar_t file[] = L"out.txt";
    swprintf_s(buf, 256, 
        L"%s\\\\%s", dir, file);
    
    wprintf(L"%s\\n", buf);
}

// PRACTICAL EXAMPLE
// =================

void BuildPath() {
    wchar_t path[MAX_PATH];
    wchar_t temp[MAX_PATH];
    
    // Get temp directory
    GetTempPathW(MAX_PATH, temp);
    
    // Build full path
    swprintf_s(path, MAX_PATH,
        L"%s\\\\myapp\\\\data.bin", 
        temp);
    
    wprintf(L"Path: %s\\n", path);
    
    // Expand environment vars
    wchar_t input[] = 
        L"%PROGRAMFILES%\\\\MyApp";
    wchar_t expanded[MAX_PATH];
    
    ExpandEnvironmentStringsW(
        input, expanded, MAX_PATH);
    
    wprintf(L"Expanded: %s\\n", 
            expanded);
}

// BEST PRACTICES
// ==============
/*
1. Use wchar_t and L"" always
2. Use *W APIs explicitly
3. Use _s functions: wcscpy_s
4. Check buffer sizes
5. Use MAX_PATH for paths
6. Remember: wcslen = chars, 
   not bytes!
7. Use swprintf_s, not strcat
*/`,
          language: "c"
        },
        {
          title: "5. Essential Headers & Linking",
          content: `Windows programming requires understanding which headers provide what. windows.h is the master header, but advanced techniques need specialized headers.

KEY HEADERS:
• windows.h - Core Win32 APIs, types, constants
• winternl.h - Internal NT structures (PEB, TEB)
• tlhelp32.h - Process/thread/module enumeration  
• psapi.h - Process status information
• ntstatus.h - Native API status codes

LIBRARIES:
• kernel32.lib - Win32 APIs (usually automatic)
• ntdll.lib - Native APIs (explicit link needed)
• advapi32.lib - Security, registry, services
• user32.lib - Windows, messages, UI
• psapi.lib - Process APIs

Use #pragma comment(lib, "name.lib") to link.`,
          code: `// HEADER REFERENCE
// =================

#include <windows.h>
// Provides:
// - Basic types (DWORD, HANDLE)
// - Win32 API declarations
// - Common constants
// - winnth (PE structures)

#include <winternl.h>
// Provides:
// - PEB, TEB structures
// - Native API prototypes
// - OBJECT_ATTRIBUTES
// - UNICODE_STRING

#include <tlhelp32.h>
// Provides:
// - CreateToolhelp32Snapshot
// - Process32First/Next
// - Thread32First/Next
// - Module32First/Next

#include <psapi.h>
// Provides:
// - EnumProcesses
// - EnumProcessModules
// - GetModuleInformation
// - GetProcessMemoryInfo
#pragma comment(lib, "psapi.lib")

#include <ntstatus.h>
// Provides:
// - STATUS_SUCCESS
// - STATUS_ACCESS_DENIED
// - NT_SUCCESS() macro

#include <shlwapi.h>
// Provides:
// - PathCombine
// - PathFileExists
// - Path manipulation
#pragma comment(lib, "shlwapi.lib")

// LIBRARY LINKING
// ===============

// Method 1: Pragma (recommended)
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

// Method 2: Compiler flags
// cl /Fe:prog.exe prog.c ntdll.lib

// TEMPLATES
// =========

// Basic program
#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "ntdll.lib")

int main() {
    wprintf(L"Hello!\\n");
    return 0;
}

// Process enumeration
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#pragma comment(lib, "psapi.lib")

int main() {
    // Enumerate processes
    HANDLE hSnap = 
        CreateToolhelp32Snapshot(
            TH32CS_SNAPPROCESS, 0);
    
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    
    Process32FirstW(hSnap, &pe);
    do {
        wprintf(L"PID %lu: %s\\n",
            pe.th32ProcessID,
            pe.szExeFile);
    } while (Process32NextW(hSnap, &pe));
    
    CloseHandle(hSnap);
    return 0;
}

// Native API template
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>
#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS (NTAPI *pFunc)(
    PVOID, PVOID);

int main() {
    HMODULE hNtdll = 
        GetModuleHandleW(L"ntdll.dll");
    
    pFunc NtFunc = (pFunc)
        GetProcAddress(hNtdll, "NtFunc");
    
    NTSTATUS status = NtFunc(NULL, NULL);
    
    if (!NT_SUCCESS(status)) {
        wprintf(L"Failed: 0x%08X\\n", 
                status);
        return 1;
    }
    
    return 0;
}

// IMPORTANT CONSTANTS
// ===================

MAX_PATH              260
FALSE                 0
TRUE                  1
INVALID_HANDLE_VALUE  -1

// Memory
MEM_COMMIT            0x1000
MEM_RESERVE           0x2000
MEM_RELEASE           0x8000

// Protection
PAGE_NOACCESS         0x01
PAGE_READONLY         0x02
PAGE_READWRITE        0x04
PAGE_EXECUTE          0x10
PAGE_EXECUTE_READ     0x20
PAGE_EXECUTE_READWRITE 0x40

// Process access
PROCESS_ALL_ACCESS    0x1F0FFF
PROCESS_TERMINATE     0x0001
PROCESS_VM_READ       0x0010
PROCESS_VM_WRITE      0x0020
PROCESS_VM_OPERATION  0x0008

// File access
GENERIC_READ          0x80000000
GENERIC_WRITE         0x40000000
GENERIC_EXECUTE       0x20000000

// COMPLETE WORKING EXAMPLE
// ========================

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

#pragma comment(lib, "psapi.lib")

DWORD FindProcess(LPCWSTR name) {
    HANDLE hSnap = 
        CreateToolhelp32Snapshot(
            TH32CS_SNAPPROCESS, 0);
    
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    
    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        return 0;
    }
    
    DWORD pid = 0;
    do {
        if (_wcsicmp(pe.szExeFile, 
                     name) == 0) {
            pid = pe.th32ProcessID;
            break;
        }
    } while (Process32NextW(hSnap, &pe));
    
    CloseHandle(hSnap);
    return pid;
}

int wmain(int argc, wchar_t *argv[]) {
    if (argc != 2) {
        wprintf(L"Usage: %s <process>\\n",
                argv[0]);
        return 1;
    }
    
    DWORD pid = FindProcess(argv[1]);
    
    if (pid == 0) {
        wprintf(L"Process not found\\n");
        return 1;
    }
    
    wprintf(L"Found PID: %lu\\n", pid);
    
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, pid
    );
    
    if (hProc == NULL) {
        wprintf(L"Failed to open: %lu\\n",
                GetLastError());
        return 1;
    }
    
    HMODULE hMods[1024];
    DWORD needed;
    
    if (EnumProcessModules(
            hProc, hMods, sizeof(hMods),
            &needed)) {
        
        DWORD count = needed / sizeof(HMODULE);
        wprintf(L"Modules: %lu\\n\\n", count);
        
        for (DWORD i = 0; i < count; i++) {
            wchar_t name[MAX_PATH];
            
            GetModuleFileNameExW(
                hProc, hMods[i],
                name, MAX_PATH
            );
            
            wprintf(L"[%3lu] %s\\n", 
                    i, name);
        }
    }
    
    CloseHandle(hProc);
    return 0;
}`,
          language: "c"
        }
      ]
    },
    "windows-internals": {
      title: "Windows Internals & Win32 API - Advanced",
      sections: [
        {
          title: "Process Architecture Deep Dive",
          content: `A process is a container for execution with its own:
• Virtual address space (4GB on x86, 128TB on x64)
• Handle table (references to kernel objects)
• Primary token (security context/privileges)
• At least one thread (unit of execution)

In kernel, a process is represented by EPROCESS structure. In user-mode, you interact via handles. The Process Environment Block (PEB) contains user-mode process info.

KEY CONCEPT: Processes don't execute code - threads do! A process is just the environment where threads run.`,
          code: `// PROCESS CREATION
#include <windows.h>

void CreateProcessExample() {
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    // Create process suspended
    BOOL success = CreateProcessW(
        NULL,                  // App name
        L"notepad.exe",        // Command
        NULL, NULL,            // Security
        FALSE,                 // Inherit handles
        CREATE_SUSPENDED,      // Suspended!
        NULL,                  // Environment
        NULL,                  // Current dir
        &si, &pi               // Out params
    );
    
    if (!success) {
        wprintf(L"Failed: %lu\\n", 
                GetLastError());
        return;
    }
    
    wprintf(L"Created:\\n");
    wprintf(L"  PID: %lu\\n", 
            pi.dwProcessId);
    wprintf(L"  TID: %lu\\n", 
            pi.dwThreadId);
    wprintf(L"  hProcess: 0x%p\\n", 
            pi.hProcess);
    wprintf(L"  hThread: 0x%p\\n", 
            pi.hThread);
    
    // Process is suspended!
    // Can inject code here...
    
    // Resume
    ResumeThread(pi.hThread);
    
    // Wait for exit
    WaitForSingleObject(
        pi.hProcess, INFINITE);
    
    DWORD exitCode;
    GetExitCodeProcess(
        pi.hProcess, &exitCode);
    wprintf(L"Exited: %lu\\n", exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

// PROCESS ENUMERATION
void EnumerateProcesses() {
    DWORD pids[1024];
    DWORD needed;
    
    EnumProcesses(pids, sizeof(pids), 
                  &needed);
    
    DWORD count = needed / sizeof(DWORD);
    
    for (DWORD i = 0; i < count; i++) {
        if (pids[i] == 0) continue;
        
        HANDLE h = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE, pids[i]
        );
        
        if (h) {
            wchar_t name[MAX_PATH];
            DWORD size = MAX_PATH;
            
            QueryFullProcessImageNameW(
                h, 0, name, &size);
            
            wprintf(L"[%5lu] %s\\n", 
                    pids[i], name);
            
            CloseHandle(h);
        }
    }
}

// PEB ACCESS
#include <winternl.h>

void ReadPEB(HANDLE hProc) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG len;
    
    typedef NTSTATUS (NTAPI *pNtQIP)(
        HANDLE, PROCESSINFOCLASS,
        PVOID, ULONG, PULONG
    );
    
    HMODULE hNtdll = 
        GetModuleHandleW(L"ntdll.dll");
    pNtQIP NtQueryInformationProcess =
        (pNtQIP)GetProcAddress(
            hNtdll, 
            "NtQueryInformationProcess"
        );
    
    NTSTATUS status = 
        NtQueryInformationProcess(
            hProc, ProcessBasicInformation,
            &pbi, sizeof(pbi), &len
        );
    
    if (NT_SUCCESS(status)) {
        wprintf(L"PEB: 0x%p\\n", 
                pbi.PebBaseAddress);
        
        // Read PEB
        PEB peb;
        SIZE_T read;
        ReadProcessMemory(
            hProc, pbi.PebBaseAddress,
            &peb, sizeof(peb), &read
        );
        
        wprintf(L"ImageBase: 0x%p\\n",
                peb.ImageBaseAddress);
        wprintf(L"BeingDebugged: %d\\n",
                peb.BeingDebugged);
    }
}`,
          language: "c"
        },
        {
          title: "Virtual Memory Management",
          content: `Every process has its own virtual address space - a flat, contiguous range of addresses. On x64, it's 128TB (0x0000000000000000 to 0x00007FFFFFFFFFFF for user mode).

Virtual addresses don't directly correspond to physical RAM - the Memory Management Unit (MMU) translates them using page tables.

MEMORY STATES:
• FREE - Not allocated
• RESERVED - Address space reserved but no physical backing
• COMMITTED - Has physical storage (RAM or pagefile)

PROTECTION:
PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE

This is the foundation for process injection!`,
          code: `#include <windows.h>

// ALLOCATE MEMORY
void AllocateMemory() {
    // In current process
    LPVOID pLocal = VirtualAlloc(
        NULL,                    // Address
        0x1000,                  // 4KB
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (pLocal) {
        wprintf(L"Allocated: 0x%p\\n", 
                pLocal);
        
        // Use memory
        memset(pLocal, 0x41, 0x1000);
        
        // Free
        VirtualFree(pLocal, 0, 
                    MEM_RELEASE);
    }
}

// ALLOCATE IN REMOTE PROCESS
void RemoteAllocate(HANDLE hProc) {
    LPVOID pRemote = VirtualAllocEx(
        hProc,                   // Target
        NULL,                    // Address
        0x1000,                  // Size
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE   // RWX!
    );
    
    if (!pRemote) {
        wprintf(L"Failed: %lu\\n",
                GetLastError());
        return;
    }
    
    wprintf(L"Remote: 0x%p\\n", pRemote);
    
    // Write data
    BYTE data[] = {0x90, 0x90, 0x90};
    SIZE_T written;
    
    WriteProcessMemory(
        hProc, pRemote,
        data, sizeof(data),
        &written
    );
    
    wprintf(L"Wrote %zu bytes\\n", written);
}

// CHANGE PROTECTION
void ProtectMemory(LPVOID addr) {
    DWORD oldProtect;
    
    BOOL ok = VirtualProtect(
        addr,
        0x1000,
        PAGE_EXECUTE_READ,  // New
        &oldProtect         // Old
    );
    
    if (ok) {
        wprintf(L"Old: 0x%08X\\n", 
                oldProtect);
    }
}

// QUERY MEMORY
void QueryMemory(LPVOID addr) {
    MEMORY_BASIC_INFORMATION mbi;
    
    SIZE_T result = VirtualQuery(
        addr, &mbi, sizeof(mbi)
    );
    
    if (result) {
        wprintf(L"Base: 0x%p\\n", 
                mbi.BaseAddress);
        wprintf(L"Size: 0x%zX\\n",
                mbi.RegionSize);
        wprintf(L"State: 0x%08X\\n",
                mbi.State);
        wprintf(L"Protect: 0x%08X\\n",
                mbi.Protect);
        wprintf(L"Type: 0x%08X\\n",
                mbi.Type);
    }
}

// ENUMERATE MEMORY REGIONS
void EnumerateMemory(HANDLE hProc) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = NULL;
    
    while (VirtualQueryEx(
            hProc, addr, 
            &mbi, sizeof(mbi))) {
        
        if (mbi.State == MEM_COMMIT) {
            wprintf(L"0x%016p - 0x%016p",
                    mbi.BaseAddress,
                    (BYTE*)mbi.BaseAddress + 
                    mbi.RegionSize);
            
            wprintf(L" [%6zuKB] ", 
                    mbi.RegionSize / 1024);
            
            // Protection
            if (mbi.Protect & PAGE_EXECUTE)
                wprintf(L"X");
            else if (mbi.Protect & 
                     PAGE_EXECUTE_READ)
                wprintf(L"RX");
            else if (mbi.Protect & 
                     PAGE_EXECUTE_READWRITE)
                wprintf(L"RWX");
            else if (mbi.Protect & 
                     PAGE_READWRITE)
                wprintf(L"RW");
            else if (mbi.Protect & 
                     PAGE_READONLY)
                wprintf(L"R");
            
            wprintf(L"\\n");
        }
        
        addr = (BYTE*)mbi.BaseAddress + 
               mbi.RegionSize;
    }
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
              <p className="text-sm text-muted-foreground whitespace-pre-line leading-relaxed">{section.content}</p>
              
              {section.code && (
                <div className="relative">
                  <Badge className="absolute top-2 right-2 text-xs">
                    {section.language}
                  </Badge>
                  <pre className="bg-muted p-4 rounded-lg overflow-x-auto text-xs">
                    <code className="text-foreground font-mono whitespace-pre">{section.code}</code>
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
