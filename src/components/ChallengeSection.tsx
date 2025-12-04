import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  Trophy, 
  Lightbulb, 
  CheckCircle2, 
  XCircle, 
  ChevronDown, 
  ChevronUp,
  Play,
  RotateCcw,
  Eye,
  EyeOff,
  Flame,
  Target,
  Zap
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface Challenge {
  id: string;
  title: string;
  difficulty: "easy" | "medium" | "hard";
  points: number;
  description: string;
  task: string;
  hints: string[];
  starterCode: string;
  solution: string;
  testCases: string[];
  explanation: string;
}

interface ChallengeSectionProps {
  moduleId: string;
}

const challenges: Record<string, Challenge[]> = {
  fundamentals: [
    {
      id: "f1",
      title: "Get Your Process ID",
      difficulty: "easy",
      points: 10,
      description: "Every running program has a unique Process ID (PID). Windows uses this to keep track of what's running.",
      task: "Write code that prints your current process ID using the Windows API.",
      hints: [
        "You need to include windows.h",
        "Look for a function that starts with 'GetCurrent'",
        "The function is called GetCurrentProcessId()"
      ],
      starterCode: `#include <windows.h>
#include <stdio.h>

int main() {
    // TODO: Get the current process ID
    // and print it to the console
    
    DWORD pid = ???; // Fix this line
    
    printf("My Process ID is: %lu\\n", pid);
    return 0;
}`,
      solution: `#include <windows.h>
#include <stdio.h>

int main() {
    // GetCurrentProcessId() returns a DWORD (32-bit number)
    // containing our process's unique ID
    
    DWORD pid = GetCurrentProcessId();
    
    printf("My Process ID is: %lu\\n", pid);
    return 0;
}`,
      testCases: [
        "✓ Uses GetCurrentProcessId() function",
        "✓ Stores result in DWORD variable",
        "✓ Prints the PID correctly"
      ],
      explanation: "GetCurrentProcessId() is one of the simplest Windows APIs. It takes no arguments and returns a DWORD (32-bit unsigned integer) that uniquely identifies your running program. This ID is assigned by Windows when your program starts."
    },
    {
      id: "f2",
      title: "Open and Close a File",
      difficulty: "easy",
      points: 15,
      description: "Files are accessed through handles in Windows. You must always close handles when done!",
      task: "Open a file called 'test.txt', check if it opened successfully, then close the handle.",
      hints: [
        "Use CreateFileW() to open files",
        "Check if the handle equals INVALID_HANDLE_VALUE",
        "Don't forget CloseHandle() at the end!"
      ],
      starterCode: `#include <windows.h>
#include <stdio.h>

int main() {
    // TODO: Open "test.txt" for reading
    HANDLE hFile = ???; // Fix this
    
    // TODO: Check if opening succeeded
    if (???) { // Fix this condition
        printf("Failed to open file!\\n");
        return 1;
    }
    
    printf("File opened successfully!\\n");
    
    // TODO: Close the handle
    ???; // Add the missing line
    
    return 0;
}`,
      solution: `#include <windows.h>
#include <stdio.h>

int main() {
    // CreateFileW opens or creates a file
    // W = Wide (Unicode) version
    HANDLE hFile = CreateFileW(
        L"test.txt",           // File name (L = Unicode string)
        GENERIC_READ,          // We want to read
        FILE_SHARE_READ,       // Others can read too
        NULL,                  // Default security
        OPEN_EXISTING,         // File must already exist
        FILE_ATTRIBUTE_NORMAL, // Normal file
        NULL                   // No template
    );
    
    // Always check if it worked!
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file! Error: %lu\\n", GetLastError());
        return 1;
    }
    
    printf("File opened successfully!\\n");
    
    // CRITICAL: Always close handles!
    CloseHandle(hFile);
    
    return 0;
}`,
      testCases: [
        "✓ Uses CreateFileW() correctly",
        "✓ Checks for INVALID_HANDLE_VALUE",
        "✓ Calls CloseHandle() before returning"
      ],
      explanation: "CreateFileW is the foundation of file operations in Windows. The 'W' means it uses Unicode strings (wide characters). Always check if the returned handle is valid, and ALWAYS close handles when done to prevent resource leaks."
    },
    {
      id: "f3",
      title: "Handle Errors Like a Pro",
      difficulty: "medium",
      points: 25,
      description: "When Windows functions fail, they set an error code. GetLastError() retrieves it.",
      task: "Try to open a file that doesn't exist and print the specific error code and a human-readable message.",
      hints: [
        "GetLastError() returns the error code",
        "FormatMessageW() can convert codes to text",
        "Error 2 means 'File not found'"
      ],
      starterCode: `#include <windows.h>
#include <stdio.h>

int main() {
    // Try to open a file that doesn't exist
    HANDLE hFile = CreateFileW(
        L"this_file_does_not_exist.xyz",
        GENERIC_READ, 0, NULL,
        OPEN_EXISTING, 0, NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        // TODO: Get the error code
        DWORD error = ???;
        
        printf("Error Code: %lu\\n", error);
        
        // BONUS: Convert error code to message
        // (This part is optional but good to learn)
    }
    
    return 0;
}`,
      solution: `#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hFile = CreateFileW(
        L"this_file_does_not_exist.xyz",
        GENERIC_READ, 0, NULL,
        OPEN_EXISTING, 0, NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        // Get the error code IMMEDIATELY after the failed call
        DWORD error = GetLastError();
        
        printf("Error Code: %lu\\n", error);
        
        // Convert error code to human-readable message
        LPWSTR messageBuffer = NULL;
        FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM,
            NULL, error, 0,
            (LPWSTR)&messageBuffer, 0, NULL
        );
        
        if (messageBuffer) {
            wprintf(L"Error Message: %s\\n", messageBuffer);
            LocalFree(messageBuffer);
        }
    }
    
    return 0;
}`,
      testCases: [
        "✓ Uses GetLastError() after failed call",
        "✓ Prints numeric error code",
        "✓ Bonus: Converts to readable message"
      ],
      explanation: "GetLastError() must be called IMMEDIATELY after a function fails, before calling any other Windows function. FormatMessageW with FORMAT_MESSAGE_FROM_SYSTEM converts error codes to human-readable text. Remember to free the message buffer with LocalFree()!"
    }
  ],
  "windows-internals": [
    {
      id: "wi1",
      title: "Enumerate Running Processes",
      difficulty: "medium",
      points: 30,
      description: "List all running processes on the system - a fundamental skill for security tools.",
      task: "Write code to list the first 10 running processes with their PIDs and names.",
      hints: [
        "Use CreateToolhelp32Snapshot() with TH32CS_SNAPPROCESS",
        "Use Process32First() and Process32Next() to iterate",
        "The PROCESSENTRY32 structure contains szExeFile (name)"
      ],
      starterCode: `#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int main() {
    // TODO: Create a snapshot of all processes
    HANDLE hSnapshot = ???;
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create snapshot\\n");
        return 1;
    }
    
    // Set up the structure (IMPORTANT: set dwSize first!)
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    
    // TODO: Get the first process
    if (???) {
        int count = 0;
        do {
            // TODO: Print process name and PID
            printf("???");
            
            count++;
            if (count >= 10) break;
        } while (???); // Get next process
    }
    
    CloseHandle(hSnapshot);
    return 0;
}`,
      solution: `#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

int main() {
    // Create a snapshot of all processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS,  // Snapshot type: processes
        0                     // 0 = current process (ignored for SNAPPROCESS)
    );
    
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create snapshot: %lu\\n", GetLastError());
        return 1;
    }
    
    // CRITICAL: Set dwSize BEFORE calling Process32First!
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    
    // Get the first process in the snapshot
    if (Process32FirstW(hSnapshot, &pe32)) {
        int count = 0;
        do {
            wprintf(L"[%5lu] %s\\n", 
                pe32.th32ProcessID,   // PID
                pe32.szExeFile        // Process name
            );
            
            count++;
            if (count >= 10) break;
            
        } while (Process32NextW(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return 0;
}`,
      testCases: [
        "✓ Creates snapshot with TH32CS_SNAPPROCESS",
        "✓ Sets pe32.dwSize before first call",
        "✓ Uses Process32FirstW and Process32NextW correctly"
      ],
      explanation: "The Toolhelp API is the standard way to enumerate processes. The snapshot is like a 'photo' of the system at that moment. CRITICAL: You MUST set dwSize before calling Process32First - this is a very common bug!"
    },
    {
      id: "wi2",
      title: "Read Process Memory",
      difficulty: "hard",
      points: 50,
      description: "Reading memory from another process is a core skill. You'll need proper privileges!",
      task: "Open a process by PID and read 16 bytes from a specified address.",
      hints: [
        "OpenProcess() with PROCESS_VM_READ access",
        "ReadProcessMemory() reads from the target",
        "Handle failures gracefully"
      ],
      starterCode: `#include <windows.h>
#include <stdio.h>

BOOL ReadMemoryFromProcess(DWORD pid, LPCVOID address, SIZE_T size) {
    // TODO: Open the target process
    HANDLE hProcess = ???;
    
    if (!hProcess) {
        printf("Failed to open process\\n");
        return FALSE;
    }
    
    // Buffer to store the data we read
    BYTE buffer[16] = {0};
    SIZE_T bytesRead = 0;
    
    // TODO: Read memory from the target process
    BOOL success = ???;
    
    if (success) {
        printf("Read %llu bytes:\\n", bytesRead);
        for (int i = 0; i < bytesRead; i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\\n");
    }
    
    CloseHandle(hProcess);
    return success;
}`,
      solution: `#include <windows.h>
#include <stdio.h>

BOOL ReadMemoryFromProcess(DWORD pid, LPCVOID address, SIZE_T size) {
    // Open process with VM_READ permission
    // PROCESS_VM_READ allows us to read memory
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ,  // Only request what we need
        FALSE,            // Don't inherit handle
        pid               // Target process ID
    );
    
    if (!hProcess) {
        printf("Failed to open process: %lu\\n", GetLastError());
        return FALSE;
    }
    
    BYTE buffer[16] = {0};
    SIZE_T bytesRead = 0;
    
    // ReadProcessMemory does the actual reading
    BOOL success = ReadProcessMemory(
        hProcess,    // Handle to process
        address,     // Address to read from
        buffer,      // Where to store the data
        size,        // How many bytes to read
        &bytesRead   // How many actually read
    );
    
    if (success) {
        printf("Read %llu bytes:\\n", bytesRead);
        for (SIZE_T i = 0; i < bytesRead; i++) {
            printf("%02X ", buffer[i]);
        }
        printf("\\n");
    } else {
        printf("ReadProcessMemory failed: %lu\\n", GetLastError());
    }
    
    CloseHandle(hProcess);
    return success;
}`,
      testCases: [
        "✓ Opens process with PROCESS_VM_READ",
        "✓ Uses ReadProcessMemory correctly",
        "✓ Handles errors and closes handle"
      ],
      explanation: "ReadProcessMemory is fundamental to process analysis. The key insight is that you need PROCESS_VM_READ access. This will fail if you try to read protected system processes or processes running with higher privileges."
    }
  ],
  "process-injection": [
    {
      id: "pi1",
      title: "Allocate Remote Memory",
      difficulty: "medium",
      points: 35,
      description: "Before injecting code, you need to allocate memory in the target process.",
      task: "Open a process and allocate 4096 bytes of executable memory in it.",
      hints: [
        "Use OpenProcess with PROCESS_VM_OPERATION | PROCESS_VM_WRITE",
        "VirtualAllocEx allocates in another process",
        "PAGE_EXECUTE_READWRITE allows code execution"
      ],
      starterCode: `#include <windows.h>
#include <stdio.h>

LPVOID AllocateRemoteMemory(DWORD pid, SIZE_T size) {
    // TODO: Open the target process with correct access rights
    HANDLE hProcess = OpenProcess(
        ???, // What access do we need?
        FALSE,
        pid
    );
    
    if (!hProcess) return NULL;
    
    // TODO: Allocate memory in the remote process
    LPVOID remoteAddr = VirtualAllocEx(
        ???, // Process handle
        ???, // Let Windows choose the address
        ???, // Size to allocate
        ???, // Allocation type
        ???  // Memory protection
    );
    
    if (remoteAddr) {
        printf("Allocated at: 0x%p\\n", remoteAddr);
    }
    
    // NOTE: Don't close the handle yet in real code!
    // You'd need it for the next step (writing)
    
    return remoteAddr;
}`,
      solution: `#include <windows.h>
#include <stdio.h>

LPVOID AllocateRemoteMemory(DWORD pid, SIZE_T size) {
    // We need these access rights:
    // PROCESS_VM_OPERATION - to allocate
    // PROCESS_VM_WRITE - to write later
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE,
        pid
    );
    
    if (!hProcess) {
        printf("OpenProcess failed: %lu\\n", GetLastError());
        return NULL;
    }
    
    // VirtualAllocEx = VirtualAlloc for another process
    LPVOID remoteAddr = VirtualAllocEx(
        hProcess,                    // Target process
        NULL,                        // Let Windows pick address
        size,                        // How much memory
        MEM_COMMIT | MEM_RESERVE,   // Reserve AND commit
        PAGE_EXECUTE_READWRITE      // RWX - can execute code
    );
    
    if (remoteAddr) {
        printf("Allocated %llu bytes at: 0x%p\\n", size, remoteAddr);
    } else {
        printf("VirtualAllocEx failed: %lu\\n", GetLastError());
    }
    
    return remoteAddr;
}`,
      testCases: [
        "✓ Opens process with VM_OPERATION | VM_WRITE",
        "✓ Uses MEM_COMMIT | MEM_RESERVE",
        "✓ Uses PAGE_EXECUTE_READWRITE for code"
      ],
      explanation: "VirtualAllocEx is the first step in process injection. PAGE_EXECUTE_READWRITE is suspicious and often flagged by security tools. In real scenarios, you'd allocate as RW, write your code, then change to RX with VirtualProtectEx."
    }
  ],
  syscalls: [
    {
      id: "sc1",
      title: "Find a Syscall Number",
      difficulty: "hard",
      points: 45,
      description: "Syscall numbers (SSNs) change between Windows versions. Learn to find them dynamically.",
      task: "Read the first 20 bytes of NtAllocateVirtualMemory and find the syscall number.",
      hints: [
        "GetProcAddress gets the function address from ntdll",
        "In x64, the pattern is: mov r10, rcx; mov eax, SSN",
        "The SSN is at offset 4 from the start"
      ],
      starterCode: `#include <windows.h>
#include <stdio.h>

DWORD GetSyscallNumber(LPCSTR functionName) {
    // TODO: Get handle to ntdll.dll
    HMODULE ntdll = ???;
    
    // TODO: Get address of the function
    FARPROC funcAddr = ???;
    
    if (!funcAddr) return -1;
    
    // Read the bytes at the function start
    BYTE* bytes = (BYTE*)funcAddr;
    
    printf("First 10 bytes: ");
    for (int i = 0; i < 10; i++) {
        printf("%02X ", bytes[i]);
    }
    printf("\\n");
    
    // TODO: Extract syscall number
    // Hint: Look at bytes[4] and bytes[5] for the SSN
    DWORD ssn = ???;
    
    return ssn;
}`,
      solution: `#include <windows.h>
#include <stdio.h>

DWORD GetSyscallNumber(LPCSTR functionName) {
    // ntdll is always loaded - get its handle
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    
    if (!ntdll) {
        printf("Failed to get ntdll\\n");
        return -1;
    }
    
    // Get the function address
    FARPROC funcAddr = GetProcAddress(ntdll, functionName);
    
    if (!funcAddr) {
        printf("Failed to find %s\\n", functionName);
        return -1;
    }
    
    BYTE* bytes = (BYTE*)funcAddr;
    
    printf("Function: %s at 0x%p\\n", functionName, funcAddr);
    printf("First 10 bytes: ");
    for (int i = 0; i < 10; i++) {
        printf("%02X ", bytes[i]);
    }
    printf("\\n");
    
    // x64 syscall stub pattern:
    // 4C 8B D1         mov r10, rcx
    // B8 XX XX 00 00   mov eax, SSN (XX XX is the syscall number)
    // 
    // So the SSN is a WORD (2 bytes) at offset 4
    
    DWORD ssn = *(WORD*)(bytes + 4);
    
    printf("Syscall Number: %lu (0x%X)\\n", ssn, ssn);
    
    return ssn;
}

// Usage: GetSyscallNumber("NtAllocateVirtualMemory");`,
      testCases: [
        "✓ Gets ntdll handle with GetModuleHandleA",
        "✓ Uses GetProcAddress for function address",
        "✓ Correctly extracts SSN from offset 4"
      ],
      explanation: "The syscall stub in ntdll follows a predictable pattern. On x64, bytes 0-2 are 'mov r10, rcx', byte 3 is 'mov eax', and bytes 4-5 contain the actual syscall number. This technique is used in Hell's Gate and similar tools."
    }
  ],
  pinvoke: [
    {
      id: "pv1",
      title: "Your First P/Invoke",
      difficulty: "easy",
      points: 20,
      description: "P/Invoke lets C# call Windows API functions directly. Master the DllImport attribute!",
      task: "Use P/Invoke to call GetCurrentProcessId() and MessageBoxA from C#.",
      hints: [
        "[DllImport(\"kernel32.dll\")] for kernel32 functions",
        "[DllImport(\"user32.dll\")] for MessageBox",
        "Use 'static extern' with the correct return type"
      ],
      starterCode: `using System;
using System.Runtime.InteropServices;

class Program {
    // TODO: Declare GetCurrentProcessId
    // Hint: It's in kernel32.dll and returns uint
    ???
    
    // TODO: Declare MessageBoxA
    // Hint: It's in user32.dll
    // int MessageBoxA(IntPtr hWnd, string text, string caption, uint type)
    ???
    
    static void Main() {
        uint pid = GetCurrentProcessId();
        Console.WriteLine($"My PID: {pid}");
        
        MessageBoxA(IntPtr.Zero, "Hello from P/Invoke!", "Success", 0);
    }
}`,
      solution: `using System;
using System.Runtime.InteropServices;

class Program {
    // P/Invoke declaration for GetCurrentProcessId
    // Lives in kernel32.dll, returns a uint (DWORD in C)
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentProcessId();
    
    // P/Invoke declaration for MessageBoxA
    // Lives in user32.dll
    // Returns int, takes: window handle, text, caption, type
    [DllImport("user32.dll", CharSet = CharSet.Ansi)]
    static extern int MessageBoxA(
        IntPtr hWnd,    // Parent window (0 = none)
        string lpText,  // Message text
        string lpCaption, // Title bar text  
        uint uType      // Button/icon flags
    );
    
    static void Main() {
        uint pid = GetCurrentProcessId();
        Console.WriteLine($"My PID: {pid}");
        
        // 0 = MB_OK (just an OK button)
        MessageBoxA(IntPtr.Zero, "Hello from P/Invoke!", "Success", 0);
    }
}`,
      testCases: [
        "✓ Correct DllImport attributes",
        "✓ Proper 'static extern' declarations",
        "✓ Matching parameter and return types"
      ],
      explanation: "P/Invoke is the bridge between managed C# and native Windows code. The key is getting the types right: DWORD→uint, HANDLE→IntPtr, BOOL→bool. CharSet.Ansi uses the 'A' versions of functions (ANSI strings)."
    }
  ],
  evasion: [
    {
      id: "ev1",
      title: "Detect Virtual Machine",
      difficulty: "medium",
      points: 30,
      description: "Security analysts often run malware in VMs. Learn to detect this!",
      task: "Write code that checks common signs of running in a virtual machine.",
      hints: [
        "Check for VM-related registry keys",
        "Look for VM processes like vmtoolsd.exe",
        "Check system manufacturer in WMI"
      ],
      starterCode: `#include <windows.h>
#include <stdio.h>

BOOL CheckVMRegistry() {
    HKEY hKey;
    // Try to open VMware registry key
    LONG result = RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        ???, // VMware stores info here
        0,
        KEY_READ,
        &hKey
    );
    
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE; // Found VMware!
    }
    
    return FALSE;
}

BOOL CheckVMProcesses() {
    // TODO: Use CreateToolhelp32Snapshot to look for
    // vmtoolsd.exe, vmwaretray.exe, vboxservice.exe
    return FALSE;
}

int main() {
    printf("VM Detection Results:\\n");
    printf("Registry Check: %s\\n", 
        CheckVMRegistry() ? "VM DETECTED" : "Clean");
    printf("Process Check: %s\\n",
        CheckVMProcesses() ? "VM DETECTED" : "Clean");
    return 0;
}`,
      solution: `#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

BOOL CheckVMRegistry() {
    HKEY hKey;
    
    // VMware registry key
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\\\VMware, Inc.\\\\VMware Tools",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    // VirtualBox registry key
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }
    
    return FALSE;
}

BOOL CheckVMProcesses() {
    const char* vmProcesses[] = {
        "vmtoolsd.exe",
        "vmwaretray.exe", 
        "vboxservice.exe",
        "vboxtray.exe"
    };
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    
    PROCESSENTRY32A pe32;
    pe32.dwSize = sizeof(pe32);
    
    if (Process32FirstA(hSnap, &pe32)) {
        do {
            // Convert to lowercase for comparison
            _strlwr(pe32.szExeFile);
            
            for (int i = 0; i < 4; i++) {
                if (strstr(pe32.szExeFile, vmProcesses[i])) {
                    CloseHandle(hSnap);
                    return TRUE;
                }
            }
        } while (Process32NextA(hSnap, &pe32));
    }
    
    CloseHandle(hSnap);
    return FALSE;
}

int main() {
    printf("=== VM Detection ===\\n\\n");
    printf("Registry Check: %s\\n", 
        CheckVMRegistry() ? "VM DETECTED!" : "Clean");
    printf("Process Check: %s\\n",
        CheckVMProcesses() ? "VM DETECTED!" : "Clean");
    return 0;
}`,
      testCases: [
        "✓ Checks VMware registry key",
        "✓ Checks VirtualBox registry key",
        "✓ Scans for VM-related processes"
      ],
      explanation: "VM detection is a cat-and-mouse game. This covers basic checks, but sophisticated analysis environments will spoof these indicators. Production malware uses many more checks: MAC addresses, CPUID, timing attacks, etc."
    }
  ],
  shellcode: [
    {
      id: "sh1",
      title: "Execute Shellcode in Memory",
      difficulty: "hard",
      points: 50,
      description: "The classic technique: allocate memory, copy shellcode, execute it.",
      task: "Write a shellcode loader that executes a simple 'ret' (return) instruction.",
      hints: [
        "VirtualAlloc with PAGE_EXECUTE_READWRITE",
        "memcpy to copy the shellcode bytes",
        "Cast the address to a function pointer and call it"
      ],
      starterCode: `#include <windows.h>
#include <stdio.h>

int main() {
    // Simple shellcode: just returns immediately
    // 0xC3 = 'ret' instruction in x64
    unsigned char shellcode[] = { 0xC3 };
    
    // TODO: Allocate executable memory
    LPVOID mem = VirtualAlloc(
        ???, // Let Windows choose
        ???, // Size needed
        ???, // Allocation type
        ???  // Must be executable!
    );
    
    if (!mem) {
        printf("Allocation failed\\n");
        return 1;
    }
    
    // TODO: Copy shellcode to allocated memory
    ???
    
    printf("Executing shellcode at: 0x%p\\n", mem);
    
    // TODO: Execute the shellcode
    // Hint: Cast to function pointer and call
    ???
    
    printf("Shellcode executed successfully!\\n");
    
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}`,
      solution: `#include <windows.h>
#include <stdio.h>
#include <string.h>

int main() {
    // Simple shellcode: just returns immediately
    // 0xC3 = 'ret' instruction in x64
    unsigned char shellcode[] = { 0xC3 };
    SIZE_T shellcodeSize = sizeof(shellcode);
    
    // Allocate memory that can be executed
    LPVOID mem = VirtualAlloc(
        NULL,                        // Let Windows choose address
        shellcodeSize,               // Just enough for our shellcode
        MEM_COMMIT | MEM_RESERVE,   // Reserve and commit
        PAGE_EXECUTE_READWRITE      // RWX permissions
    );
    
    if (!mem) {
        printf("Allocation failed: %lu\\n", GetLastError());
        return 1;
    }
    
    printf("Allocated %llu bytes at: 0x%p\\n", shellcodeSize, mem);
    
    // Copy shellcode to executable memory
    memcpy(mem, shellcode, shellcodeSize);
    
    printf("Executing shellcode...\\n");
    
    // Cast to function pointer and execute
    // void (*)() = pointer to function taking nothing, returning nothing
    typedef void (*ShellcodeFunc)();
    ShellcodeFunc run = (ShellcodeFunc)mem;
    run();
    
    printf("Shellcode executed successfully!\\n");
    
    // Clean up
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}`,
      testCases: [
        "✓ Allocates with PAGE_EXECUTE_READWRITE",
        "✓ Copies shellcode with memcpy",
        "✓ Uses function pointer to execute"
      ],
      explanation: "This is the simplest shellcode loader. In practice: (1) PAGE_EXECUTE_READWRITE is suspicious - use VirtualProtect to change permissions, (2) The shellcode would do something useful like spawn a shell, (3) You'd want to clean up your tracks."
    }
  ],
  labs: [
    {
      id: "lab1",
      title: "Build a Process Lister",
      difficulty: "easy",
      points: 25,
      description: "Create a simple tool that shows all running processes with their details.",
      task: "Build a process lister that shows PID, name, and parent PID for all processes.",
      hints: [
        "Combine CreateToolhelp32Snapshot with Process32First/Next",
        "PROCESSENTRY32 has th32ParentProcessID field",
        "Format output nicely with printf column widths"
      ],
      starterCode: `#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

void ListProcesses() {
    printf("%-8s %-8s %-30s\\n", "PID", "PPID", "Name");
    printf("----------------------------------------\\n");
    
    // TODO: Create snapshot
    // TODO: Iterate and print each process
    // Format: printf("%-8lu %-8lu %-30ws\\n", pid, ppid, name);
}

int main() {
    printf("\\n=== Process Lister ===\\n\\n");
    ListProcesses();
    return 0;
}`,
      solution: `#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

void ListProcesses() {
    printf("%-8s %-8s %-30s\\n", "PID", "PPID", "Name");
    printf("%-8s %-8s %-30s\\n", "---", "----", "----");
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        printf("Failed to create snapshot: %lu\\n", GetLastError());
        return;
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    
    if (Process32FirstW(hSnap, &pe32)) {
        do {
            wprintf(L"%-8lu %-8lu %-30s\\n",
                pe32.th32ProcessID,
                pe32.th32ParentProcessID,
                pe32.szExeFile
            );
        } while (Process32NextW(hSnap, &pe32));
    }
    
    CloseHandle(hSnap);
}

int main() {
    printf("\\n=== Process Lister v1.0 ===\\n\\n");
    ListProcesses();
    printf("\\n[Done]\\n");
    return 0;
}`,
      testCases: [
        "✓ Creates process snapshot",
        "✓ Shows PID, PPID, and name",
        "✓ Clean formatted output"
      ],
      explanation: "This is the foundation of process monitoring tools. The parent PID (PPID) is useful for understanding process relationships - for example, cmd.exe spawned by explorer.exe vs spawned by malware."
    }
  ]
};

const getDifficultyColor = (difficulty: string) => {
  switch (difficulty) {
    case "easy": return "bg-success/20 text-success border-success/30";
    case "medium": return "bg-warning/20 text-warning border-warning/30";
    case "hard": return "bg-destructive/20 text-destructive border-destructive/30";
    default: return "bg-muted text-muted-foreground";
  }
};

const ChallengeSection = ({ moduleId }: ChallengeSectionProps) => {
  const [expandedChallenge, setExpandedChallenge] = useState<string | null>(null);
  const [showHints, setShowHints] = useState<Record<string, number>>({});
  const [showSolution, setShowSolution] = useState<Record<string, boolean>>({});
  const [userCode, setUserCode] = useState<Record<string, string>>({});
  const [completed, setCompleted] = useState<Record<string, boolean>>({});
  const { toast } = useToast();

  const moduleChallenges = challenges[moduleId] || [];
  
  const totalPoints = moduleChallenges.reduce((sum, c) => sum + c.points, 0);
  const earnedPoints = moduleChallenges.reduce((sum, c) => completed[c.id] ? sum + c.points : sum, 0);

  const revealHint = (challengeId: string, maxHints: number) => {
    setShowHints(prev => ({
      ...prev,
      [challengeId]: Math.min((prev[challengeId] || 0) + 1, maxHints)
    }));
  };

  const toggleSolution = (challengeId: string) => {
    setShowSolution(prev => ({ ...prev, [challengeId]: !prev[challengeId] }));
  };

  const markComplete = (challengeId: string, points: number) => {
    setCompleted(prev => ({ ...prev, [challengeId]: true }));
    toast({
      title: "🎉 Challenge Completed!",
      description: `You earned ${points} points!`,
    });
  };

  const resetChallenge = (challengeId: string, starterCode: string) => {
    setUserCode(prev => ({ ...prev, [challengeId]: starterCode }));
    setShowHints(prev => ({ ...prev, [challengeId]: 0 }));
    setShowSolution(prev => ({ ...prev, [challengeId]: false }));
  };

  if (moduleChallenges.length === 0) {
    return (
      <Card className="p-8 bg-card/50 border-border/50 text-center">
        <Target className="h-12 w-12 mx-auto mb-4 text-muted-foreground/50" />
        <h3 className="text-lg font-semibold text-foreground mb-2">Challenges Coming Soon</h3>
        <p className="text-muted-foreground">We're working on challenges for this module.</p>
      </Card>
    );
  }

  return (
    <Card className="bg-card/80 border-border/50 overflow-hidden shadow-xl animate-fade-in">
      {/* Header */}
      <div className="bg-gradient-to-r from-primary/20 via-primary/10 to-transparent p-6 border-b border-border/50">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-xl bg-primary/20 shadow-glow-sm">
              <Trophy className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-foreground">Coding Challenges</h3>
              <p className="text-sm text-muted-foreground">Test your skills with hands-on exercises</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="text-2xl font-bold text-primary">{earnedPoints}/{totalPoints}</div>
              <div className="text-xs text-muted-foreground">Points Earned</div>
            </div>
            <div className="h-12 w-12 rounded-full bg-primary/20 flex items-center justify-center">
              <Flame className={`h-6 w-6 ${earnedPoints > 0 ? 'text-warning animate-pulse' : 'text-muted-foreground'}`} />
            </div>
          </div>
        </div>
      </div>

      {/* Challenges List */}
      <ScrollArea className="h-[500px]">
        <div className="p-4 space-y-4">
          {moduleChallenges.map((challenge) => {
            const isExpanded = expandedChallenge === challenge.id;
            const hintsRevealed = showHints[challenge.id] || 0;
            const solutionVisible = showSolution[challenge.id] || false;
            const isCompleted = completed[challenge.id] || false;
            const currentCode = userCode[challenge.id] || challenge.starterCode;

            return (
              <Card 
                key={challenge.id} 
                className={`overflow-hidden transition-all duration-300 ${
                  isCompleted 
                    ? 'border-success/50 bg-success/5' 
                    : 'border-border/50 hover:border-primary/30'
                }`}
              >
                {/* Challenge Header */}
                <button
                  onClick={() => setExpandedChallenge(isExpanded ? null : challenge.id)}
                  className="w-full p-4 flex items-center justify-between hover:bg-muted/30 transition-colors"
                >
                  <div className="flex items-center gap-4">
                    {isCompleted ? (
                      <CheckCircle2 className="h-6 w-6 text-success" />
                    ) : (
                      <Target className="h-6 w-6 text-muted-foreground" />
                    )}
                    <div className="text-left">
                      <h4 className="font-semibold text-foreground">{challenge.title}</h4>
                      <p className="text-sm text-muted-foreground line-clamp-1">{challenge.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <Badge className={`${getDifficultyColor(challenge.difficulty)}`}>
                      {challenge.difficulty}
                    </Badge>
                    <Badge variant="outline" className="bg-primary/10 border-primary/30">
                      <Zap className="h-3 w-3 mr-1" />
                      {challenge.points} pts
                    </Badge>
                    {isExpanded ? <ChevronUp className="h-5 w-5" /> : <ChevronDown className="h-5 w-5" />}
                  </div>
                </button>

                {/* Expanded Content */}
                {isExpanded && (
                  <div className="border-t border-border/50 p-4 space-y-4 animate-fade-in">
                    {/* Task Description */}
                    <div className="p-4 rounded-lg bg-muted/30 border border-border/30">
                      <h5 className="font-semibold text-foreground mb-2 flex items-center gap-2">
                        <Target className="h-4 w-4 text-primary" />
                        Your Task
                      </h5>
                      <p className="text-foreground/90">{challenge.task}</p>
                    </div>

                    {/* Code Editor */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium text-foreground">Your Code</span>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => resetChallenge(challenge.id, challenge.starterCode)}
                          className="text-xs"
                        >
                          <RotateCcw className="h-3 w-3 mr-1" />
                          Reset
                        </Button>
                      </div>
                      <Textarea
                        value={currentCode}
                        onChange={(e) => setUserCode(prev => ({ ...prev, [challenge.id]: e.target.value }))}
                        className="min-h-[200px] font-mono text-sm bg-code-bg border-border/50"
                        placeholder="Write your solution here..."
                      />
                    </div>

                    {/* Hints Section */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-sm font-medium text-foreground flex items-center gap-2">
                          <Lightbulb className="h-4 w-4 text-warning" />
                          Hints ({hintsRevealed}/{challenge.hints.length})
                        </span>
                        {hintsRevealed < challenge.hints.length && (
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => revealHint(challenge.id, challenge.hints.length)}
                            className="text-xs"
                          >
                            Reveal Hint
                          </Button>
                        )}
                      </div>
                      {hintsRevealed > 0 && (
                        <div className="space-y-2">
                          {challenge.hints.slice(0, hintsRevealed).map((hint, idx) => (
                            <div key={idx} className="p-3 rounded-lg bg-warning/10 border border-warning/20 text-sm">
                              <span className="font-medium text-warning">Hint {idx + 1}:</span>{" "}
                              <span className="text-foreground/90">{hint}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Solution Toggle */}
                    <div className="space-y-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => toggleSolution(challenge.id)}
                        className="w-full"
                      >
                        {solutionVisible ? <EyeOff className="h-4 w-4 mr-2" /> : <Eye className="h-4 w-4 mr-2" />}
                        {solutionVisible ? "Hide Solution" : "Show Solution"}
                      </Button>
                      
                      {solutionVisible && (
                        <div className="space-y-3 animate-fade-in">
                          <div className="p-4 rounded-lg bg-code-bg border border-border/50">
                            <h5 className="font-semibold text-foreground mb-2">Solution</h5>
                            <pre className="text-sm text-primary/90 whitespace-pre-wrap overflow-x-auto">
                              {challenge.solution}
                            </pre>
                          </div>
                          <div className="p-4 rounded-lg bg-concept/20 border border-concept/30">
                            <h5 className="font-semibold text-concept mb-2">Explanation</h5>
                            <p className="text-sm text-foreground/90">{challenge.explanation}</p>
                          </div>
                          <div className="p-4 rounded-lg bg-success/10 border border-success/30">
                            <h5 className="font-semibold text-success mb-2">Test Cases</h5>
                            <ul className="space-y-1">
                              {challenge.testCases.map((test, idx) => (
                                <li key={idx} className="text-sm text-foreground/90">{test}</li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Complete Button */}
                    {!isCompleted && (
                      <Button
                        onClick={() => markComplete(challenge.id, challenge.points)}
                        className="w-full gap-2 shadow-glow-sm hover:shadow-glow-md"
                      >
                        <CheckCircle2 className="h-4 w-4" />
                        Mark as Complete (+{challenge.points} pts)
                      </Button>
                    )}
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      </ScrollArea>
    </Card>
  );
};

export default ChallengeSection;
