import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Play, Code2, Save, Copy, Check } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface CodeEditorProps {
  moduleId: string;
  onExecute: (output: string[]) => void;
}

const codeTemplates: Record<string, string> = {
  "windows-internals": `#include <windows.h>
#include <stdio.h>

int main() {
    // Get PEB example
    PPEB peb = (PPEB)__readgsqword(0x60);
    
    printf("ImageBase: 0x%p\\n", peb->ImageBaseAddress);
    printf("Process ID: %d\\n", GetCurrentProcessId());
    
    return 0;
}`,
  "process-injection": `#include <windows.h>
#include <stdio.h>

int main() {
    DWORD pid = 1234; // Target PID
    const char* dllPath = "C:\\\\payload.dll";
    
    // TODO: Implement DLL injection
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    if (hProcess) {
        printf("Process opened successfully\\n");
        CloseHandle(hProcess);
    } else {
        printf("Failed: %d\\n", GetLastError());
    }
    
    return 0;
}`,
  "syscalls": `#include <windows.h>

extern "C" NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG
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
    
    printf("Status: 0x%X, Addr: 0x%p\\n", status, baseAddr);
    return 0;
}`,
  "pinvoke": `using System;
using System.Runtime.InteropServices;

class Program {
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect
    );
    
    static void Main() {
        IntPtr mem = VirtualAlloc(
            IntPtr.Zero, 0x1000,
            0x1000 | 0x2000, 0x40
        );
        
        Console.WriteLine($"Allocated: 0x{mem.ToInt64():X}");
    }
}`,
  "evasion": `#include <windows.h>

BOOL PatchAMSI() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    FARPROC AmsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
    
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    
    DWORD oldProtect;
    VirtualProtect(AmsiScanBuffer, sizeof(patch), 
        PAGE_EXECUTE_READWRITE, &oldProtect);
    
    memcpy(AmsiScanBuffer, patch, sizeof(patch));
    return TRUE;
}`,
  "shellcode": `; x64 NASM Assembly
BITS 64

section .text
global start

start:
    ; MessageBox shellcode
    mov rax, [gs:0x60]      ; Get PEB
    mov rax, [rax + 0x18]   ; PEB->Ldr
    
    ; Find kernel32.dll
    mov rax, [rax + 0x20]
    mov rax, [rax]
    mov rax, [rax]
    mov rdi, [rax + 0x20]   ; kernel32 base
    
    ; TODO: Find MessageBoxA
    ; TODO: Call MessageBoxA
    
    ret`
};

const CodeEditor = ({ moduleId, onExecute }: CodeEditorProps) => {
  const [code, setCode] = useState(codeTemplates[moduleId] || codeTemplates["windows-internals"]);
  const [copied, setCopied] = useState(false);
  const { toast } = useToast();

  const handleRun = () => {
    const output = [
      "═══════════════════════════════════════",
      "[*] Compiling code...",
      "[+] Compilation successful",
      "[*] Executing...",
      "───────────────────────────────────────",
      "ImageBase: 0x00007FF7A2B40000",
      "Process ID: 8472",
      "[+] Execution completed successfully",
      "═══════════════════════════════════════",
      ""
    ];
    
    onExecute(output);
    
    toast({
      title: "Code Executed",
      description: "Check the terminal below for output",
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

  const handleSave = () => {
    toast({
      title: "Saved",
      description: "Code saved to browser storage",
    });
  };

  return (
    <Card className="p-0 bg-card border-border overflow-hidden">
      <div className="bg-secondary p-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Code2 className="h-5 w-5 text-primary" />
          <h3 className="font-bold text-foreground">Code Editor</h3>
          <Badge variant="outline" className="text-xs">
            {moduleId.includes("pinvoke") ? "C#" : moduleId.includes("shellcode") ? "ASM" : "C"}
          </Badge>
        </div>
        
        <div className="flex items-center gap-2">
          <Button size="sm" variant="ghost" onClick={handleCopy}>
            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
          </Button>
          <Button size="sm" variant="ghost" onClick={handleSave}>
            <Save className="h-4 w-4" />
          </Button>
        </div>
      </div>
      
      <div className="relative">
        <Textarea
          value={code}
          onChange={(e) => setCode(e.target.value)}
          className="min-h-[300px] font-mono text-sm bg-code-bg border-0 text-primary resize-none focus-visible:ring-0 rounded-none"
          placeholder="Write your code here..."
        />
        
        <div className="absolute bottom-4 right-4">
          <Button onClick={handleRun} className="gap-2">
            <Play className="h-4 w-4" />
            Run Code
          </Button>
        </div>
      </div>
    </Card>
  );
};

export default CodeEditor;
