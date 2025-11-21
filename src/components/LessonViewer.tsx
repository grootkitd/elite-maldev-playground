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
          content: `Think of Windows data types as a special language Microsoft created to make sure programs work correctly on all computers (old and new, 32-bit and 64-bit).

**The Problem:** If you use regular 'int', it might be different sizes on different computers.
**The Solution:** Windows types like DWORD are ALWAYS the same size everywhere.`,
          tip: `Think of these types as "guaranteed sizes" - DWORD is ALWAYS 32 bits, no matter what computer you're on.`,
          concepts: [
            {
              label: "BYTE",
              explanation: "8 bits (0-255) - Use for small numbers or single characters"
            },
            {
              label: "WORD",
              explanation: "16 bits (0-65,535) - Rarely used today"
            },
            {
              label: "DWORD",
              explanation: "32 bits - Most common, use for IDs, sizes, counts"
            },
            {
              label: "QWORD",
              explanation: "64 bits - Use for very large numbers"
            },
            {
              label: "HANDLE",
              explanation: "A reference ticket to a Windows resource (file, process, etc.)"
            }
          ],
          example: {
            title: "Simple Example - Using Windows Types",
            description: "Here's how you use these types in real code:",
            code: `#include <windows.h>
#include <stdio.h>

int main() {
    // Process ID - use DWORD
    DWORD processId = 1234;
    
    // File size - use DWORD for sizes
    DWORD fileSize = 2048;  // 2 KB
    
    // Handle to a file
    HANDLE hFile = CreateFileW(
        L"test.txt",              // File name
        GENERIC_READ,             // We want to read
        FILE_SHARE_READ,          // Others can read too
        NULL,                     // Security (default)
        OPEN_EXISTING,            // File must exist
        FILE_ATTRIBUTE_NORMAL,    // Normal file
        NULL                      // No template
    );
    
    // Always check if it worked!
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file!\\n");
        return 1;
    }
    
    printf("File opened successfully!\\n");
    
    // IMPORTANT: Always close handles!
    CloseHandle(hFile);
    
    return 0;
}`,
            language: "c"
          },
          warning: `Never forget to call CloseHandle()! If you don't close handles, your program will leak resources and eventually fail.`
        },
        {
          title: "Handles - Your Access Tickets to Windows",
          content: `A HANDLE is like a ticket that Windows gives you to use something. You can't access Windows resources directly (that would be unsafe!), so Windows gives you a "ticket" instead.

**Real World Analogy:**
Think of a coat check at a restaurant:
• You give them your coat
• They give you a ticket (HANDLE)
• You can't go behind the counter (security!)
• When you show the ticket, they give you your coat back
• The ticket is only valid in that restaurant (process)

Windows handles work the same way!`,
          tip: `Handles are like claim tickets - they're only valid in your program. A handle from one program won't work in another program.`,
          example: {
            title: "Working with Process Handles",
            description: "Let's open another process and work with it:",
            code: `#include <windows.h>
#include <stdio.h>

int main() {
    // Step 1: Get the Process ID you want to work with
    DWORD targetPID = 1234;  // Replace with real PID
    
    // Step 2: Ask Windows for a handle to that process
    printf("[*] Opening process %lu...\\n", targetPID);
    
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION,  // What we want to do
        FALSE,                      // Don't inherit to child processes
        targetPID                   // Which process
    );
    
    // Step 3: Check if it worked
    if (hProcess == NULL) {
        // Get the error code
        DWORD error = GetLastError();
        printf("[ERROR] Failed! Error code: %lu\\n", error);
        
        // Common errors:
        if (error == 5) {
            printf("  -> Access Denied. Try running as Administrator.\\n");
        }
        return 1;
    }
    
    printf("[SUCCESS] Got handle: 0x%p\\n", hProcess);
    
    // Step 4: Do something with it
    // (Query information, read memory, etc.)
    
    // Step 5: ALWAYS close the handle when done!
    CloseHandle(hProcess);
    printf("[*] Handle closed. All done!\\n");
    
    return 0;
}`,
            language: "c"
          },
          concepts: [
            {
              label: "HANDLE",
              explanation: "A reference to a Windows object (file, process, thread, etc.)"
            },
            {
              label: "OpenProcess",
              explanation: "Gets a handle to an existing process"
            },
            {
              label: "CloseHandle",
              explanation: "Releases the handle when you're done"
            },
            {
              label: "GetLastError",
              explanation: "Gets the error code when something fails"
            }
          ]
        },
        {
          title: "Error Handling - When Things Go Wrong",
          content: `In Windows programming, things fail ALL THE TIME. A file doesn't exist, you don't have permission, a process ended, etc. You MUST check for errors!

**The Pattern:**
1. Call a Windows function
2. Check if it failed
3. Call GetLastError() to find out why
4. Handle the error appropriately`,
          warning: `Never ignore return values! If you don't check for errors, your program will crash in mysterious ways.`,
          example: {
            title: "Proper Error Handling",
            description: "Always check return values and handle errors:",
            code: `#include <windows.h>
#include <stdio.h>

// Helper function to print error messages
void PrintError(const char* operation) {
    DWORD error = GetLastError();
    printf("[ERROR] %s failed with error %lu\\n", operation, error);
    
    // Get Windows' description of the error
    char* message = NULL;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        error,
        0,
        (LPSTR)&message,
        0,
        NULL
    );
    
    if (message) {
        printf("  Description: %s\\n", message);
        LocalFree(message);
    }
}

int main() {
    // Example: Try to open a file
    HANDLE hFile = CreateFileW(
        L"nonexistent.txt",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    // Check if it failed
    if (hFile == INVALID_HANDLE_VALUE) {
        PrintError("CreateFile");
        
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            printf("\\n[TIP] The file doesn't exist!\\n");
        } else if (error == ERROR_ACCESS_DENIED) {
            printf("\\n[TIP] You don't have permission!\\n");
        }
        
        return 1;
    }
    
    // Success path
    printf("[SUCCESS] File opened!\\n");
    CloseHandle(hFile);
    return 0;
}`,
            language: "c"
          },
          tip: `Common error codes: ERROR_SUCCESS (0), ERROR_ACCESS_DENIED (5), ERROR_FILE_NOT_FOUND (2), ERROR_INVALID_PARAMETER (87)`
        },
        {
          title: "Strings - ASCII vs Unicode",
          content: `Windows has TWO types of strings because it supports all languages worldwide:

**ASCII (CHAR, LPSTR):**
• 1 byte per character
• Only English and basic characters
• Old way, still used sometimes

**Unicode (WCHAR, LPWSTR):**
• 2 bytes per character  
• Supports ALL languages (Chinese, Arabic, Emoji, etc.)
• Modern way - USE THIS!`,
          tip: `Always use Unicode (wide strings with 'W' suffix). Put 'L' before string literals: L"Hello"`,
          example: {
            title: "String Examples",
            description: "Working with both types of strings:",
            code: `#include <windows.h>
#include <stdio.h>

int main() {
    // ASCII string (old way)
    const char* asciiStr = "Hello";
    printf("ASCII: %s\\n", asciiStr);
    
    // Unicode string (modern way) - note the L prefix!
    const wchar_t* unicodeStr = L"Hello 世界 🌍";
    wprintf(L"Unicode: %s\\n", unicodeStr);
    
    // Windows API - most functions have A and W versions
    
    // MessageBoxA - ASCII version
    MessageBoxA(NULL, "ASCII Message", "Title", MB_OK);
    
    // MessageBoxW - Unicode version (USE THIS!)
    MessageBoxW(NULL, L"Unicode Message 你好", L"Title", MB_OK);
    
    // File operations with Unicode
    HANDLE hFile = CreateFileW(  // Note the W suffix!
        L"test_文件.txt",         // Filename with Chinese characters
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile != INVALID_HANDLE_VALUE) {
        printf("File created with Unicode name!\\n");
        CloseHandle(hFile);
    }
    
    return 0;
}`,
            language: "c"
          },
          warning: `Always match string types! Don't mix char* with WCHAR*. Use the 'W' version of Windows functions with Unicode strings.`
        }
      ]
    },
    // windows-internals: {
    //   title: "Windows Internals",
    //   description: "Delve into the heart of the Windows operating system",
    //   sections: [
    //     {
    //       title: "Processes and Threads",
    //       content: `Processes are the containers for running programs, while threads are the units of execution within a process.`,
    //       example: {
    //         title: "Creating a Thread",
    //         description: "Example of creating a simple thread in C++:",
    //         code: `#include <iostream>
    // #include <thread>
    
    // void task() {
    //     std::cout << "Thread is running" << std::endl;
    // }
    
    // int main() {
    //     std::thread t(task);
    //     t.join();
    //     return 0;
    // }`,
    //         language: "cpp"
    //       }
    //     },
    //     {
    //       title: "Memory Management",
    //       content: `Windows uses virtual memory to manage memory allocation for processes.`,
    //       example: {
    //         title: "Allocating Memory",
    //         description: "Example of allocating memory using VirtualAlloc:",
    //         code: `#include <iostream>
    // #include <windows.h>
    
    // int main() {
    //     LPVOID addr = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    //     if (addr == NULL) {
    //         std::cerr << "Failed to allocate memory" << std::endl;
    //         return 1;
    //     }
    //     std::cout << "Memory allocated at: " << addr << std::endl;
    //     VirtualFree(addr, 0, MEM_RELEASE);
    //     return 0;
    // }`,
    //         language: "cpp"
    //       }
    //     }
    //   ]
    // },
    // networking: {
    //   title: "Networking with WinAPI",
    //   description: "Learn how to create network applications using WinAPI",
    //   sections: [
    //     {
    //       title: "Sockets",
    //       content: `Sockets are endpoints for network communication.`,
    //       example: {
    //         title: "Creating a Socket",
    //         description: "Example of creating a socket in C++:",
    //         code: `#include <iostream>
    // #include <winsock2.h>
    
    // #pragma comment(lib, "ws2_32.lib")
    
    // int main() {
    //     WSADATA wsaData;
    //     if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    //         std::cerr << "Failed to initialize Winsock" << std::endl;
    //         return 1;
    //     }
    
    //     SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    //     if (s == INVALID_SOCKET) {
    //         std::cerr << "Failed to create socket" << std::endl;
    //         WSACleanup();
    //         return 1;
    //     }
    
    //     std::cout << "Socket created" << std::endl;
    //     closesocket(s);
    //     WSACleanup();
    //     return 0;
    // }`,
    //         language: "cpp"
    //       }
    //     },
    //     {
    //       title: "HTTP Requests",
    //       content: `You can use WinAPI to make HTTP requests.`,
    //       example: {
    //         title: "Making an HTTP Request",
    //         description: "Example of making an HTTP request using WinHTTP:",
    //         code: `#include <iostream>
    // #include <winhttp.h>
    
    // #pragma comment(lib, "winhttp.lib")
    
    // int main() {
    //     HINTERNET hSession = WinHttpOpen(L"WinHTTP Example", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    //     if (hSession == NULL) {
    //         std::cerr << "Failed to open WinHTTP session" << std::endl;
    //         return 1;
    //     }
    
    //     HINTERNET hConnect = WinHttpConnect(hSession, L"example.com", INTERNET_DEFAULT_HTTP_PORT, 0);
    //     if (hConnect == NULL) {
    //         std::cerr << "Failed to connect to server" << std::endl;
    //         WinHttpCloseHandle(hSession);
    //         return 1;
    //     }
    
    //     HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    //     if (hRequest == NULL) {
    //         std::cerr << "Failed to open HTTP request" << std::endl;
    //         WinHttpCloseHandle(hConnect);
    //         WinHttpCloseHandle(hSession);
    //         return 1;
    //     }
    
    //     if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
    //         if (WinHttpReceiveResponse(hRequest, NULL)) {
    //             std::cout << "HTTP request successful" << std::endl;
    //         } else {
    //             std::cerr << "Failed to receive response" << std::endl;
    //         }
    //     } else {
    //         std::cerr << "Failed to send request" << std::endl;
    //     }
    
    //     WinHttpCloseHandle(hRequest);
    //     WinHttpCloseHandle(hConnect);
    //     WinHttpCloseHandle(hSession);
    //     return 0;
    // }`,
    //         language: "cpp"
    //       }
    //     }
    //   ]
    // }
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
