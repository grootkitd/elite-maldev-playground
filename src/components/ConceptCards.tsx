import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { 
  Lightbulb, X, ChevronLeft, ChevronRight, 
  Code2, Terminal, Shield, AlertTriangle, CheckCircle2
} from "lucide-react";

interface ConceptCard {
  id: string;
  title: string;
  category: string;
  content: string;
  example?: string;
  relatedConcepts: string[];
}

interface ConceptCardsProps {
  moduleId: string;
}

const ConceptCards = ({ moduleId }: ConceptCardsProps) => {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [flipped, setFlipped] = useState(false);

  const conceptsByModule: Record<string, ConceptCard[]> = {
    fundamentals: [
      {
        id: "handles",
        title: "What is a Handle?",
        category: "Core Concept",
        content: "A handle is like a ticket number. When you open a file, create a window, or start a process, Windows gives you a number (handle) to reference it. You don't see what's behind it - you just use the number to interact with the resource.",
        example: "HANDLE hFile = CreateFile(...); // hFile might be 0x00000144 - just a number!",
        relatedConcepts: ["HANDLE", "CloseHandle", "INVALID_HANDLE_VALUE"]
      },
      {
        id: "dword",
        title: "Why DWORD instead of int?",
        category: "Data Types",
        content: "In C, 'int' can be 16, 32, or 64 bits depending on the compiler. DWORD is ALWAYS 32 bits on Windows. This consistency is crucial when working with the Windows API which expects exact sizes.",
        example: "DWORD pid = GetCurrentProcessId(); // Always 32-bit unsigned",
        relatedConcepts: ["WORD", "QWORD", "SIZE_T", "ULONG_PTR"]
      },
      {
        id: "unicode",
        title: "Why W and A Functions?",
        category: "Strings",
        content: "Windows has two versions of most functions: 'A' for ANSI (ASCII, 8-bit characters) and 'W' for Wide (Unicode, 16-bit characters). Always use 'W' versions for proper international text support.",
        example: "CreateFileW(L\"文件.txt\", ...); // L prefix for wide strings",
        relatedConcepts: ["LPSTR", "LPWSTR", "TCHAR", "TEXT() macro"]
      },
      {
        id: "getlasterror",
        title: "How to Debug Windows Errors",
        category: "Error Handling",
        content: "When a Windows function fails, it sets an internal error code. Call GetLastError() IMMEDIATELY after the failure to retrieve it. Any other Windows call might change it!",
        example: "if (!success) { DWORD err = GetLastError(); } // Call right away!",
        relatedConcepts: ["FormatMessage", "ERROR_SUCCESS", "SetLastError"]
      }
    ],
    shellcode: [
      {
        id: "pic",
        title: "Position Independent Code",
        category: "Core Concept",
        content: "Shellcode must work no matter WHERE in memory it's loaded. This means no hardcoded addresses! Instead, resolve addresses dynamically at runtime using techniques like PEB walking.",
        example: "// Bad: call 0x7FFFFFFF  // Good: call [rax+offset]",
        relatedConcepts: ["PEB", "RIP-relative addressing", "Dynamic resolution"]
      },
      {
        id: "stages",
        title: "Staged vs Stageless",
        category: "Architecture",
        content: "Staged: Small loader (stager) fetches the real payload over network. Stageless: Entire payload in one piece. Staged = smaller initial size, but network dependency. Stageless = larger but self-contained.",
        example: "Stager: 300 bytes → downloads → 50KB payload",
        relatedConcepts: ["Meterpreter", "Beacon", "Loader"]
      }
    ],
    evasion: [
      {
        id: "hooks",
        title: "What are EDR Hooks?",
        category: "Detection",
        content: "EDRs inject code at the start of sensitive functions (like NtAllocateVirtualMemory) to inspect calls before they happen. This 'hook' redirects to EDR code first, then the original function.",
        example: "Original: mov r10,rcx → Hooked: jmp EDR_Scanner",
        relatedConcepts: ["Unhooking", "Inline hooks", "IAT hooks"]
      },
      {
        id: "syscalls",
        title: "Why Direct Syscalls?",
        category: "Evasion",
        content: "EDR hooks live in user-mode DLLs. By using the 'syscall' instruction directly (bypassing ntdll.dll), you skip the hooks entirely. The challenge is knowing the correct syscall numbers.",
        example: "mov eax, SSN; syscall; // Skip ntdll hooks!",
        relatedConcepts: ["SSN", "Hell's Gate", "Indirect Syscalls"]
      }
    ]
  };

  const concepts = conceptsByModule[moduleId] || conceptsByModule.fundamentals;
  const currentConcept = concepts[currentIndex];

  const nextCard = () => {
    setFlipped(false);
    setTimeout(() => {
      setCurrentIndex((prev) => (prev + 1) % concepts.length);
    }, 150);
  };

  const prevCard = () => {
    setFlipped(false);
    setTimeout(() => {
      setCurrentIndex((prev) => (prev - 1 + concepts.length) % concepts.length);
    }, 150);
  };

  return (
    <Card className="p-4 glass">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-accent/20">
            <Lightbulb className="h-4 w-4 text-accent" />
          </div>
          <h3 className="font-semibold text-sm">Key Concepts</h3>
        </div>
        <Badge variant="outline" className="text-xs">
          {currentIndex + 1}/{concepts.length}
        </Badge>
      </div>

      {/* Flashcard */}
      <div 
        className={`
          relative min-h-[200px] p-4 rounded-lg border cursor-pointer
          transition-all duration-300 transform
          ${flipped 
            ? 'bg-primary/5 border-primary/30' 
            : 'bg-secondary/30 border-border/50'
          }
        `}
        onClick={() => setFlipped(!flipped)}
      >
        {!flipped ? (
          /* Front of card */
          <div className="space-y-3 animate-fade-in">
            <Badge variant="outline" className="text-[10px] bg-primary/10 text-primary border-primary/30">
              {currentConcept.category}
            </Badge>
            <h4 className="text-lg font-bold">{currentConcept.title}</h4>
            <p className="text-xs text-muted-foreground">
              Click to reveal explanation →
            </p>
          </div>
        ) : (
          /* Back of card */
          <div className="space-y-3 animate-fade-in">
            <p className="text-sm leading-relaxed">{currentConcept.content}</p>
            
            {currentConcept.example && (
              <div className="p-2 rounded bg-background/50 border border-border/50">
                <p className="text-[10px] text-muted-foreground mb-1">Example:</p>
                <code className="text-xs text-primary font-mono">
                  {currentConcept.example}
                </code>
              </div>
            )}
            
            <div className="flex flex-wrap gap-1 pt-2">
              {currentConcept.relatedConcepts.map((concept, idx) => (
                <Badge key={idx} variant="outline" className="text-[10px]">
                  {concept}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {/* Flip indicator */}
        <div className="absolute bottom-2 right-2 text-[10px] text-muted-foreground">
          {flipped ? "Click to flip back" : "Tap to flip"}
        </div>
      </div>

      {/* Navigation */}
      <div className="flex items-center justify-between mt-4">
        <Button
          variant="ghost"
          size="sm"
          onClick={prevCard}
          className="h-8 text-xs"
        >
          <ChevronLeft className="h-4 w-4 mr-1" />
          Previous
        </Button>
        
        <div className="flex gap-1">
          {concepts.map((_, idx) => (
            <button
              key={idx}
              onClick={() => {
                setFlipped(false);
                setCurrentIndex(idx);
              }}
              className={`
                w-2 h-2 rounded-full transition-all duration-200
                ${idx === currentIndex 
                  ? 'bg-primary w-4' 
                  : 'bg-muted-foreground/30 hover:bg-muted-foreground/50'
                }
              `}
            />
          ))}
        </div>

        <Button
          variant="ghost"
          size="sm"
          onClick={nextCard}
          className="h-8 text-xs"
        >
          Next
          <ChevronRight className="h-4 w-4 ml-1" />
        </Button>
      </div>
    </Card>
  );
};

export default ConceptCards;
