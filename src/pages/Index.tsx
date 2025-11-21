import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Terminal, Shield, Code2, Cpu, Lock, Zap, Wrench } from "lucide-react";
import LessonViewer from "@/components/LessonViewer";
import CodeEditor from "@/components/CodeEditor";
import TerminalConsole from "@/components/TerminalConsole";

const Index = () => {
  const [currentModule, setCurrentModule] = useState("windows-internals");
  const [consoleOutput, setConsoleOutput] = useState<string[]>([
    "REDTEAM-DEV v1.0 | Advanced Systems Programming",
    "Type 'help' for available commands",
    ""
  ]);

  const modules = [
    {
      id: "fundamentals",
      title: "C/C++ WinAPI Fundamentals",
      icon: Code2,
      description: "Essential Windows programming foundations - windows.h, types, handles, and core APIs",
      difficulty: "Beginner",
      topics: [
        "Windows Data Types",
        "Handles & Objects Model",
        "Error Handling (GetLastError)",
        "Strings & Unicode",
        "Essential Header Files",
      ]
    },
    {
      id: "windows-internals",
      title: "Windows Internals & Win32 API",
      icon: Shield,
      description: "Master Windows architecture, processes, threads, and the Win32 API",
      difficulty: "Advanced",
      topics: [
        "Process & Thread Architecture",
        "Virtual Memory Management",
        "Win32 API Deep Dive",
        "Handle Tables & Objects",
        "NTDLL & Native API",
      ]
    },
    {
      id: "process-injection",
      title: "Process Injection & Memory",
      icon: Cpu,
      description: "Advanced memory manipulation and process injection techniques",
      difficulty: "Expert",
      topics: [
        "Classic DLL Injection",
        "Process Hollowing",
        "APC Queue Injection",
        "Memory Scanning & Patching",
        "Remote Thread Creation",
      ]
    },
    {
      id: "syscalls",
      title: "Syscalls & Native API",
      icon: Terminal,
      description: "Direct syscall invocation and NTDLL internals",
      difficulty: "Expert",
      topics: [
        "SSN (System Service Numbers)",
        "Direct Syscalls",
        "Indirect Syscalls",
        "Hell's Gate & Halo's Gate",
        "Bypassing User-Mode Hooks",
      ]
    },
    {
      id: "pinvoke",
      title: "P/Invoke & .NET Interop",
      icon: Lock,
      description: "C# unmanaged code interop and marshalling",
      difficulty: "Advanced",
      topics: [
        "P/Invoke Fundamentals",
        "Structure Marshalling",
        "Function Pointer Callbacks",
        "D/Invoke Techniques",
        "In-Memory Assembly Loading",
      ]
    },
    {
      id: "evasion",
      title: "Evasion Techniques",
      icon: Zap,
      description: "AV/EDR bypass and anti-analysis methods",
      difficulty: "Expert",
      topics: [
        "AMSI Bypass Techniques",
        "ETW Patching",
        "API Unhooking",
        "Obfuscation Methods",
        "Sleep Obfuscation",
      ]
    },
    {
      id: "shellcode",
      title: "Shellcode Development",
      icon: Cpu,
      description: "Position-independent code and payload development",
      difficulty: "Expert",
      topics: [
        "Assembly Basics (x64)",
        "PIC Development",
        "Encoder/Decoder Stubs",
        "Syscall Shellcode",
        "Payload Encryption",
      ]
    },
    {
      id: "labs",
      title: "Practical Labs",
      icon: Wrench,
      description: "Build real security tools step-by-step: process dumper, memory scanner, and DLL injector",
      difficulty: "Intermediate",
      topics: [
        "Process Memory Dumper",
        "Memory Pattern Scanner",
        "DLL Injector (CreateRemoteThread)",
        "Step-by-Step Guided Projects",
        "Complete Working Code",
      ]
    }
  ];

  const selectedModule = modules.find(m => m.id === currentModule) || modules[0];

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-gradient-to-r from-card to-card/50 backdrop-blur">
        <div className="container mx-auto px-6 py-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-xl bg-primary/20 backdrop-blur">
                <Shield className="h-8 w-8 text-primary" />
              </div>
              <div>
                <h1 className="text-3xl font-bold text-foreground bg-gradient-to-r from-primary to-primary/70 bg-clip-text text-transparent">
                  REDTEAM-DEV
                </h1>
                <p className="text-sm text-muted-foreground mt-1">
                  Learn Windows Systems Programming • Step by Step • Real Examples
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Badge variant="outline" className="text-success border-success/50 bg-success/10">
                🎓 Learning Mode
              </Badge>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="container mx-auto px-6 py-8">
        <Tabs value={currentModule} onValueChange={setCurrentModule} className="space-y-6">
          {/* Module Navigation */}
          <TabsList className="grid w-full grid-cols-2 lg:grid-cols-7 gap-3 bg-card/50 p-3 h-auto rounded-xl backdrop-blur border border-border/50 shadow-lg">
            {modules.map((module) => {
              const Icon = module.icon;
              const isActive = currentModule === module.id;
              return (
                <TabsTrigger
                  key={module.id}
                  value={module.id}
                  className={`group flex flex-col items-center gap-2 p-4 rounded-lg transition-all duration-300 hover:scale-105 ${
                    isActive 
                      ? 'bg-primary text-primary-foreground shadow-glow-md' 
                      : 'hover:bg-muted/70 hover:shadow-glow-sm'
                  }`}
                >
                  <div className={`p-2 rounded-lg transition-all duration-300 ${
                    isActive 
                      ? 'bg-primary-foreground/20 shadow-inner' 
                      : 'bg-primary/10 group-hover:bg-primary/20'
                  }`}>
                    <Icon className={`h-5 w-5 transition-transform duration-300 ${isActive ? 'scale-110' : 'group-hover:scale-110'}`} />
                  </div>
                  <span className="text-xs text-center leading-tight font-medium">{module.title}</span>
                </TabsTrigger>
              );
            })}
          </TabsList>

          {/* Module Content */}
          {modules.map((module) => (
            <TabsContent key={module.id} value={module.id} className="space-y-6">
              {/* Module Header */}
              <Card className="p-8 bg-gradient-to-br from-card via-card to-card/50 border-border/50 backdrop-blur shadow-xl hover:shadow-glow-md transition-all duration-500 animate-slide-up">
                <div className="flex items-start justify-between">
                  <div className="space-y-3">
                    <div className="flex items-center gap-3">
                      <h2 className="text-4xl font-bold bg-gradient-to-r from-primary via-primary-glow to-primary bg-clip-text text-transparent">
                        {module.title}
                      </h2>
                    </div>
                    <p className="text-muted-foreground text-lg leading-relaxed">{module.description}</p>
                  </div>
                  <Badge 
                    variant={module.difficulty === "Expert" ? "destructive" : module.difficulty === "Advanced" ? "default" : "secondary"}
                    className="text-sm px-4 py-1.5 shadow-sm"
                  >
                    {module.difficulty}
                  </Badge>
                </div>
                
                {/* Topics List */}
                <div className="mt-8 p-6 rounded-xl bg-gradient-to-br from-muted/40 to-muted/20 border border-border/40 backdrop-blur-sm">
                  <h3 className="text-sm font-bold text-primary mb-5 uppercase tracking-wider flex items-center gap-2">
                    <div className="h-1 w-8 bg-primary rounded-full" />
                    What You'll Learn
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {module.topics.map((topic, idx) => (
                      <div key={idx} className="flex items-center gap-3 text-sm group cursor-default">
                        <div className="h-2 w-2 rounded-full bg-primary shadow-glow-sm group-hover:scale-150 group-hover:shadow-glow-md transition-all duration-300" />
                        <span className="text-foreground group-hover:text-primary group-hover:translate-x-1 transition-all duration-300">{topic}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </Card>

              {/* Learning Interface */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Lesson Content */}
                <LessonViewer moduleId={module.id} />

                {/* Code Editor */}
                <div className="space-y-4">
                  <CodeEditor 
                    moduleId={module.id}
                    onExecute={(output) => {
                      setConsoleOutput(prev => [...prev, ...output]);
                    }}
                  />
                  
                  {/* Terminal */}
                  <TerminalConsole 
                    output={consoleOutput}
                    onCommand={(cmd) => {
                      setConsoleOutput(prev => [...prev, `> ${cmd}`, "Command executed successfully"]);
                    }}
                  />
                </div>
              </div>
            </TabsContent>
          ))}
        </Tabs>
      </div>
    </div>
  );
};

export default Index;
