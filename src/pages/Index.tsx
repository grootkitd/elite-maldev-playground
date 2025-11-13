import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Terminal, Shield, Code2, Cpu, Lock, Zap } from "lucide-react";
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
      icon: Code2,
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
      icon: Lock,
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
      icon: Zap,
      description: "Position-independent code and payload development",
      difficulty: "Expert",
      topics: [
        "Assembly Basics (x64)",
        "PIC Development",
        "Encoder/Decoder Stubs",
        "Syscall Shellcode",
        "Payload Encryption",
      ]
    }
  ];

  const selectedModule = modules.find(m => m.id === currentModule) || modules[0];

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="h-8 w-8 text-primary" />
              <div>
                <h1 className="text-2xl font-bold text-foreground">REDTEAM-DEV</h1>
                <p className="text-sm text-muted-foreground">Elite Systems Programming Academy</p>
              </div>
            </div>
            <Badge variant="outline" className="text-primary border-primary">
              Red Team Certified
            </Badge>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="container mx-auto px-6 py-8">
        <Tabs value={currentModule} onValueChange={setCurrentModule} className="space-y-6">
          {/* Module Navigation */}
          <TabsList className="grid w-full grid-cols-2 lg:grid-cols-6 gap-2 bg-card p-2 h-auto">
            {modules.map((module) => {
              const Icon = module.icon;
              return (
                <TabsTrigger
                  key={module.id}
                  value={module.id}
                  className="flex flex-col items-center gap-2 p-3 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
                >
                  <Icon className="h-5 w-5" />
                  <span className="text-xs text-center leading-tight">{module.title}</span>
                </TabsTrigger>
              );
            })}
          </TabsList>

          {/* Module Content */}
          {modules.map((module) => (
            <TabsContent key={module.id} value={module.id} className="space-y-6">
              {/* Module Header */}
              <Card className="p-6 bg-card border-border">
                <div className="flex items-start justify-between">
                  <div className="space-y-2">
                    <h2 className="text-3xl font-bold text-foreground">{module.title}</h2>
                    <p className="text-muted-foreground">{module.description}</p>
                  </div>
                  <Badge variant={module.difficulty === "Expert" ? "destructive" : "default"}>
                    {module.difficulty}
                  </Badge>
                </div>
                
                {/* Topics List */}
                <div className="mt-6 grid gap-2">
                  <h3 className="text-sm font-semibold text-muted-foreground">COVERED TOPICS:</h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {module.topics.map((topic, idx) => (
                      <div key={idx} className="flex items-center gap-2 text-sm">
                        <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                        <span className="text-foreground">{topic}</span>
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
