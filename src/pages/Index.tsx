import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  Terminal, Shield, Code2, Cpu, Lock, Zap, Wrench, BookOpen, Trophy, Network, Target,
  ChevronRight, Sparkles, Flame, Menu, X, Github, ExternalLink
} from "lucide-react";
import LessonViewer from "@/components/LessonViewer";
import CodeEditor from "@/components/CodeEditor";
import TerminalConsole from "@/components/TerminalConsole";
import ChallengeSection from "@/components/ChallengeSection";
import TechniquesChecklist from "@/components/TechniquesChecklist";
import ProgressTracker from "@/components/ProgressTracker";

const Index = () => {
  const [currentModule, setCurrentModule] = useState("fundamentals");
  const [consoleOutput, setConsoleOutput] = useState<string[]>([
    "╔══════════════════════════════════════════════════════════════╗",
    "║  REDTEAM-DEV Terminal v2.0                                   ║",
    "║  Advanced Windows Security Research Platform                 ║",
    "╚══════════════════════════════════════════════════════════════╝",
    "",
    "[*] System initialized",
    "[+] Welcome, operator",
    "[?] Type 'help' for available commands",
    ""
  ]);
  const [sidebarOpen, setSidebarOpen] = useState(true);

  const modules = [
    {
      id: "fundamentals",
      title: "C/C++ WinAPI Basics",
      shortTitle: "Fundamentals",
      icon: Code2,
      description: "Essential Windows programming foundations - windows.h, types, handles, and core APIs",
      difficulty: "Beginner",
      color: "cyber-blue",
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
      title: "Windows Internals",
      shortTitle: "Internals",
      icon: Shield,
      description: "Master Windows architecture, processes, threads, and the Win32 API",
      difficulty: "Advanced",
      color: "primary",
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
      title: "Process Injection",
      shortTitle: "Injection",
      icon: Cpu,
      description: "Advanced memory manipulation and process injection techniques",
      difficulty: "Expert",
      color: "accent",
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
      shortTitle: "Syscalls",
      icon: Terminal,
      description: "Direct syscall invocation and NTDLL internals",
      difficulty: "Expert",
      color: "cyber-purple",
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
      title: "P/Invoke & .NET",
      shortTitle: "P/Invoke",
      icon: Lock,
      description: "C# unmanaged code interop and marshalling",
      difficulty: "Advanced",
      color: "cyber-blue",
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
      shortTitle: "Evasion",
      icon: Zap,
      description: "AV/EDR bypass and anti-analysis methods",
      difficulty: "Expert",
      color: "warning",
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
      shortTitle: "Shellcode",
      icon: Cpu,
      description: "Position-independent code and payload development",
      difficulty: "Expert",
      color: "destructive",
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
      shortTitle: "Labs",
      icon: Wrench,
      description: "Build real security tools step-by-step",
      difficulty: "Intermediate",
      color: "success",
      topics: [
        "Process Memory Dumper",
        "Memory Pattern Scanner",
        "DLL Injector",
        "Step-by-Step Guided Projects",
        "Complete Working Code",
      ]
    },
    {
      id: "active-directory",
      title: "Active Directory",
      shortTitle: "AD Attacks",
      icon: Network,
      description: "AD enumeration, lateral movement, and domain dominance",
      difficulty: "Expert",
      color: "cyber-orange",
      topics: [
        "Domain Enumeration & Recon",
        "Kerberoasting & ASREPRoasting",
        "Pass-the-Hash/Ticket Attacks",
        "DCSync & Golden Ticket",
        "Lateral Movement Techniques",
      ]
    }
  ];

  const selectedModule = modules.find(m => m.id === currentModule) || modules[0];

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "Beginner": return "bg-success/20 text-success border-success/30";
      case "Intermediate": return "bg-info/20 text-info border-info/30";
      case "Advanced": return "bg-warning/20 text-warning border-warning/30";
      case "Expert": return "bg-destructive/20 text-destructive border-destructive/30";
      default: return "bg-muted text-muted-foreground";
    }
  };

  return (
    <div className="min-h-screen bg-background bg-cyber-grid bg-grid">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-border/50 glass-strong">
        <div className="container mx-auto px-4 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Button
                variant="ghost"
                size="icon"
                className="lg:hidden"
                onClick={() => setSidebarOpen(!sidebarOpen)}
              >
                {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
              </Button>
              
              <div className="flex items-center gap-3">
                <div className="relative">
                  <div className="p-2.5 rounded-xl bg-primary/20 border border-primary/30 shadow-glow-sm pulse-ring">
                    <Shield className="h-6 w-6 text-primary" />
                  </div>
                </div>
                <div>
                  <h1 className="text-xl font-bold font-display gradient-text tracking-tight">
                    REDTEAM-DEV
                  </h1>
                  <p className="text-[10px] text-muted-foreground tracking-wider uppercase">
                    Advanced Security Research
                  </p>
                </div>
              </div>
            </div>
            
            <div className="flex items-center gap-3">
              <Badge variant="outline" className="hidden sm:flex gap-1.5 text-xs border-success/30 bg-success/10 text-success">
                <Flame className="h-3 w-3" />
                3 Day Streak
              </Badge>
              <Button variant="ghost" size="icon" className="h-8 w-8">
                <Github className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside className={`
          fixed lg:sticky top-[57px] left-0 z-40 h-[calc(100vh-57px)] w-64 
          border-r border-border/50 glass-strong
          transition-transform duration-300 ease-in-out
          ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
        `}>
          <ScrollArea className="h-full py-4">
            <div className="px-3 space-y-1 stagger-fade-in">
              {modules.map((module, index) => {
                const Icon = module.icon;
                const isActive = currentModule === module.id;
                return (
                  <button
                    key={module.id}
                    onClick={() => {
                      setCurrentModule(module.id);
                      setSidebarOpen(false);
                    }}
                    className={`
                      w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left
                      transition-all duration-300 group
                      ${isActive 
                        ? 'bg-primary/20 border border-primary/40 shadow-glow-sm text-foreground' 
                        : 'hover:bg-muted/50 text-muted-foreground hover:text-foreground'
                      }
                    `}
                    style={{ animationDelay: `${index * 0.05}s` }}
                  >
                    <div className={`
                      p-1.5 rounded-md transition-all duration-300
                      ${isActive 
                        ? 'bg-primary/30 text-primary' 
                        : 'bg-muted text-muted-foreground group-hover:bg-primary/20 group-hover:text-primary'
                      }
                    `}>
                      <Icon className="h-4 w-4" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className={`text-sm font-medium truncate ${isActive ? 'text-foreground' : ''}`}>
                        {module.shortTitle}
                      </p>
                      <p className="text-[10px] text-muted-foreground truncate">
                        {module.difficulty}
                      </p>
                    </div>
                    {isActive && (
                      <ChevronRight className="h-4 w-4 text-primary" />
                    )}
                  </button>
                );
              })}
            </div>
            
            {/* Progress Tracker in Sidebar */}
            <div className="px-3 mt-6">
              <ProgressTracker moduleId={currentModule} />
            </div>
          </ScrollArea>
        </aside>

        {/* Main Content */}
        <main className="flex-1 min-w-0">
          <div className="container mx-auto px-4 py-6 max-w-7xl">
            {/* Module Header */}
            <div className="mb-6 animate-slide-up">
              <Card className="p-6 glass glow-box overflow-hidden relative">
                <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent" />
                <div className="relative">
                  <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
                    <div className="space-y-3">
                      <div className="flex items-center gap-3 flex-wrap">
                        <div className="p-2 rounded-lg bg-primary/20 border border-primary/30">
                          {(() => {
                            const Icon = selectedModule.icon;
                            return <Icon className="h-5 w-5 text-primary" />;
                          })()}
                        </div>
                        <h2 className="text-2xl md:text-3xl font-bold font-display gradient-text">
                          {selectedModule.title}
                        </h2>
                        <Badge className={`${getDifficultyColor(selectedModule.difficulty)} border`}>
                          {selectedModule.difficulty}
                        </Badge>
                      </div>
                      <p className="text-muted-foreground text-sm md:text-base max-w-2xl">
                        {selectedModule.description}
                      </p>
                    </div>
                  </div>
                  
                  {/* Topics */}
                  <div className="mt-6 flex flex-wrap gap-2">
                    {selectedModule.topics.map((topic, idx) => (
                      <Badge 
                        key={idx} 
                        variant="outline" 
                        className="text-xs bg-secondary/50 border-border/50 text-muted-foreground hover:bg-primary/10 hover:text-primary hover:border-primary/30 transition-all cursor-default"
                      >
                        {topic}
                      </Badge>
                    ))}
                  </div>
                </div>
              </Card>
            </div>

            {/* Content Tabs */}
            <Tabs defaultValue="lessons" className="space-y-4">
              <TabsList className="inline-flex h-auto glass p-1 rounded-xl">
                <TabsTrigger 
                  value="lessons" 
                  className="flex items-center gap-2 px-4 py-2.5 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground rounded-lg transition-all"
                >
                  <BookOpen className="h-4 w-4" />
                  <span className="hidden sm:inline">Lessons</span>
                </TabsTrigger>
                <TabsTrigger 
                  value="challenges" 
                  className="flex items-center gap-2 px-4 py-2.5 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground rounded-lg transition-all"
                >
                  <Trophy className="h-4 w-4" />
                  <span className="hidden sm:inline">Challenges</span>
                </TabsTrigger>
                {currentModule === "active-directory" && (
                  <TabsTrigger 
                    value="techniques" 
                    className="flex items-center gap-2 px-4 py-2.5 data-[state=active]:bg-primary data-[state=active]:text-primary-foreground rounded-lg transition-all"
                  >
                    <Target className="h-4 w-4" />
                    <span className="hidden sm:inline">Techniques</span>
                  </TabsTrigger>
                )}
              </TabsList>

              <TabsContent value="lessons" className="mt-0 animate-fade-in">
                <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                  <LessonViewer moduleId={currentModule} />
                  <div className="space-y-4">
                    <CodeEditor 
                      moduleId={currentModule}
                      onExecute={(output) => {
                        setConsoleOutput(prev => [...prev, ...output]);
                      }}
                    />
                    <TerminalConsole 
                      output={consoleOutput}
                      onCommand={(cmd) => {
                        setConsoleOutput(prev => [
                          ...prev, 
                          `❯ ${cmd}`,
                          cmd === "help" 
                            ? "[*] Available commands: clear, help, info, run" 
                            : cmd === "clear"
                            ? ""
                            : cmd === "info"
                            ? `[*] Current module: ${currentModule}`
                            : "[+] Command executed"
                        ]);
                      }}
                    />
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="challenges" className="mt-0 animate-fade-in">
                <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                  <ChallengeSection moduleId={currentModule} />
                  <div className="space-y-4">
                    <CodeEditor 
                      moduleId={currentModule}
                      onExecute={(output) => {
                        setConsoleOutput(prev => [...prev, ...output]);
                      }}
                    />
                    <TerminalConsole 
                      output={consoleOutput}
                      onCommand={(cmd) => {
                        setConsoleOutput(prev => [...prev, `❯ ${cmd}`, "[+] Command executed"]);
                      }}
                    />
                  </div>
                </div>
              </TabsContent>

              {currentModule === "active-directory" && (
                <TabsContent value="techniques" className="mt-0 animate-fade-in">
                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
                    <TechniquesChecklist moduleId={currentModule} />
                    <div className="space-y-4">
                      <CodeEditor 
                        moduleId={currentModule}
                        onExecute={(output) => {
                          setConsoleOutput(prev => [...prev, ...output]);
                        }}
                      />
                      <TerminalConsole 
                        output={consoleOutput}
                        onCommand={(cmd) => {
                          setConsoleOutput(prev => [...prev, `❯ ${cmd}`, "[+] Command executed"]);
                        }}
                      />
                    </div>
                  </div>
                </TabsContent>
              )}
            </Tabs>
          </div>
        </main>
      </div>

      {/* Mobile overlay */}
      {sidebarOpen && (
        <div 
          className="fixed inset-0 bg-background/80 backdrop-blur-sm z-30 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  );
};

export default Index;
