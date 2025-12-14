import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { 
  Code2, Shield, Cpu, Terminal, Lock, Zap, Wrench, Network,
  ChevronRight, CheckCircle2, Circle, Lock as LockIcon, Star, Sparkles
} from "lucide-react";

interface RoadmapModule {
  id: string;
  title: string;
  shortTitle: string;
  icon: any;
  description: string;
  difficulty: string;
  prerequisites: string[];
  estimatedHours: number;
  skills: string[];
  isUnlocked: boolean;
  isCompleted: boolean;
  progress: number;
}

interface LearningRoadmapProps {
  onSelectModule: (moduleId: string) => void;
  currentModule: string;
}

const LearningRoadmap = ({ onSelectModule, currentModule }: LearningRoadmapProps) => {
  const [hoveredModule, setHoveredModule] = useState<string | null>(null);

  const roadmapModules: RoadmapModule[] = [
    {
      id: "fundamentals",
      title: "C/C++ WinAPI Basics",
      shortTitle: "Fundamentals",
      icon: Code2,
      description: "Start here! Learn Windows data types, handles, and essential APIs",
      difficulty: "Beginner",
      prerequisites: [],
      estimatedHours: 8,
      skills: ["Windows.h", "Data Types", "Handles", "Error Handling"],
      isUnlocked: true,
      isCompleted: false,
      progress: 35
    },
    {
      id: "windows-internals",
      title: "Windows Internals",
      shortTitle: "Internals",
      icon: Shield,
      description: "Deep dive into Windows architecture, processes, and memory",
      difficulty: "Intermediate",
      prerequisites: ["fundamentals"],
      estimatedHours: 12,
      skills: ["Process Architecture", "Virtual Memory", "PEB/TEB", "Win32 API"],
      isUnlocked: true,
      isCompleted: false,
      progress: 0
    },
    {
      id: "shellcode",
      title: "Shellcode Basics",
      shortTitle: "Shellcode",
      icon: Cpu,
      description: "Learn position-independent code and basic execution methods",
      difficulty: "Intermediate",
      prerequisites: ["fundamentals", "windows-internals"],
      estimatedHours: 10,
      skills: ["PIC Code", "Memory Allocation", "Execution Methods", "Payload Basics"],
      isUnlocked: false,
      isCompleted: false,
      progress: 0
    },
    {
      id: "process-injection",
      title: "Process Injection",
      shortTitle: "Injection",
      icon: Terminal,
      description: "Master injection techniques and cross-process operations",
      difficulty: "Advanced",
      prerequisites: ["shellcode"],
      estimatedHours: 15,
      skills: ["DLL Injection", "Process Hollowing", "APC Injection", "Thread Hijacking"],
      isUnlocked: false,
      isCompleted: false,
      progress: 0
    },
    {
      id: "syscalls",
      title: "Syscalls & Native API",
      shortTitle: "Syscalls",
      icon: Terminal,
      description: "Direct syscalls and bypassing user-mode hooks",
      difficulty: "Advanced",
      prerequisites: ["process-injection"],
      estimatedHours: 12,
      skills: ["SSN Resolution", "Direct Syscalls", "Hell's Gate", "Indirect Syscalls"],
      isUnlocked: false,
      isCompleted: false,
      progress: 0
    },
    {
      id: "evasion",
      title: "Defense Evasion",
      shortTitle: "Evasion",
      icon: Zap,
      description: "Bypass AV/EDR and evade detection mechanisms",
      difficulty: "Expert",
      prerequisites: ["syscalls"],
      estimatedHours: 20,
      skills: ["AMSI Bypass", "ETW Patching", "API Unhooking", "Sleep Obfuscation"],
      isUnlocked: false,
      isCompleted: false,
      progress: 0
    },
    {
      id: "pinvoke",
      title: "P/Invoke & .NET",
      shortTitle: "P/Invoke",
      icon: Lock,
      description: "C# interop with unmanaged code and D/Invoke",
      difficulty: "Intermediate",
      prerequisites: ["windows-internals"],
      estimatedHours: 10,
      skills: ["Marshalling", "D/Invoke", "Assembly Loading", "Reflection"],
      isUnlocked: false,
      isCompleted: false,
      progress: 0
    },
    {
      id: "active-directory",
      title: "Active Directory",
      shortTitle: "AD Attacks",
      icon: Network,
      description: "Domain enumeration and lateral movement techniques",
      difficulty: "Expert",
      prerequisites: ["evasion"],
      estimatedHours: 25,
      skills: ["Kerberos", "Pass-the-Hash", "DCSync", "Golden Ticket"],
      isUnlocked: false,
      isCompleted: false,
      progress: 0
    },
    {
      id: "labs",
      title: "Practical Labs",
      shortTitle: "Labs",
      icon: Wrench,
      description: "Build real tools with step-by-step guidance",
      difficulty: "All Levels",
      prerequisites: [],
      estimatedHours: 30,
      skills: ["Tool Building", "Debugging", "Integration", "Real Projects"],
      isUnlocked: true,
      isCompleted: false,
      progress: 10
    }
  ];

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "Beginner": return "text-success border-success/30 bg-success/10";
      case "Intermediate": return "text-info border-info/30 bg-info/10";
      case "Advanced": return "text-warning border-warning/30 bg-warning/10";
      case "Expert": return "text-destructive border-destructive/30 bg-destructive/10";
      default: return "text-muted-foreground border-border bg-muted/50";
    }
  };

  const getConnectionColor = (fromUnlocked: boolean, toUnlocked: boolean) => {
    if (toUnlocked) return "bg-primary";
    if (fromUnlocked) return "bg-primary/30";
    return "bg-border";
  };

  // Define visual path connections
  const pathConnections = [
    { from: "fundamentals", to: "windows-internals" },
    { from: "windows-internals", to: "shellcode" },
    { from: "windows-internals", to: "pinvoke" },
    { from: "shellcode", to: "process-injection" },
    { from: "process-injection", to: "syscalls" },
    { from: "syscalls", to: "evasion" },
    { from: "evasion", to: "active-directory" },
  ];

  return (
    <Card className="p-6 glass glow-box">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-xl font-bold font-display gradient-text flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-primary" />
            Your Learning Path
          </h3>
          <p className="text-sm text-muted-foreground mt-1">
            Follow the recommended path or explore freely
          </p>
        </div>
        <Badge className="bg-primary/20 text-primary border-primary/30">
          2/9 Modules Started
        </Badge>
      </div>

      {/* Roadmap Grid */}
      <div className="relative">
        {/* Main Path */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {roadmapModules.map((module, index) => {
            const Icon = module.icon;
            const isActive = currentModule === module.id;
            const isHovered = hoveredModule === module.id;
            
            return (
              <div
                key={module.id}
                className="relative"
                onMouseEnter={() => setHoveredModule(module.id)}
                onMouseLeave={() => setHoveredModule(null)}
              >
                <Card
                  className={`
                    p-4 cursor-pointer transition-all duration-300 h-full
                    ${isActive ? 'ring-2 ring-primary shadow-glow-md' : ''}
                    ${module.isUnlocked 
                      ? 'glass hover:shadow-glow-sm' 
                      : 'bg-muted/30 opacity-60'
                    }
                    ${isHovered && module.isUnlocked ? 'scale-[1.02]' : ''}
                  `}
                  onClick={() => module.isUnlocked && onSelectModule(module.id)}
                >
                  {/* Module Header */}
                  <div className="flex items-start justify-between mb-3">
                    <div className={`
                      p-2 rounded-lg transition-all duration-300
                      ${module.isUnlocked 
                        ? 'bg-primary/20 text-primary' 
                        : 'bg-muted text-muted-foreground'
                      }
                    `}>
                      <Icon className="h-5 w-5" />
                    </div>
                    <div className="flex items-center gap-2">
                      {module.isCompleted ? (
                        <CheckCircle2 className="h-5 w-5 text-success" />
                      ) : !module.isUnlocked ? (
                        <LockIcon className="h-4 w-4 text-muted-foreground" />
                      ) : module.progress > 0 ? (
                        <span className="text-xs text-primary font-medium">{module.progress}%</span>
                      ) : null}
                    </div>
                  </div>

                  {/* Title & Description */}
                  <h4 className={`font-semibold mb-1 ${module.isUnlocked ? 'text-foreground' : 'text-muted-foreground'}`}>
                    {module.shortTitle}
                  </h4>
                  <p className="text-xs text-muted-foreground mb-3 line-clamp-2">
                    {module.description}
                  </p>

                  {/* Progress Bar */}
                  {module.isUnlocked && module.progress > 0 && (
                    <Progress value={module.progress} className="h-1.5 mb-3" />
                  )}

                  {/* Meta Info */}
                  <div className="flex items-center justify-between mt-auto">
                    <Badge variant="outline" className={`text-[10px] ${getDifficultyColor(module.difficulty)}`}>
                      {module.difficulty}
                    </Badge>
                    <span className="text-[10px] text-muted-foreground">
                      ~{module.estimatedHours}h
                    </span>
                  </div>

                  {/* Skills Preview on Hover */}
                  {isHovered && module.isUnlocked && (
                    <div className="absolute inset-x-0 -bottom-2 translate-y-full z-10 p-3 glass rounded-lg border border-border/50 shadow-lg animate-fade-in">
                      <p className="text-[10px] text-muted-foreground mb-1.5">Skills you'll learn:</p>
                      <div className="flex flex-wrap gap-1">
                        {module.skills.map((skill, idx) => (
                          <Badge key={idx} variant="outline" className="text-[10px] bg-secondary/50">
                            {skill}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recommended Starting Point */}
                  {module.id === "fundamentals" && (
                    <div className="absolute -top-2 -right-2">
                      <Badge className="bg-success text-success-foreground text-[10px] animate-pulse">
                        <Star className="h-3 w-3 mr-1" />
                        Start Here
                      </Badge>
                    </div>
                  )}
                </Card>
              </div>
            );
          })}
        </div>
      </div>

      {/* Path Legend */}
      <div className="mt-6 pt-4 border-t border-border/50">
        <div className="flex flex-wrap items-center gap-4 text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-success" />
            <span>Completed</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-primary" />
            <span>In Progress</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-muted" />
            <span>Locked</span>
          </div>
          <div className="flex items-center gap-2 ml-auto">
            <span className="text-muted-foreground">💡</span>
            <span>Complete prerequisites to unlock</span>
          </div>
        </div>
      </div>
    </Card>
  );
};

export default LearningRoadmap;
