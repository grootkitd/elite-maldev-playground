import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { 
  ExternalLink, BookOpen, Video, Github, FileText, 
  Download, Globe, Terminal, Code2, Shield
} from "lucide-react";

interface Resource {
  title: string;
  description: string;
  url: string;
  type: "article" | "video" | "github" | "tool" | "docs" | "book";
  difficulty: "beginner" | "intermediate" | "advanced";
  free: boolean;
}

interface ResourcesSectionProps {
  moduleId: string;
}

const ResourcesSection = ({ moduleId }: ResourcesSectionProps) => {
  const resourcesByModule: Record<string, Resource[]> = {
    fundamentals: [
      {
        title: "Microsoft Win32 API Reference",
        description: "Official documentation for all Windows API functions",
        url: "https://docs.microsoft.com/en-us/windows/win32/api/",
        type: "docs",
        difficulty: "beginner",
        free: true
      },
      {
        title: "Programming Windows - Charles Petzold",
        description: "The classic book on Windows programming (still relevant!)",
        url: "#",
        type: "book",
        difficulty: "beginner",
        free: false
      },
      {
        title: "Visual Studio Community",
        description: "Free IDE for Windows development with IntelliSense",
        url: "https://visualstudio.microsoft.com/vs/community/",
        type: "tool",
        difficulty: "beginner",
        free: true
      },
      {
        title: "Windows Internals YouTube Series",
        description: "Pavel Yosifovich explains Windows internals concepts",
        url: "#",
        type: "video",
        difficulty: "beginner",
        free: true
      }
    ],
    shellcode: [
      {
        title: "Shellcode Execution Techniques",
        description: "Overview of different methods to execute shellcode",
        url: "#",
        type: "article",
        difficulty: "intermediate",
        free: true
      },
      {
        title: "Donut - PE to Shellcode",
        description: "Convert .NET assemblies and PEs to shellcode",
        url: "https://github.com/TheWover/donut",
        type: "github",
        difficulty: "intermediate",
        free: true
      },
      {
        title: "sRDI - Shellcode Reflective DLL Injection",
        description: "Convert DLLs to position-independent shellcode",
        url: "https://github.com/monoxgas/sRDI",
        type: "github",
        difficulty: "advanced",
        free: true
      }
    ],
    evasion: [
      {
        title: "AMSI Bypass Methods",
        description: "Collection of documented AMSI bypass techniques",
        url: "#",
        type: "article",
        difficulty: "advanced",
        free: true
      },
      {
        title: "EDR Evasion Primer",
        description: "Understanding how EDRs work and common weaknesses",
        url: "#",
        type: "article",
        difficulty: "advanced",
        free: true
      },
      {
        title: "SysWhispers",
        description: "Generate direct system call stubs for AV/EDR evasion",
        url: "https://github.com/jthuraisamy/SysWhispers",
        type: "github",
        difficulty: "advanced",
        free: true
      }
    ],
    "active-directory": [
      {
        title: "PayloadsAllTheThings - AD",
        description: "Comprehensive AD attack cheat sheet",
        url: "https://github.com/swisskyrepo/PayloadsAllTheThings",
        type: "github",
        difficulty: "intermediate",
        free: true
      },
      {
        title: "BloodHound",
        description: "AD relationship graphing for attack path discovery",
        url: "https://github.com/BloodHoundAD/BloodHound",
        type: "github",
        difficulty: "intermediate",
        free: true
      },
      {
        title: "AD Security Blog",
        description: "Sean Metcalf's excellent AD security articles",
        url: "https://adsecurity.org/",
        type: "article",
        difficulty: "intermediate",
        free: true
      },
      {
        title: "Attacking Active Directory Course",
        description: "Hands-on course for AD pentesting",
        url: "#",
        type: "video",
        difficulty: "advanced",
        free: false
      }
    ]
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "article": return FileText;
      case "video": return Video;
      case "github": return Github;
      case "tool": return Download;
      case "docs": return BookOpen;
      case "book": return BookOpen;
      default: return Globe;
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case "article": return "bg-info/10 text-info border-info/30";
      case "video": return "bg-destructive/10 text-destructive border-destructive/30";
      case "github": return "bg-foreground/10 text-foreground border-foreground/30";
      case "tool": return "bg-success/10 text-success border-success/30";
      case "docs": return "bg-primary/10 text-primary border-primary/30";
      case "book": return "bg-warning/10 text-warning border-warning/30";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "beginner": return "text-success";
      case "intermediate": return "text-warning";
      case "advanced": return "text-destructive";
      default: return "text-muted-foreground";
    }
  };

  const resources = resourcesByModule[moduleId] || resourcesByModule.fundamentals;

  return (
    <Card className="p-4 glass">
      <div className="flex items-center gap-2 mb-4">
        <div className="p-1.5 rounded-lg bg-primary/20">
          <BookOpen className="h-4 w-4 text-primary" />
        </div>
        <h3 className="font-semibold text-sm">Learning Resources</h3>
      </div>

      <div className="space-y-2">
        {resources.map((resource, idx) => {
          const Icon = getTypeIcon(resource.type);
          
          return (
            <a
              key={idx}
              href={resource.url}
              target="_blank"
              rel="noopener noreferrer"
              className="block p-3 rounded-lg bg-secondary/20 border border-border/50 hover:border-primary/30 hover:bg-secondary/40 transition-all duration-200 group"
            >
              <div className="flex items-start gap-3">
                <div className={`p-1.5 rounded-md border ${getTypeColor(resource.type)}`}>
                  <Icon className="h-4 w-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium truncate group-hover:text-primary transition-colors">
                      {resource.title}
                    </p>
                    <ExternalLink className="h-3 w-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                  </div>
                  <p className="text-xs text-muted-foreground line-clamp-1 mt-0.5">
                    {resource.description}
                  </p>
                  <div className="flex items-center gap-2 mt-1.5">
                    <Badge variant="outline" className={`text-[10px] ${getTypeColor(resource.type)}`}>
                      {resource.type}
                    </Badge>
                    <span className={`text-[10px] ${getDifficultyColor(resource.difficulty)}`}>
                      {resource.difficulty}
                    </span>
                    {resource.free && (
                      <Badge variant="outline" className="text-[10px] bg-success/10 text-success border-success/30">
                        Free
                      </Badge>
                    )}
                  </div>
                </div>
              </div>
            </a>
          );
        })}
      </div>

      <Button variant="ghost" size="sm" className="w-full mt-3 text-xs h-8">
        View All Resources
        <ExternalLink className="h-3 w-3 ml-1" />
      </Button>
    </Card>
  );
};

export default ResourcesSection;
