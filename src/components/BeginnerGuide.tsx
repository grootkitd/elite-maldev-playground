import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  HelpCircle, BookOpen, Terminal, Code2, Shield, 
  ChevronRight, ExternalLink, Play, CheckCircle2
} from "lucide-react";

const BeginnerGuide = () => {
  const [expandedTopic, setExpandedTopic] = useState<string | null>(null);

  const prerequisites = [
    {
      id: "os-basics",
      title: "Operating System Basics",
      description: "Understanding what an OS does and how programs run",
      status: "optional",
      resources: [
        { title: "How Operating Systems Work", type: "video", duration: "15 min" },
        { title: "Programs vs Processes", type: "article", duration: "5 min" }
      ]
    },
    {
      id: "c-basics",
      title: "Basic C/C++ Syntax",
      description: "Variables, functions, pointers (we'll cover this!)",
      status: "helpful",
      resources: [
        { title: "C in 100 Seconds", type: "video", duration: "2 min" },
        { title: "Pointer Basics", type: "interactive", duration: "20 min" }
      ]
    },
    {
      id: "command-line",
      title: "Command Line Basics",
      description: "Navigating folders, running programs",
      status: "helpful",
      resources: [
        { title: "Windows CMD Crash Course", type: "video", duration: "10 min" },
        { title: "PowerShell for Beginners", type: "article", duration: "15 min" }
      ]
    }
  ];

  const glossary = [
    { term: "API", definition: "Application Programming Interface - a set of functions the OS provides for programs to use" },
    { term: "Handle", definition: "A number that represents a system resource (like a file or window) - think of it as a ticket number" },
    { term: "Process", definition: "A running program. Each program you open becomes a process with its own memory" },
    { term: "Thread", definition: "A unit of execution within a process. Programs can do multiple things at once using threads" },
    { term: "DLL", definition: "Dynamic Link Library - a file containing code that multiple programs can share" },
    { term: "Memory Address", definition: "A number identifying a specific location in RAM where data is stored" },
    { term: "Pointer", definition: "A variable that stores a memory address - it 'points to' where data lives" },
    { term: "Shellcode", definition: "Small, position-independent code designed to be injected and run in memory" },
    { term: "Injection", definition: "Putting code into another process's memory to execute it there" },
    { term: "Hook", definition: "Intercepting function calls to monitor or modify behavior" }
  ];

  const commonQuestions = [
    {
      q: "Do I need to know C/C++ before starting?",
      a: "Not required! We introduce concepts as needed. However, basic familiarity helps. The Fundamentals module covers what you need."
    },
    {
      q: "What tools do I need installed?",
      a: "For learning: just this platform! For practice: Visual Studio (free Community edition), a Windows VM, and optionally x64dbg for debugging."
    },
    {
      q: "Is this legal to learn?",
      a: "Yes! Understanding security is legal and valuable. Just never use these techniques on systems you don't own or have permission to test."
    },
    {
      q: "How long will it take to complete?",
      a: "The core curriculum is ~100 hours of content. Most learners take 2-4 months studying a few hours per week."
    },
    {
      q: "Can I skip to advanced topics?",
      a: "We recommend following the path, as each module builds on previous ones. But you can explore freely after completing prerequisites."
    }
  ];

  return (
    <Card className="p-4 glass">
      <div className="flex items-center gap-2 mb-4">
        <div className="p-1.5 rounded-lg bg-info/20">
          <HelpCircle className="h-4 w-4 text-info" />
        </div>
        <h3 className="font-semibold">Beginner's Guide</h3>
      </div>

      <Tabs defaultValue="prereqs" className="space-y-4">
        <TabsList className="grid grid-cols-3 h-auto p-1 bg-secondary/30">
          <TabsTrigger value="prereqs" className="text-xs py-1.5">Prerequisites</TabsTrigger>
          <TabsTrigger value="glossary" className="text-xs py-1.5">Glossary</TabsTrigger>
          <TabsTrigger value="faq" className="text-xs py-1.5">FAQ</TabsTrigger>
        </TabsList>

        <TabsContent value="prereqs" className="space-y-3 mt-0">
          <p className="text-xs text-muted-foreground">
            Don't worry if you're missing some - we'll teach what you need!
          </p>
          {prerequisites.map((prereq) => (
            <div
              key={prereq.id}
              className="p-3 rounded-lg bg-secondary/20 border border-border/50"
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <h4 className="text-sm font-medium">{prereq.title}</h4>
                    <Badge variant="outline" className={`text-[10px] ${
                      prereq.status === "optional" 
                        ? "bg-muted text-muted-foreground" 
                        : "bg-info/10 text-info border-info/30"
                    }`}>
                      {prereq.status}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">{prereq.description}</p>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 text-xs"
                  onClick={() => setExpandedTopic(
                    expandedTopic === prereq.id ? null : prereq.id
                  )}
                >
                  Resources
                  <ChevronRight className={`h-3 w-3 ml-1 transition-transform ${
                    expandedTopic === prereq.id ? "rotate-90" : ""
                  }`} />
                </Button>
              </div>
              
              {expandedTopic === prereq.id && (
                <div className="mt-3 pt-3 border-t border-border/50 space-y-2 animate-fade-in">
                  {prereq.resources.map((resource, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-xs">
                      {resource.type === "video" && <Play className="h-3 w-3 text-primary" />}
                      {resource.type === "article" && <BookOpen className="h-3 w-3 text-info" />}
                      {resource.type === "interactive" && <Code2 className="h-3 w-3 text-success" />}
                      <span>{resource.title}</span>
                      <span className="text-muted-foreground">({resource.duration})</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </TabsContent>

        <TabsContent value="glossary" className="mt-0">
          <div className="max-h-[300px] overflow-y-auto pr-2 space-y-2">
            {glossary.map((item, idx) => (
              <div key={idx} className="p-2 rounded-lg bg-secondary/20">
                <div className="flex items-start gap-2">
                  <Badge variant="outline" className="text-[10px] shrink-0 mt-0.5 bg-primary/10 text-primary border-primary/30">
                    {item.term}
                  </Badge>
                  <p className="text-xs text-muted-foreground">{item.definition}</p>
                </div>
              </div>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="faq" className="mt-0">
          <div className="max-h-[300px] overflow-y-auto pr-2 space-y-3">
            {commonQuestions.map((item, idx) => (
              <div key={idx} className="p-3 rounded-lg bg-secondary/20">
                <p className="text-sm font-medium mb-1 flex items-start gap-2">
                  <span className="text-primary">Q:</span>
                  {item.q}
                </p>
                <p className="text-xs text-muted-foreground pl-5">
                  {item.a}
                </p>
              </div>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </Card>
  );
};

export default BeginnerGuide;
