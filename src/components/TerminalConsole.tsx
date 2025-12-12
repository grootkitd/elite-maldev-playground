import { useState, useRef, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";
import { Terminal, Trash2, Copy, Check, Maximize2, Minimize2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface TerminalConsoleProps {
  output: string[];
  onCommand: (cmd: string) => void;
}

const TerminalConsole = ({ output, onCommand }: TerminalConsoleProps) => {
  const [command, setCommand] = useState("");
  const [history, setHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [isExpanded, setIsExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const { toast } = useToast();

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [output]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (command.trim()) {
      onCommand(command);
      setHistory(prev => [...prev, command]);
      setHistoryIndex(-1);
      setCommand("");
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      if (historyIndex < history.length - 1) {
        const newIndex = historyIndex + 1;
        setHistoryIndex(newIndex);
        setCommand(history[history.length - 1 - newIndex] || "");
      }
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      if (historyIndex > 0) {
        const newIndex = historyIndex - 1;
        setHistoryIndex(newIndex);
        setCommand(history[history.length - 1 - newIndex] || "");
      } else {
        setHistoryIndex(-1);
        setCommand("");
      }
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(output.join("\n"));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast({
      title: "Copied",
      description: "Terminal output copied to clipboard",
    });
  };

  const handleClear = () => {
    // This would need to be handled by parent component
    toast({
      title: "Cleared",
      description: "Terminal output cleared",
    });
  };

  const formatLine = (line: string, idx: number) => {
    // Color coding for different output types
    let className = "text-foreground/80";
    
    if (line.startsWith("[*]")) {
      className = "text-info";
    } else if (line.startsWith("[+]")) {
      className = "text-success";
    } else if (line.startsWith("[-]") || line.startsWith("[!]")) {
      className = "text-destructive";
    } else if (line.startsWith("[?]")) {
      className = "text-warning";
    } else if (line.startsWith("> ")) {
      className = "text-primary font-semibold";
    } else if (line.includes("═") || line.includes("─")) {
      className = "text-muted-foreground/50";
    } else if (line.startsWith("0x") || /^[A-F0-9]{2}\s/.test(line)) {
      className = "text-cyber-purple";
    }
    
    return (
      <div key={idx} className={`whitespace-pre-wrap ${className}`}>
        {line}
      </div>
    );
  };

  return (
    <Card className={`p-0 bg-terminal-bg border-border overflow-hidden transition-all duration-300 ${isExpanded ? 'fixed inset-4 z-50' : ''}`}>
      <div className="bg-gradient-to-r from-secondary via-secondary to-secondary/80 p-2.5 border-b border-border/50 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full bg-destructive/80" />
            <div className="w-3 h-3 rounded-full bg-warning/80" />
            <div className="w-3 h-3 rounded-full bg-success/80" />
          </div>
          <div className="flex items-center gap-2">
            <Terminal className="h-4 w-4 text-primary" />
            <span className="font-mono text-xs text-muted-foreground">redteam@localhost</span>
            <span className="text-primary/60 font-mono text-xs">~</span>
          </div>
        </div>
        
        <div className="flex items-center gap-1">
          <Button
            size="icon"
            variant="ghost"
            className="h-7 w-7 hover:bg-muted/50"
            onClick={handleCopy}
          >
            {copied ? <Check className="h-3.5 w-3.5 text-success" /> : <Copy className="h-3.5 w-3.5 text-muted-foreground" />}
          </Button>
          <Button
            size="icon"
            variant="ghost"
            className="h-7 w-7 hover:bg-muted/50"
            onClick={handleClear}
          >
            <Trash2 className="h-3.5 w-3.5 text-muted-foreground" />
          </Button>
          <Button
            size="icon"
            variant="ghost"
            className="h-7 w-7 hover:bg-muted/50"
            onClick={() => setIsExpanded(!isExpanded)}
          >
            {isExpanded ? (
              <Minimize2 className="h-3.5 w-3.5 text-muted-foreground" />
            ) : (
              <Maximize2 className="h-3.5 w-3.5 text-muted-foreground" />
            )}
          </Button>
        </div>
      </div>
      
      <ScrollArea className={isExpanded ? "h-[calc(100%-100px)]" : "h-[180px]"} ref={scrollRef}>
        <div className="p-4 font-mono text-xs space-y-0.5 scan-line">
          {output.map((line, idx) => formatLine(line, idx))}
          <div className="typing-cursor text-primary">█</div>
        </div>
      </ScrollArea>
      
      <form onSubmit={handleSubmit} className="border-t border-border/50 p-2 bg-terminal-bg/50">
        <div className="flex items-center gap-2">
          <span className="text-success font-mono text-xs">❯</span>
          <Input
            ref={inputRef}
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            onKeyDown={handleKeyDown}
            className="bg-transparent border-0 font-mono text-xs text-foreground focus-visible:ring-0 p-0 h-auto placeholder:text-muted-foreground/50"
            placeholder="Type a command..."
          />
        </div>
      </form>
    </Card>
  );
};

export default TerminalConsole;
