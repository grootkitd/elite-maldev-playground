import { useState, useRef, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Terminal } from "lucide-react";

interface TerminalConsoleProps {
  output: string[];
  onCommand: (cmd: string) => void;
}

const TerminalConsole = ({ output, onCommand }: TerminalConsoleProps) => {
  const [command, setCommand] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [output]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (command.trim()) {
      onCommand(command);
      setCommand("");
    }
  };

  return (
    <Card className="p-0 bg-terminal-bg border-border overflow-hidden">
      <div className="bg-secondary p-3 border-b border-border flex items-center gap-2">
        <Terminal className="h-4 w-4 text-primary" />
        <span className="font-mono text-xs text-foreground">terminal@redteam-dev:~$</span>
      </div>
      
      <ScrollArea className="h-[200px]" ref={scrollRef}>
        <div className="p-4 font-mono text-xs space-y-1">
          {output.map((line, idx) => (
            <div key={idx} className="text-primary whitespace-pre-wrap">
              {line}
            </div>
          ))}
        </div>
      </ScrollArea>
      
      <form onSubmit={handleSubmit} className="border-t border-border p-2">
        <div className="flex items-center gap-2">
          <span className="text-primary font-mono text-xs">$</span>
          <Input
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            className="bg-transparent border-0 font-mono text-xs text-primary focus-visible:ring-0 p-0 h-auto"
            placeholder="Enter command..."
          />
        </div>
      </form>
    </Card>
  );
};

export default TerminalConsole;
