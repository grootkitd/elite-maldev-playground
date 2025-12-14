import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { 
  Lightbulb, ChevronLeft, ChevronRight, X, BookOpen, 
  Terminal, Code2, Shield, Zap, Target
} from "lucide-react";

interface QuickTipsProps {
  moduleId: string;
}

const QuickTips = ({ moduleId }: QuickTipsProps) => {
  const [currentTip, setCurrentTip] = useState(0);
  const [dismissed, setDismissed] = useState(false);

  const tipsByModule: Record<string, Array<{ title: string; content: string; icon: any }>> = {
    fundamentals: [
      {
        title: "Start with Windows.h",
        content: "Always include <windows.h> first - it's your gateway to the Windows API and contains all essential type definitions.",
        icon: Code2
      },
      {
        title: "Handles are Keys",
        content: "Think of handles like keys to doors. You need the right key (handle) to access system resources. Always close them when done!",
        icon: Terminal
      },
      {
        title: "Check GetLastError()",
        content: "When a Windows API function fails, call GetLastError() immediately to find out why. This is your best debugging friend.",
        icon: Lightbulb
      },
      {
        title: "Use Unicode by Default",
        content: "Always use the 'W' suffix versions of functions (e.g., CreateFileW) for Unicode support. ANSI versions are legacy.",
        icon: BookOpen
      }
    ],
    shellcode: [
      {
        title: "Position Independent",
        content: "Shellcode must work regardless of where it's loaded. Avoid hardcoded addresses - resolve everything dynamically.",
        icon: Code2
      },
      {
        title: "RWX is a Red Flag",
        content: "PAGE_EXECUTE_READWRITE memory is suspicious. Use RW for writing, then change to RX for execution.",
        icon: Shield
      },
      {
        title: "Test in Isolation",
        content: "Always test shellcode in a controlled environment first. Use a VM and disable network to avoid accidents.",
        icon: Target
      }
    ],
    evasion: [
      {
        title: "Know Your Enemy",
        content: "Understand how AV/EDR works before trying to bypass it. Static analysis, behavioral analysis, and hooks are the main vectors.",
        icon: Shield
      },
      {
        title: "Less is More",
        content: "The less suspicious behavior your code exhibits, the better. Avoid unnecessary API calls and memory operations.",
        icon: Zap
      }
    ]
  };

  const tips = tipsByModule[moduleId] || tipsByModule.fundamentals;

  if (dismissed || tips.length === 0) return null;

  const currentTipData = tips[currentTip];
  const Icon = currentTipData.icon;

  return (
    <Card className="p-4 glass border-primary/20 relative overflow-hidden">
      {/* Background Glow */}
      <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-transparent" />
      
      <div className="relative">
        {/* Header */}
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-warning/20">
              <Lightbulb className="h-4 w-4 text-warning" />
            </div>
            <span className="text-sm font-medium">Quick Tip</span>
            <Badge variant="outline" className="text-[10px]">
              {currentTip + 1}/{tips.length}
            </Badge>
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            onClick={() => setDismissed(true)}
          >
            <X className="h-3 w-3" />
          </Button>
        </div>

        {/* Tip Content */}
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-secondary/50 hidden sm:block">
            <Icon className="h-5 w-5 text-muted-foreground" />
          </div>
          <div className="flex-1 min-w-0">
            <h4 className="font-semibold text-sm mb-1">{currentTipData.title}</h4>
            <p className="text-xs text-muted-foreground leading-relaxed">
              {currentTipData.content}
            </p>
          </div>
        </div>

        {/* Navigation */}
        {tips.length > 1 && (
          <div className="flex items-center justify-between mt-3 pt-3 border-t border-border/50">
            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-xs"
              onClick={() => setCurrentTip(currentTip === 0 ? tips.length - 1 : currentTip - 1)}
            >
              <ChevronLeft className="h-3 w-3 mr-1" />
              Previous
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 text-xs"
              onClick={() => setCurrentTip((currentTip + 1) % tips.length)}
            >
              Next
              <ChevronRight className="h-3 w-3 ml-1" />
            </Button>
          </div>
        )}
      </div>
    </Card>
  );
};

export default QuickTips;
