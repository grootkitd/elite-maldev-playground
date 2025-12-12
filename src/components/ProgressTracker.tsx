import { useState, useEffect } from "react";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Trophy, Flame, Target, Zap, Star } from "lucide-react";

interface ProgressTrackerProps {
  moduleId: string;
  completedChallenges?: number;
  totalChallenges?: number;
}

const moduleStats: Record<string, { totalLessons: number; totalChallenges: number }> = {
  fundamentals: { totalLessons: 5, totalChallenges: 3 },
  "windows-internals": { totalLessons: 6, totalChallenges: 4 },
  "process-injection": { totalLessons: 5, totalChallenges: 3 },
  syscalls: { totalLessons: 5, totalChallenges: 3 },
  pinvoke: { totalLessons: 4, totalChallenges: 3 },
  evasion: { totalLessons: 6, totalChallenges: 4 },
  shellcode: { totalLessons: 5, totalChallenges: 3 },
  labs: { totalLessons: 3, totalChallenges: 3 },
  "active-directory": { totalLessons: 8, totalChallenges: 6 },
};

const ProgressTracker = ({ moduleId }: ProgressTrackerProps) => {
  const [progress, setProgress] = useState(0);
  const [streak, setStreak] = useState(3);
  const [xp, setXp] = useState(450);
  
  const stats = moduleStats[moduleId] || { totalLessons: 5, totalChallenges: 3 };
  
  useEffect(() => {
    // Simulate loading progress
    const timer = setTimeout(() => {
      setProgress(Math.floor(Math.random() * 40) + 10);
    }, 500);
    return () => clearTimeout(timer);
  }, [moduleId]);

  const level = Math.floor(xp / 200) + 1;
  const xpToNextLevel = (level * 200) - xp;
  const levelProgress = ((xp % 200) / 200) * 100;

  return (
    <div className="glass rounded-xl p-4 space-y-4 animate-fade-in">
      {/* XP and Level */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center border border-primary/30 shadow-glow-sm">
              <Star className="h-6 w-6 text-primary" />
            </div>
            <Badge className="absolute -top-1 -right-1 h-5 px-1.5 text-[10px] bg-primary text-primary-foreground border-0">
              {level}
            </Badge>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Level {level}</p>
            <p className="text-sm font-semibold text-foreground">{xp} XP</p>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          {/* Streak */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-warning/10 border border-warning/30">
            <Flame className="h-4 w-4 text-warning" />
            <span className="text-sm font-semibold text-warning">{streak}</span>
          </div>
          
          {/* Challenges */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-accent/10 border border-accent/30">
            <Trophy className="h-4 w-4 text-accent" />
            <span className="text-sm font-semibold text-accent">2/{stats.totalChallenges}</span>
          </div>
        </div>
      </div>
      
      {/* Level Progress */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-xs">
          <span className="text-muted-foreground">Progress to Level {level + 1}</span>
          <span className="text-primary font-mono">{xpToNextLevel} XP needed</span>
        </div>
        <div className="h-2 bg-secondary rounded-full overflow-hidden">
          <div 
            className="h-full bg-gradient-to-r from-primary to-primary-glow rounded-full progress-bar-animated transition-all duration-1000"
            style={{ width: `${levelProgress}%` }}
          />
        </div>
      </div>
      
      {/* Module Progress */}
      <div className="pt-2 border-t border-border/50 space-y-2">
        <div className="flex items-center justify-between text-xs">
          <span className="text-muted-foreground flex items-center gap-1.5">
            <Target className="h-3.5 w-3.5" />
            Module Progress
          </span>
          <span className="text-foreground font-semibold">{progress}%</span>
        </div>
        <Progress value={progress} className="h-1.5" />
      </div>
      
      {/* Quick Stats */}
      <div className="grid grid-cols-3 gap-2 pt-2">
        <div className="text-center p-2 rounded-lg bg-secondary/50">
          <Zap className="h-4 w-4 text-cyber-blue mx-auto mb-1" />
          <p className="text-xs text-muted-foreground">Lessons</p>
          <p className="text-sm font-semibold text-foreground">3/{stats.totalLessons}</p>
        </div>
        <div className="text-center p-2 rounded-lg bg-secondary/50">
          <Trophy className="h-4 w-4 text-warning mx-auto mb-1" />
          <p className="text-xs text-muted-foreground">Challenges</p>
          <p className="text-sm font-semibold text-foreground">2/{stats.totalChallenges}</p>
        </div>
        <div className="text-center p-2 rounded-lg bg-secondary/50">
          <Target className="h-4 w-4 text-accent mx-auto mb-1" />
          <p className="text-xs text-muted-foreground">Score</p>
          <p className="text-sm font-semibold text-foreground">85</p>
        </div>
      </div>
    </div>
  );
};

export default ProgressTracker;
