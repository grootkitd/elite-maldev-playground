import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Award, Star, Zap, Shield, Code2, Target, Flame, 
  BookOpen, Terminal, Rocket, Trophy, Crown, Lock
} from "lucide-react";

interface Achievement {
  id: string;
  title: string;
  description: string;
  icon: any;
  color: string;
  earned: boolean;
  earnedDate?: string;
  rarity: "common" | "rare" | "epic" | "legendary";
}

const AchievementBadges = () => {
  const achievements: Achievement[] = [
    {
      id: "first-steps",
      title: "First Steps",
      description: "Complete your first lesson",
      icon: BookOpen,
      color: "success",
      earned: true,
      earnedDate: "2 days ago",
      rarity: "common"
    },
    {
      id: "code-runner",
      title: "Code Runner",
      description: "Execute code 10 times",
      icon: Terminal,
      color: "info",
      earned: true,
      earnedDate: "1 day ago",
      rarity: "common"
    },
    {
      id: "fundamentals-master",
      title: "Fundamentals Master",
      description: "Complete the Fundamentals module",
      icon: Code2,
      color: "primary",
      earned: false,
      rarity: "rare"
    },
    {
      id: "streak-keeper",
      title: "Streak Keeper",
      description: "Maintain a 7-day learning streak",
      icon: Flame,
      color: "warning",
      earned: false,
      rarity: "rare"
    },
    {
      id: "challenge-conqueror",
      title: "Challenge Conqueror",
      description: "Complete 5 challenges",
      icon: Target,
      color: "accent",
      earned: false,
      rarity: "epic"
    },
    {
      id: "shellcode-sage",
      title: "Shellcode Sage",
      description: "Master shellcode execution",
      icon: Zap,
      color: "destructive",
      earned: false,
      rarity: "epic"
    },
    {
      id: "evasion-expert",
      title: "Evasion Expert",
      description: "Complete all evasion techniques",
      icon: Shield,
      color: "cyber-purple",
      earned: false,
      rarity: "legendary"
    },
    {
      id: "red-team-elite",
      title: "Red Team Elite",
      description: "Complete the entire curriculum",
      icon: Crown,
      color: "warning",
      earned: false,
      rarity: "legendary"
    }
  ];

  const getRarityStyles = (rarity: string) => {
    switch (rarity) {
      case "common": return "border-muted-foreground/30 bg-muted/20";
      case "rare": return "border-info/30 bg-info/10";
      case "epic": return "border-primary/30 bg-primary/10";
      case "legendary": return "border-warning/30 bg-gradient-to-br from-warning/20 to-transparent";
      default: return "";
    }
  };

  const getRarityLabel = (rarity: string) => {
    switch (rarity) {
      case "common": return "Common";
      case "rare": return "Rare";
      case "epic": return "Epic";
      case "legendary": return "Legendary";
      default: return rarity;
    }
  };

  const earnedCount = achievements.filter(a => a.earned).length;

  return (
    <Card className="p-4 glass">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Award className="h-5 w-5 text-warning" />
          <h3 className="font-semibold">Achievements</h3>
        </div>
        <Badge variant="outline" className="text-xs">
          {earnedCount}/{achievements.length}
        </Badge>
      </div>

      <div className="grid grid-cols-4 gap-2">
        {achievements.map((achievement) => {
          const Icon = achievement.icon;
          return (
            <div
              key={achievement.id}
              className={`
                relative group p-2 rounded-lg border text-center
                transition-all duration-300 cursor-default
                ${achievement.earned 
                  ? `${getRarityStyles(achievement.rarity)} hover:scale-105` 
                  : 'border-border/30 bg-muted/10 opacity-50'
                }
              `}
            >
              <div className={`
                mx-auto w-8 h-8 rounded-full flex items-center justify-center mb-1
                ${achievement.earned 
                  ? `bg-${achievement.color}/20 text-${achievement.color}` 
                  : 'bg-muted text-muted-foreground'
                }
              `}>
                {achievement.earned ? (
                  <Icon className="h-4 w-4" />
                ) : (
                  <Lock className="h-3 w-3" />
                )}
              </div>
              <p className="text-[9px] font-medium truncate">{achievement.title}</p>

              {/* Tooltip */}
              <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-40 p-2 rounded-lg glass border border-border/50 shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-10">
                <p className="text-xs font-medium mb-1">{achievement.title}</p>
                <p className="text-[10px] text-muted-foreground mb-1">{achievement.description}</p>
                <div className="flex items-center justify-between">
                  <Badge variant="outline" className="text-[8px]">
                    {getRarityLabel(achievement.rarity)}
                  </Badge>
                  {achievement.earned && (
                    <span className="text-[8px] text-muted-foreground">{achievement.earnedDate}</span>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
};

export default AchievementBadges;
