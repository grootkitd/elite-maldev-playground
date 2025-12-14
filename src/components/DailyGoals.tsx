import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { 
  Target, CheckCircle2, Circle, Flame, Gift, Clock, 
  BookOpen, Code2, Trophy, Zap, Star, Sparkles
} from "lucide-react";

interface DailyGoal {
  id: string;
  title: string;
  description: string;
  target: number;
  current: number;
  xpReward: number;
  icon: any;
  completed: boolean;
}

const DailyGoals = () => {
  const [goals, setGoals] = useState<DailyGoal[]>([
    {
      id: "lessons",
      title: "Complete a Lesson",
      description: "Read through at least 1 lesson",
      target: 1,
      current: 1,
      xpReward: 25,
      icon: BookOpen,
      completed: true
    },
    {
      id: "code",
      title: "Run Code",
      description: "Execute code in the editor 3 times",
      target: 3,
      current: 2,
      xpReward: 15,
      icon: Code2,
      completed: false
    },
    {
      id: "challenge",
      title: "Solve a Challenge",
      description: "Complete any challenge",
      target: 1,
      current: 0,
      xpReward: 50,
      icon: Trophy,
      completed: false
    },
    {
      id: "streak",
      title: "Keep the Streak",
      description: "Log in and study today",
      target: 1,
      current: 1,
      xpReward: 10,
      icon: Flame,
      completed: true
    }
  ]);

  const [timeRemaining, setTimeRemaining] = useState("");
  const [claimedReward, setClaimedReward] = useState(false);

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const midnight = new Date();
      midnight.setHours(24, 0, 0, 0);
      const diff = midnight.getTime() - now.getTime();
      
      const hours = Math.floor(diff / (1000 * 60 * 60));
      const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
      
      setTimeRemaining(`${hours}h ${minutes}m`);
    };

    updateTime();
    const interval = setInterval(updateTime, 60000);
    return () => clearInterval(interval);
  }, []);

  const completedGoals = goals.filter(g => g.completed).length;
  const totalXp = goals.reduce((sum, g) => sum + (g.completed ? g.xpReward : 0), 0);
  const allCompleted = completedGoals === goals.length;
  const bonusXp = allCompleted ? 50 : 0;

  const handleClaimReward = () => {
    setClaimedReward(true);
  };

  return (
    <Card className="p-4 glass border-warning/20">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-warning/20">
            <Target className="h-4 w-4 text-warning" />
          </div>
          <div>
            <h3 className="font-semibold text-sm">Daily Goals</h3>
            <p className="text-[10px] text-muted-foreground flex items-center gap-1">
              <Clock className="h-3 w-3" />
              Resets in {timeRemaining}
            </p>
          </div>
        </div>
        <Badge variant="outline" className={`text-xs ${
          allCompleted ? "bg-success/10 text-success border-success/30" : ""
        }`}>
          {completedGoals}/{goals.length}
        </Badge>
      </div>

      {/* Progress Overview */}
      <div className="mb-4 p-3 rounded-lg bg-gradient-to-r from-warning/10 via-transparent to-transparent border border-warning/20">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-muted-foreground">Daily Progress</span>
          <span className="text-xs font-medium text-warning">
            {totalXp} / {goals.reduce((s, g) => s + g.xpReward, 0)} XP
          </span>
        </div>
        <Progress 
          value={(completedGoals / goals.length) * 100} 
          className="h-2"
        />
      </div>

      {/* Goals List */}
      <div className="space-y-2 mb-4">
        {goals.map((goal) => {
          const Icon = goal.icon;
          const progress = (goal.current / goal.target) * 100;
          
          return (
            <div
              key={goal.id}
              className={`
                p-2.5 rounded-lg border transition-all duration-300
                ${goal.completed 
                  ? 'bg-success/5 border-success/30' 
                  : 'bg-secondary/20 border-border/50'
                }
              `}
            >
              <div className="flex items-center gap-3">
                <div className={`
                  p-1.5 rounded-md
                  ${goal.completed ? 'bg-success/20 text-success' : 'bg-muted text-muted-foreground'}
                `}>
                  {goal.completed ? (
                    <CheckCircle2 className="h-4 w-4" />
                  ) : (
                    <Icon className="h-4 w-4" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <p className={`text-sm font-medium ${goal.completed ? 'text-success' : ''}`}>
                      {goal.title}
                    </p>
                    <Badge variant="outline" className="text-[10px] bg-primary/10 text-primary border-primary/30">
                      +{goal.xpReward} XP
                    </Badge>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <Progress value={progress} className="h-1 flex-1" />
                    <span className="text-[10px] text-muted-foreground whitespace-nowrap">
                      {goal.current}/{goal.target}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Bonus Reward */}
      {allCompleted && !claimedReward && (
        <div className="p-3 rounded-lg bg-gradient-to-r from-warning/20 to-primary/20 border border-warning/30 animate-pulse">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Gift className="h-5 w-5 text-warning" />
              <div>
                <p className="text-sm font-medium">All Goals Complete!</p>
                <p className="text-[10px] text-muted-foreground">Claim your bonus reward</p>
              </div>
            </div>
            <Button 
              size="sm" 
              className="h-7 text-xs gap-1"
              onClick={handleClaimReward}
            >
              <Sparkles className="h-3 w-3" />
              Claim +{bonusXp} XP
            </Button>
          </div>
        </div>
      )}

      {claimedReward && (
        <div className="p-3 rounded-lg bg-success/10 border border-success/30 text-center">
          <div className="flex items-center justify-center gap-2">
            <Star className="h-4 w-4 text-success" />
            <span className="text-sm text-success font-medium">Bonus Claimed! +50 XP</span>
          </div>
        </div>
      )}
    </Card>
  );
};

export default DailyGoals;
