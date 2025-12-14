import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { 
  Rocket, BookOpen, Code2, Shield, Zap, ChevronRight, 
  CheckCircle2, Target, Users, Award, ArrowRight, Sparkles, Play
} from "lucide-react";

interface WelcomeOnboardingProps {
  onGetStarted: () => void;
  onDismiss: () => void;
}

const WelcomeOnboarding = ({ onGetStarted, onDismiss }: WelcomeOnboardingProps) => {
  const [currentStep, setCurrentStep] = useState(0);

  const steps = [
    {
      title: "Welcome to REDTEAM-DEV",
      subtitle: "Your journey into Windows security starts here",
      icon: Shield,
      content: (
        <div className="space-y-4">
          <p className="text-muted-foreground">
            This platform will teach you offensive security from the ground up. 
            Whether you're a complete beginner or looking to level up your skills, 
            we've got you covered.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {[
              { icon: BookOpen, label: "Structured Lessons", desc: "Theory + Practice" },
              { icon: Code2, label: "Hands-on Labs", desc: "Real code examples" },
              { icon: Target, label: "Challenges", desc: "Test your skills" },
            ].map((item, idx) => (
              <div key={idx} className="p-3 rounded-lg bg-secondary/30 border border-border/50 text-center">
                <item.icon className="h-5 w-5 mx-auto mb-2 text-primary" />
                <p className="text-sm font-medium">{item.label}</p>
                <p className="text-[10px] text-muted-foreground">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      )
    },
    {
      title: "No Prior Experience Required",
      subtitle: "We start from the very basics",
      icon: Rocket,
      content: (
        <div className="space-y-4">
          <p className="text-muted-foreground">
            Our curriculum is designed for beginners. You'll learn:
          </p>
          <div className="space-y-3">
            {[
              { label: "Windows Fundamentals", desc: "How Windows works under the hood", done: false },
              { label: "C/C++ Basics", desc: "Essential programming for security", done: false },
              { label: "The Win32 API", desc: "Interacting with the operating system", done: false },
              { label: "Security Concepts", desc: "Offensive and defensive techniques", done: false },
            ].map((item, idx) => (
              <div key={idx} className="flex items-center gap-3 p-2 rounded-lg bg-secondary/20">
                <div className="p-1 rounded bg-primary/20">
                  <CheckCircle2 className="h-4 w-4 text-primary" />
                </div>
                <div>
                  <p className="text-sm font-medium">{item.label}</p>
                  <p className="text-[10px] text-muted-foreground">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )
    },
    {
      title: "Your Learning Path",
      subtitle: "Follow a structured roadmap to mastery",
      icon: Zap,
      content: (
        <div className="space-y-4">
          <p className="text-muted-foreground">
            We've created a clear path from beginner to expert:
          </p>
          <div className="relative">
            <div className="absolute left-4 top-6 bottom-6 w-0.5 bg-gradient-to-b from-success via-warning to-destructive" />
            <div className="space-y-3">
              {[
                { level: "Beginner", modules: ["Fundamentals", "Windows Internals"], color: "success" },
                { level: "Intermediate", modules: ["Shellcode", "P/Invoke"], color: "info" },
                { level: "Advanced", modules: ["Injection", "Syscalls"], color: "warning" },
                { level: "Expert", modules: ["Evasion", "AD Attacks"], color: "destructive" },
              ].map((stage, idx) => (
                <div key={idx} className="flex items-center gap-3 ml-8">
                  <Badge variant="outline" className={`bg-${stage.color}/10 text-${stage.color} border-${stage.color}/30`}>
                    {stage.level}
                  </Badge>
                  <span className="text-sm text-muted-foreground">
                    {stage.modules.join(" → ")}
                  </span>
                </div>
              ))}
            </div>
          </div>
          <div className="p-3 rounded-lg bg-tip-bg/50 border border-tip-border/50 mt-4">
            <p className="text-sm">
              💡 <strong>Tip:</strong> Complete modules in order to unlock advanced content. 
              Each module builds on what you learned before.
            </p>
          </div>
        </div>
      )
    },
    {
      title: "Ready to Begin?",
      subtitle: "Start with the fundamentals",
      icon: Play,
      content: (
        <div className="space-y-4">
          <p className="text-muted-foreground">
            We recommend starting with <strong>C/C++ WinAPI Basics</strong>. 
            This module will give you the foundation for everything else.
          </p>
          <div className="p-4 rounded-lg glass border border-primary/30 shadow-glow-sm">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-lg bg-primary/20">
                <Code2 className="h-6 w-6 text-primary" />
              </div>
              <div className="flex-1">
                <h4 className="font-semibold">C/C++ WinAPI Basics</h4>
                <p className="text-sm text-muted-foreground mb-2">
                  Essential Windows programming foundations
                </p>
                <div className="flex items-center gap-2 text-xs">
                  <Badge variant="outline" className="bg-success/10 text-success border-success/30">
                    Beginner
                  </Badge>
                  <span className="text-muted-foreground">~8 hours</span>
                  <span className="text-muted-foreground">•</span>
                  <span className="text-muted-foreground">5 lessons</span>
                </div>
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Award className="h-4 w-4 text-warning" />
            <span>Complete this module to earn your first badge!</span>
          </div>
        </div>
      )
    }
  ];

  const currentStepData = steps[currentStep];
  const Icon = currentStepData.icon;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm animate-fade-in">
      <Card className="w-full max-w-2xl mx-4 p-0 glass glow-box overflow-hidden">
        {/* Header */}
        <div className="p-6 pb-4 border-b border-border/50 bg-gradient-to-r from-primary/10 via-transparent to-transparent">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-primary/20 border border-primary/30 shadow-glow-sm">
              <Icon className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h2 className="text-xl font-bold font-display gradient-text">
                {currentStepData.title}
              </h2>
              <p className="text-sm text-muted-foreground">
                {currentStepData.subtitle}
              </p>
            </div>
          </div>
        </div>

        {/* Content */}
        <div className="p-6 min-h-[300px]">
          {currentStepData.content}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-border/50 bg-secondary/20 flex items-center justify-between">
          {/* Progress Dots */}
          <div className="flex items-center gap-2">
            {steps.map((_, idx) => (
              <button
                key={idx}
                onClick={() => setCurrentStep(idx)}
                className={`
                  w-2 h-2 rounded-full transition-all duration-300
                  ${idx === currentStep 
                    ? 'w-6 bg-primary' 
                    : idx < currentStep 
                      ? 'bg-primary/50' 
                      : 'bg-muted-foreground/30'
                  }
                `}
              />
            ))}
          </div>

          {/* Navigation */}
          <div className="flex items-center gap-2">
            {currentStep > 0 && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setCurrentStep(currentStep - 1)}
              >
                Back
              </Button>
            )}
            {currentStep < steps.length - 1 ? (
              <Button
                size="sm"
                onClick={() => setCurrentStep(currentStep + 1)}
                className="gap-2"
              >
                Next
                <ChevronRight className="h-4 w-4" />
              </Button>
            ) : (
              <Button
                size="sm"
                onClick={onGetStarted}
                className="gap-2 bg-primary hover:bg-primary/90"
              >
                <Sparkles className="h-4 w-4" />
                Start Learning
              </Button>
            )}
          </div>
        </div>

        {/* Skip Button */}
        <button
          onClick={onDismiss}
          className="absolute top-4 right-4 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          Skip intro
        </button>
      </Card>
    </div>
  );
};

export default WelcomeOnboarding;
