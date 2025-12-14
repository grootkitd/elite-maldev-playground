import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Label } from "@/components/ui/label";
import { 
  Brain, CheckCircle2, XCircle, ChevronRight, 
  RotateCcw, Trophy, Zap, Star, Sparkles
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface Question {
  id: string;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation: string;
}

interface QuizSectionProps {
  moduleId: string;
}

const QuizSection = ({ moduleId }: QuizSectionProps) => {
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null);
  const [showResult, setShowResult] = useState(false);
  const [score, setScore] = useState(0);
  const [quizComplete, setQuizComplete] = useState(false);
  const { toast } = useToast();

  const questionsByModule: Record<string, Question[]> = {
    fundamentals: [
      {
        id: "q1",
        question: "What does DWORD guarantee that 'int' doesn't?",
        options: [
          "It's always signed",
          "It's always 32 bits",
          "It can hold pointers",
          "It's thread-safe"
        ],
        correctAnswer: 1,
        explanation: "DWORD is always exactly 32 bits on Windows, while 'int' can vary by compiler (16, 32, or 64 bits)."
      },
      {
        id: "q2",
        question: "When should you call GetLastError()?",
        options: [
          "At the start of your program",
          "After any function call",
          "Immediately after a function fails",
          "Before calling CloseHandle"
        ],
        correctAnswer: 2,
        explanation: "GetLastError() must be called IMMEDIATELY after a function fails. Any subsequent Windows API call may change the error code."
      },
      {
        id: "q3",
        question: "What does INVALID_HANDLE_VALUE equal?",
        options: [
          "0",
          "NULL",
          "-1 (0xFFFFFFFF)",
          "1"
        ],
        correctAnswer: 2,
        explanation: "INVALID_HANDLE_VALUE is -1 (0xFFFFFFFF). Note: Some functions return NULL instead, so check the documentation!"
      },
      {
        id: "q4",
        question: "Why should you use CreateFileW instead of CreateFileA?",
        options: [
          "CreateFileW is faster",
          "CreateFileA is deprecated",
          "CreateFileW supports Unicode filenames",
          "CreateFileW uses less memory"
        ],
        correctAnswer: 2,
        explanation: "The 'W' suffix means Wide/Unicode. This allows filenames in any language (Chinese, Japanese, etc.), not just ASCII."
      },
      {
        id: "q5",
        question: "What happens if you forget to call CloseHandle()?",
        options: [
          "Nothing, Windows cleans up automatically",
          "Your program crashes",
          "Handle/resource leak until process exits",
          "The file gets corrupted"
        ],
        correctAnswer: 2,
        explanation: "Forgetting CloseHandle() causes a resource leak. The handle stays allocated until your process terminates, potentially exhausting system resources."
      }
    ],
    shellcode: [
      {
        id: "s1",
        question: "What makes shellcode 'position independent'?",
        options: [
          "It's compiled with special flags",
          "It has no hardcoded memory addresses",
          "It runs in kernel mode",
          "It's encrypted"
        ],
        correctAnswer: 1,
        explanation: "Position Independent Code (PIC) works regardless of where it's loaded because it doesn't rely on hardcoded addresses - everything is resolved dynamically."
      },
      {
        id: "s2",
        question: "What's the main risk of PAGE_EXECUTE_READWRITE memory?",
        options: [
          "It's slower",
          "It uses more memory",
          "Security tools flag it as suspicious",
          "It can't be freed"
        ],
        correctAnswer: 2,
        explanation: "RWX memory is a major red flag for security tools because legitimate code rarely needs to write AND execute in the same memory region."
      },
      {
        id: "s3",
        question: "In 'staged' shellcode, what does the stager do?",
        options: [
          "Encrypts the payload",
          "Downloads and executes the main payload",
          "Escalates privileges",
          "Evades detection"
        ],
        correctAnswer: 1,
        explanation: "A stager is small code that downloads (or otherwise retrieves) the larger main payload and executes it. This keeps the initial payload size small."
      }
    ],
    evasion: [
      {
        id: "e1",
        question: "Where do EDR user-mode hooks typically exist?",
        options: [
          "In the kernel",
          "In ntdll.dll",
          "In your executable",
          "In the registry"
        ],
        correctAnswer: 1,
        explanation: "EDRs typically hook functions in ntdll.dll because it's the gateway to all system calls. They insert jumps at function starts to redirect to their inspection code."
      },
      {
        id: "e2",
        question: "What's the main benefit of direct syscalls?",
        options: [
          "They're faster",
          "They bypass user-mode hooks",
          "They require less code",
          "They work on all Windows versions"
        ],
        correctAnswer: 1,
        explanation: "Direct syscalls skip ntdll.dll entirely, bypassing any hooks placed there. The 'syscall' instruction goes straight to the kernel."
      }
    ]
  };

  const questions = questionsByModule[moduleId] || questionsByModule.fundamentals;
  const current = questions[currentQuestion];

  const handleAnswer = () => {
    if (selectedAnswer === null) return;
    
    const isCorrect = selectedAnswer === current.correctAnswer;
    
    if (isCorrect) {
      setScore(score + 1);
      toast({
        title: "Correct! 🎉",
        description: current.explanation,
        duration: 4000,
      });
    } else {
      toast({
        title: "Not quite!",
        description: current.explanation,
        variant: "destructive",
        duration: 4000,
      });
    }
    
    setShowResult(true);
  };

  const nextQuestion = () => {
    if (currentQuestion < questions.length - 1) {
      setCurrentQuestion(currentQuestion + 1);
      setSelectedAnswer(null);
      setShowResult(false);
    } else {
      setQuizComplete(true);
    }
  };

  const resetQuiz = () => {
    setCurrentQuestion(0);
    setSelectedAnswer(null);
    setShowResult(false);
    setScore(0);
    setQuizComplete(false);
  };

  if (quizComplete) {
    const percentage = Math.round((score / questions.length) * 100);
    const xpEarned = score * 10;
    
    return (
      <Card className="p-6 glass text-center">
        <div className="mb-6">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-gradient-to-br from-primary/20 to-primary/5 flex items-center justify-center border border-primary/30 shadow-glow-md">
            <Trophy className="h-8 w-8 text-primary" />
          </div>
          <h3 className="text-xl font-bold mb-2">Quiz Complete!</h3>
          <p className="text-muted-foreground">
            You scored {score} out of {questions.length} ({percentage}%)
          </p>
        </div>
        
        <div className="grid grid-cols-2 gap-4 mb-6">
          <div className="p-4 rounded-lg bg-success/10 border border-success/30">
            <CheckCircle2 className="h-6 w-6 text-success mx-auto mb-2" />
            <p className="text-2xl font-bold text-success">{score}</p>
            <p className="text-xs text-muted-foreground">Correct</p>
          </div>
          <div className="p-4 rounded-lg bg-primary/10 border border-primary/30">
            <Star className="h-6 w-6 text-primary mx-auto mb-2" />
            <p className="text-2xl font-bold text-primary">+{xpEarned}</p>
            <p className="text-xs text-muted-foreground">XP Earned</p>
          </div>
        </div>

        {percentage >= 80 && (
          <div className="mb-6 p-4 rounded-lg bg-warning/10 border border-warning/30">
            <Sparkles className="h-5 w-5 text-warning mx-auto mb-2" />
            <p className="text-sm font-medium text-warning">Excellent! Module mastery achieved!</p>
          </div>
        )}

        <Button onClick={resetQuiz} className="gap-2">
          <RotateCcw className="h-4 w-4" />
          Try Again
        </Button>
      </Card>
    );
  }

  return (
    <Card className="p-4 glass">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-primary/20">
            <Brain className="h-4 w-4 text-primary" />
          </div>
          <h3 className="font-semibold text-sm">Quick Quiz</h3>
        </div>
        <Badge variant="outline" className="text-xs">
          {currentQuestion + 1}/{questions.length}
        </Badge>
      </div>

      {/* Progress */}
      <div className="flex gap-1 mb-4">
        {questions.map((_, idx) => (
          <div
            key={idx}
            className={`
              h-1 flex-1 rounded-full transition-all duration-300
              ${idx < currentQuestion 
                ? 'bg-success' 
                : idx === currentQuestion 
                  ? 'bg-primary' 
                  : 'bg-muted'
              }
            `}
          />
        ))}
      </div>

      {/* Question */}
      <div className="mb-4">
        <p className="font-medium mb-4">{current.question}</p>
        
        <RadioGroup
          value={selectedAnswer?.toString()}
          onValueChange={(val) => !showResult && setSelectedAnswer(parseInt(val))}
          className="space-y-2"
        >
          {current.options.map((option, idx) => {
            const isCorrect = idx === current.correctAnswer;
            const isSelected = idx === selectedAnswer;
            
            return (
              <div
                key={idx}
                className={`
                  flex items-center space-x-3 p-3 rounded-lg border transition-all
                  ${showResult
                    ? isCorrect
                      ? 'bg-success/10 border-success/50'
                      : isSelected
                        ? 'bg-destructive/10 border-destructive/50'
                        : 'border-border/50'
                    : isSelected
                      ? 'bg-primary/10 border-primary/50'
                      : 'border-border/50 hover:border-primary/30'
                  }
                  ${!showResult ? 'cursor-pointer' : 'cursor-default'}
                `}
              >
                <RadioGroupItem value={idx.toString()} id={`opt-${idx}`} disabled={showResult} />
                <Label htmlFor={`opt-${idx}`} className="flex-1 cursor-pointer text-sm">
                  {option}
                </Label>
                {showResult && isCorrect && (
                  <CheckCircle2 className="h-4 w-4 text-success" />
                )}
                {showResult && isSelected && !isCorrect && (
                  <XCircle className="h-4 w-4 text-destructive" />
                )}
              </div>
            );
          })}
        </RadioGroup>
      </div>

      {/* Actions */}
      <div className="flex justify-between">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Zap className="h-3 w-3" />
          <span>+10 XP per correct answer</span>
        </div>
        
        {!showResult ? (
          <Button
            size="sm"
            onClick={handleAnswer}
            disabled={selectedAnswer === null}
          >
            Check Answer
          </Button>
        ) : (
          <Button size="sm" onClick={nextQuestion} className="gap-1">
            {currentQuestion < questions.length - 1 ? 'Next' : 'Finish'}
            <ChevronRight className="h-4 w-4" />
          </Button>
        )}
      </div>
    </Card>
  );
};

export default QuizSection;
