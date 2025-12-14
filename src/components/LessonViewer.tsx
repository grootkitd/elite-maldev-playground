import { Card } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { BookOpen, Lightbulb, AlertTriangle, Code, CheckCircle2, Brain } from "lucide-react";
import { lessons } from "@/data/lessons";

interface LessonViewerProps {
  moduleId: string;
}

const LessonViewer = ({ moduleId }: LessonViewerProps) => {
  const currentLesson = lessons[moduleId];

  if (!currentLesson) {
    return (
      <Card className="flex flex-col glass h-full min-h-[500px]">
        <div className="flex-1 flex items-center justify-center p-8">
          <div className="text-center space-y-4">
            <BookOpen className="h-16 w-16 text-muted-foreground mx-auto opacity-50" />
            <p className="text-lg text-muted-foreground">Select a module to start learning</p>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <Card className="flex flex-col glass overflow-hidden h-full min-h-[500px]">
      {/* Header */}
      <div className="p-4 border-b border-border/50 bg-gradient-to-r from-primary/10 via-primary/5 to-transparent shrink-0">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/20 border border-primary/30">
            <BookOpen className="h-5 w-5 text-primary" />
          </div>
          <div className="min-w-0 flex-1">
            <h3 className="font-semibold text-foreground truncate">{currentLesson.title}</h3>
            <p className="text-xs text-muted-foreground truncate">{currentLesson.description}</p>
          </div>
        </div>
      </div>
      
      {/* Content */}
      <ScrollArea className="flex-1">
        <div className="p-4 md:p-6 space-y-6">
          {currentLesson.sections.map((section, idx) => (
            <div key={idx} className="space-y-4">
              {/* Intro Section */}
              {section.type === "intro" && (
                <div className="p-4 rounded-lg bg-primary/10 border-l-4 border-primary">
                  <p className="text-sm text-foreground leading-relaxed">{section.content}</p>
                </div>
              )}

              {/* Regular Section */}
              {!section.type && (
                <>
                  {/* Section Title */}
                  {section.title && (
                    <div className="flex items-start gap-3 pt-2">
                      <div className="mt-0.5 w-7 h-7 rounded-full bg-primary/20 flex items-center justify-center text-xs font-bold text-primary shrink-0">
                        {idx}
                      </div>
                      <h4 className="text-lg font-bold text-foreground">{section.title}</h4>
                    </div>
                  )}

                  {/* Main Content */}
                  {section.content && (
                    <div className="ml-10 space-y-3">
                      <div className="prose prose-sm max-w-none">
                        <p className="text-sm text-foreground/90 leading-relaxed whitespace-pre-line">
                          {section.content}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Key Concepts Box */}
                  {section.concepts && section.concepts.length > 0 && (
                    <div className="ml-10 p-4 rounded-lg bg-concept-bg/50 border border-concept-border/50">
                      <div className="flex items-center gap-2 mb-3">
                        <Brain className="h-4 w-4 text-concept-border" />
                        <h5 className="font-semibold text-concept-text text-xs uppercase tracking-wider">Key Concepts</h5>
                      </div>
                      <div className="space-y-2">
                        {section.concepts.map((concept, i) => (
                          <div key={i} className="flex gap-3 items-start">
                            <code className="text-xs font-mono text-concept-border bg-concept-bg px-2 py-0.5 rounded shrink-0">
                              {concept.label}
                            </code>
                            <p className="text-xs text-concept-text/90 leading-relaxed">
                              {concept.explanation}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Tip Box */}
                  {section.tip && (
                    <div className="ml-10 p-3 rounded-lg bg-tip-bg/50 border border-tip-border/50">
                      <div className="flex items-start gap-2">
                        <Lightbulb className="h-4 w-4 text-tip-border shrink-0 mt-0.5" />
                        <p className="text-xs text-tip-text leading-relaxed">{section.tip}</p>
                      </div>
                    </div>
                  )}

                  {/* Warning Box */}
                  {section.warning && (
                    <div className="ml-10 p-3 rounded-lg bg-warning/10 border border-warning/30">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-warning shrink-0 mt-0.5" />
                        <p className="text-xs text-warning leading-relaxed">{section.warning}</p>
                      </div>
                    </div>
                  )}

                  {/* Example Box */}
                  {section.example && (
                    <div className="ml-10 space-y-0">
                      <div className="p-3 rounded-t-lg bg-example-bg/50 border border-example-border/50 border-b-0">
                        <div className="flex items-center gap-2">
                          <Code className="h-4 w-4 text-example-border" />
                          <h5 className="font-semibold text-example-text text-xs">{section.example.title}</h5>
                        </div>
                        {section.example.description && (
                          <p className="text-xs text-example-text/70 mt-1 ml-6">
                            {section.example.description}
                          </p>
                        )}
                      </div>
                      <div className="relative">
                        <div className="absolute top-2 right-2 z-10">
                          <Badge variant="secondary" className="text-[10px] font-mono bg-background/80 backdrop-blur px-1.5 py-0.5">
                            {section.example.language || "c"}
                          </Badge>
                        </div>
                        <pre className="bg-code-bg p-4 rounded-b-lg overflow-x-auto text-xs border border-example-border/50 border-t-0 max-h-80">
                          <code className="text-foreground/90 font-mono whitespace-pre leading-relaxed text-[11px]">
                            {section.example.code}
                          </code>
                        </pre>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          ))}

          {/* Completion */}
          <div className="flex items-center justify-center gap-2 pt-4 border-t border-border/30">
            <CheckCircle2 className="h-4 w-4 text-success" />
            <p className="text-xs text-muted-foreground">
              Section complete - try the code in the editor
            </p>
          </div>
        </div>
      </ScrollArea>
    </Card>
  );
};

export default LessonViewer;
