import { useState } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Progress } from "@/components/ui/progress";
import { 
  CheckCircle2, 
  Circle, 
  ChevronDown, 
  ChevronRight,
  Target,
  Shield,
  Zap,
  Key,
  Users,
  Server,
  Network,
  Lock,
  AlertTriangle,
  Skull
} from "lucide-react";

interface Technique {
  id: string;
  name: string;
  description: string;
  difficulty: "easy" | "medium" | "hard" | "expert";
  mitre?: string;
  tools?: string[];
}

interface TechniqueCategory {
  id: string;
  name: string;
  icon: any;
  techniques: Technique[];
}

interface TechniquesChecklistProps {
  moduleId: string;
}

const techniquesByModule: Record<string, TechniqueCategory[]> = {
  "active-directory": [
    {
      id: "recon",
      name: "Reconnaissance & Enumeration",
      icon: Target,
      techniques: [
        { id: "ad1", name: "Domain Enumeration", description: "Identify domain controllers, trusts, and domain structure", difficulty: "easy", mitre: "T1087", tools: ["PowerView", "ADModule", "BloodHound"] },
        { id: "ad2", name: "User Enumeration", description: "List domain users, groups, and their properties", difficulty: "easy", mitre: "T1087.002", tools: ["net user /domain", "Get-ADUser"] },
        { id: "ad3", name: "Group Enumeration", description: "Identify high-value groups (Domain Admins, Enterprise Admins)", difficulty: "easy", mitre: "T1069.002", tools: ["PowerView", "ADModule"] },
        { id: "ad4", name: "Computer Enumeration", description: "Find all domain computers, DCs, and servers", difficulty: "easy", tools: ["Get-ADComputer", "PowerView"] },
        { id: "ad5", name: "ACL Enumeration", description: "Find exploitable ACLs and permissions", difficulty: "medium", mitre: "T1003", tools: ["PowerView", "BloodHound"] },
        { id: "ad6", name: "GPO Enumeration", description: "List Group Policy Objects and their settings", difficulty: "medium", tools: ["Get-GPO", "PowerView"] },
        { id: "ad7", name: "SPN Scanning", description: "Find Service Principal Names for Kerberoasting", difficulty: "medium", mitre: "T1558.003", tools: ["GetUserSPNs.py", "PowerView"] },
        { id: "ad8", name: "Trust Enumeration", description: "Map domain and forest trusts", difficulty: "medium", tools: ["nltest", "PowerView"] },
      ]
    },
    {
      id: "initial-access",
      name: "Initial Access & Credential Attacks",
      icon: Key,
      techniques: [
        { id: "ia1", name: "Password Spraying", description: "Try common passwords against many accounts", difficulty: "easy", mitre: "T1110.003", tools: ["Spray", "DomainPasswordSpray"] },
        { id: "ia2", name: "LLMNR/NBT-NS Poisoning", description: "Capture hashes via name resolution poisoning", difficulty: "easy", mitre: "T1557.001", tools: ["Responder", "Inveigh"] },
        { id: "ia3", name: "SMB Relay", description: "Relay captured NTLM auth to other hosts", difficulty: "medium", mitre: "T1557.001", tools: ["ntlmrelayx", "Responder"] },
        { id: "ia4", name: "ASREPRoasting", description: "Target accounts with Kerberos pre-auth disabled", difficulty: "medium", mitre: "T1558.004", tools: ["GetNPUsers.py", "Rubeus"] },
        { id: "ia5", name: "Kerberoasting", description: "Request TGS tickets and crack service account hashes", difficulty: "medium", mitre: "T1558.003", tools: ["GetUserSPNs.py", "Rubeus"] },
        { id: "ia6", name: "NTLM Hash Extraction", description: "Extract hashes from SAM/SYSTEM/NTDS", difficulty: "medium", mitre: "T1003", tools: ["secretsdump.py", "mimikatz"] },
      ]
    },
    {
      id: "priv-esc",
      name: "Privilege Escalation",
      icon: Zap,
      techniques: [
        { id: "pe1", name: "Token Impersonation", description: "Steal and use tokens from other processes", difficulty: "medium", mitre: "T1134", tools: ["Incognito", "mimikatz"] },
        { id: "pe2", name: "GPO Abuse", description: "Exploit writable GPOs to gain code execution", difficulty: "medium", mitre: "T1484.001", tools: ["SharpGPOAbuse", "PowerView"] },
        { id: "pe3", name: "ACL Abuse - GenericAll", description: "Full control over objects (reset passwords, add to groups)", difficulty: "medium", tools: ["PowerView", "BloodHound"] },
        { id: "pe4", name: "ACL Abuse - WriteDACL", description: "Modify permissions on AD objects", difficulty: "hard", tools: ["PowerView", "dacledit.py"] },
        { id: "pe5", name: "ACL Abuse - WriteOwner", description: "Take ownership of AD objects", difficulty: "hard", tools: ["PowerView"] },
        { id: "pe6", name: "Unconstrained Delegation", description: "Extract TGTs from hosts with unconstrained delegation", difficulty: "hard", mitre: "T1558", tools: ["Rubeus", "mimikatz"] },
        { id: "pe7", name: "Constrained Delegation", description: "Abuse S4U2Self/S4U2Proxy for privilege escalation", difficulty: "expert", mitre: "T1558", tools: ["Rubeus", "getST.py"] },
        { id: "pe8", name: "Resource-Based Constrained Delegation", description: "Abuse msDS-AllowedToActOnBehalfOfOtherIdentity", difficulty: "expert", tools: ["Rubeus", "PowerView"] },
      ]
    },
    {
      id: "lateral",
      name: "Lateral Movement",
      icon: Network,
      techniques: [
        { id: "lm1", name: "Pass-the-Hash", description: "Use NTLM hash to authenticate without password", difficulty: "easy", mitre: "T1550.002", tools: ["pth-winexe", "mimikatz", "Impacket"] },
        { id: "lm2", name: "Pass-the-Ticket", description: "Use stolen Kerberos tickets for authentication", difficulty: "medium", mitre: "T1550.003", tools: ["Rubeus", "mimikatz"] },
        { id: "lm3", name: "Overpass-the-Hash", description: "Convert NTLM hash to Kerberos ticket", difficulty: "medium", mitre: "T1550.002", tools: ["Rubeus", "mimikatz"] },
        { id: "lm4", name: "WMI Execution", description: "Remote command execution via WMI", difficulty: "easy", mitre: "T1047", tools: ["wmiexec.py", "Invoke-WMIMethod"] },
        { id: "lm5", name: "PSRemoting", description: "PowerShell Remoting for lateral movement", difficulty: "easy", mitre: "T1021.006", tools: ["Enter-PSSession", "evil-winrm"] },
        { id: "lm6", name: "SMB/Admin Shares", description: "Use admin shares (C$, ADMIN$) for file transfer", difficulty: "easy", mitre: "T1021.002", tools: ["PsExec", "smbexec.py"] },
        { id: "lm7", name: "DCOM Execution", description: "Abuse DCOM objects for remote execution", difficulty: "hard", mitre: "T1021.003", tools: ["dcomexec.py", "Invoke-DCOM"] },
      ]
    },
    {
      id: "persistence",
      name: "Persistence",
      icon: Lock,
      techniques: [
        { id: "ps1", name: "Golden Ticket", description: "Forge TGT with KRBTGT hash for unlimited access", difficulty: "hard", mitre: "T1558.001", tools: ["mimikatz", "ticketer.py"] },
        { id: "ps2", name: "Silver Ticket", description: "Forge TGS for specific service access", difficulty: "medium", mitre: "T1558.002", tools: ["mimikatz", "ticketer.py"] },
        { id: "ps3", name: "Skeleton Key", description: "Patch LSASS to add master password", difficulty: "expert", mitre: "T1556", tools: ["mimikatz"] },
        { id: "ps4", name: "DCSync", description: "Replicate DC data to extract all hashes", difficulty: "hard", mitre: "T1003.006", tools: ["mimikatz", "secretsdump.py"] },
        { id: "ps5", name: "DCShadow", description: "Create rogue DC to push malicious changes", difficulty: "expert", mitre: "T1207", tools: ["mimikatz"] },
        { id: "ps6", name: "AdminSDHolder Abuse", description: "Backdoor protected groups via AdminSDHolder", difficulty: "hard", tools: ["PowerView"] },
        { id: "ps7", name: "SID History Injection", description: "Add privileged SIDs to user's SID history", difficulty: "expert", mitre: "T1134.005", tools: ["mimikatz"] },
      ]
    },
    {
      id: "domain-dom",
      name: "Domain Dominance",
      icon: Skull,
      techniques: [
        { id: "dd1", name: "KRBTGT Hash Extraction", description: "Extract KRBTGT hash for Golden Ticket attacks", difficulty: "hard", mitre: "T1003.006", tools: ["secretsdump.py", "mimikatz"] },
        { id: "dd2", name: "NTDS.dit Extraction", description: "Dump entire AD database", difficulty: "hard", mitre: "T1003.003", tools: ["ntdsutil", "secretsdump.py"] },
        { id: "dd3", name: "Forest Trust Abuse", description: "Exploit trust relationships for cross-forest access", difficulty: "expert", tools: ["Rubeus", "PowerView"] },
        { id: "dd4", name: "Print Spooler Abuse", description: "Coerce authentication from DCs (PrinterBug)", difficulty: "medium", mitre: "T1557", tools: ["SpoolSample", "printerbug.py"] },
        { id: "dd5", name: "ADCS Abuse", description: "Exploit AD Certificate Services misconfigurations", difficulty: "hard", tools: ["Certify", "Certipy"] },
        { id: "dd6", name: "Shadow Credentials", description: "Abuse msDS-KeyCredentialLink for persistence", difficulty: "hard", tools: ["Whisker", "pywhisker"] },
      ]
    }
  ]
};

const TechniquesChecklist = ({ moduleId }: TechniquesChecklistProps) => {
  const [completedTechniques, setCompletedTechniques] = useState<Set<string>>(new Set());
  const [expandedCategories, setExpandedCategories] = useState<Set<string>>(new Set(["recon"]));

  const categories = techniquesByModule[moduleId] || [];
  const totalTechniques = categories.reduce((sum, cat) => sum + cat.techniques.length, 0);
  const completedCount = completedTechniques.size;
  const progressPercentage = totalTechniques > 0 ? (completedCount / totalTechniques) * 100 : 0;

  const toggleTechnique = (id: string) => {
    setCompletedTechniques(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const toggleCategory = (id: string) => {
    setExpandedCategories(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case "easy": return "bg-success/20 text-success border-success/30";
      case "medium": return "bg-warning/20 text-warning border-warning/30";
      case "hard": return "bg-destructive/20 text-destructive border-destructive/30";
      case "expert": return "bg-purple-500/20 text-purple-400 border-purple-500/30";
      default: return "bg-muted text-muted-foreground";
    }
  };

  if (categories.length === 0) {
    return (
      <Card className="p-8 bg-card/50 border-border/50 text-center">
        <AlertTriangle className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
        <p className="text-muted-foreground">No techniques checklist available for this module.</p>
      </Card>
    );
  }

  return (
    <Card className="bg-card/50 border-border/50 backdrop-blur overflow-hidden">
      {/* Header with Progress */}
      <div className="p-6 border-b border-border/50 bg-gradient-to-r from-primary/10 to-transparent">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/20">
              <Target className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h3 className="font-bold text-foreground">Attack Techniques Checklist</h3>
              <p className="text-sm text-muted-foreground">Track your progress through AD attack techniques</p>
            </div>
          </div>
          <Badge variant="outline" className="text-primary border-primary/50">
            {completedCount}/{totalTechniques} Complete
          </Badge>
        </div>
        <Progress value={progressPercentage} className="h-2" />
      </div>

      {/* Categories */}
      <ScrollArea className="h-[500px]">
        <div className="p-4 space-y-3">
          {categories.map((category) => {
            const Icon = category.icon;
            const isExpanded = expandedCategories.has(category.id);
            const categoryCompleted = category.techniques.filter(t => completedTechniques.has(t.id)).length;

            return (
              <div key={category.id} className="border border-border/50 rounded-lg overflow-hidden">
                {/* Category Header */}
                <button
                  onClick={() => toggleCategory(category.id)}
                  className="w-full flex items-center justify-between p-4 bg-muted/30 hover:bg-muted/50 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <Icon className="h-5 w-5 text-primary" />
                    <span className="font-semibold text-foreground">{category.name}</span>
                    <Badge variant="secondary" className="text-xs">
                      {categoryCompleted}/{category.techniques.length}
                    </Badge>
                  </div>
                  {isExpanded ? (
                    <ChevronDown className="h-5 w-5 text-muted-foreground" />
                  ) : (
                    <ChevronRight className="h-5 w-5 text-muted-foreground" />
                  )}
                </button>

                {/* Techniques List */}
                {isExpanded && (
                  <div className="p-3 space-y-2 bg-background/50">
                    {category.techniques.map((technique) => {
                      const isCompleted = completedTechniques.has(technique.id);
                      return (
                        <div
                          key={technique.id}
                          onClick={() => toggleTechnique(technique.id)}
                          className={`p-3 rounded-lg border cursor-pointer transition-all duration-200 ${
                            isCompleted 
                              ? "bg-success/10 border-success/30" 
                              : "bg-card/50 border-border/50 hover:border-primary/50 hover:bg-primary/5"
                          }`}
                        >
                          <div className="flex items-start gap-3">
                            <div className="mt-0.5">
                              {isCompleted ? (
                                <CheckCircle2 className="h-5 w-5 text-success" />
                              ) : (
                                <Circle className="h-5 w-5 text-muted-foreground" />
                              )}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className={`font-medium ${isCompleted ? "text-success" : "text-foreground"}`}>
                                  {technique.name}
                                </span>
                                <Badge className={`text-xs ${getDifficultyColor(technique.difficulty)}`}>
                                  {technique.difficulty}
                                </Badge>
                                {technique.mitre && (
                                  <Badge variant="outline" className="text-xs text-muted-foreground">
                                    {technique.mitre}
                                  </Badge>
                                )}
                              </div>
                              <p className="text-sm text-muted-foreground mt-1">{technique.description}</p>
                              {technique.tools && technique.tools.length > 0 && (
                                <div className="flex flex-wrap gap-1 mt-2">
                                  {technique.tools.map((tool, idx) => (
                                    <span key={idx} className="text-xs px-2 py-0.5 rounded bg-muted text-muted-foreground">
                                      {tool}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </ScrollArea>
    </Card>
  );
};

export default TechniquesChecklist;
