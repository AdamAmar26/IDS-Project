"use client";

import { useQuery } from "@tanstack/react-query";
import { api, type Incident } from "@/lib/api";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const TACTIC_ORDER = [
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0003", name: "Persistence" },
  { id: "TA0004", name: "Privilege Escalation" },
  { id: "TA0005", name: "Defense Evasion" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0008", name: "Lateral Movement" },
  { id: "TA0009", name: "Collection" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0011", name: "Command and Control" },
  { id: "TA0040", name: "Impact" },
];

const TECHNIQUE_DB: Record<string, { name: string; tactics: string[] }> = {
  T1078: { name: "Valid Accounts", tactics: ["TA0001", "TA0003", "TA0004", "TA0005"] },
  T1071: { name: "Application Layer Protocol", tactics: ["TA0011"] },
  T1046: { name: "Network Service Discovery", tactics: ["TA0007"] },
  T1110: { name: "Brute Force", tactics: ["TA0006"] },
  T1059: { name: "Command and Scripting Interpreter", tactics: ["TA0002"] },
  T1562: { name: "Impair Defenses", tactics: ["TA0005"] },
  T1048: { name: "Exfiltration Over Alternative Protocol", tactics: ["TA0010"] },
  T1021: { name: "Remote Services", tactics: ["TA0008"] },
};

function buildHeatmap(incidents: Incident[]) {
  const counts: Record<string, number> = {};
  for (const inc of incidents) {
    for (const tech of inc.mitre_techniques) {
      const id = typeof tech === "string" ? tech : tech.id;
      counts[id] = (counts[id] || 0) + 1;
    }
  }
  return counts;
}

function heatColor(count: number, max: number): string {
  if (count === 0) return "bg-secondary/30";
  const ratio = count / Math.max(max, 1);
  if (ratio > 0.66) return "bg-red-500/60";
  if (ratio > 0.33) return "bg-orange-500/40";
  return "bg-yellow-500/30";
}

export default function MitrePage() {
  const { data: incidents } = useQuery<Incident[]>({
    queryKey: ["incidents-mitre"],
    queryFn: () => api.getIncidents("limit=200"),
  });

  const counts = buildHeatmap(incidents ?? []);
  const maxCount = Math.max(...Object.values(counts), 1);

  const tacticTechniques: Record<string, string[]> = {};
  for (const tactic of TACTIC_ORDER) {
    tacticTechniques[tactic.id] = [];
  }
  for (const [techId, info] of Object.entries(TECHNIQUE_DB)) {
    for (const tactic of info.tactics) {
      if (tacticTechniques[tactic]) {
        tacticTechniques[tactic].push(techId);
      }
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">MITRE ATT&CK Matrix</h1>
      <p className="text-muted-foreground text-sm">
        Heatmap of detected techniques across all incidents. Darker cells indicate higher detection frequency.
      </p>

      <Card>
        <CardContent className="p-6 overflow-x-auto">
          <div className="grid gap-3" style={{ gridTemplateColumns: `repeat(${TACTIC_ORDER.length}, minmax(120px, 1fr))` }}>
            {TACTIC_ORDER.map((tactic) => (
              <div key={tactic.id} className="space-y-2">
                <div className="text-xs font-bold text-center px-1 py-2 bg-primary/10 rounded-md">
                  <div className="text-primary">{tactic.id}</div>
                  <div className="text-foreground mt-0.5">{tactic.name}</div>
                </div>
                {(tacticTechniques[tactic.id] ?? []).map((techId) => {
                  const count = counts[techId] || 0;
                  const info = TECHNIQUE_DB[techId];
                  return (
                    <a
                      key={techId}
                      href={`https://attack.mitre.org/techniques/${techId}/`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className={cn(
                        "block text-xs p-2 rounded-md text-center transition-all hover:ring-1 hover:ring-primary",
                        heatColor(count, maxCount),
                      )}
                    >
                      <div className="font-mono font-bold">{techId}</div>
                      <div className="mt-0.5 text-muted-foreground">
                        {info?.name}
                      </div>
                      {count > 0 && (
                        <div className="mt-1 text-foreground font-semibold">
                          {count} hit{count > 1 ? "s" : ""}
                        </div>
                      )}
                    </a>
                  );
                })}
                {(tacticTechniques[tactic.id] ?? []).length === 0 && (
                  <div className="text-xs text-muted-foreground text-center py-4">
                    No techniques
                  </div>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Detection Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <p className="text-3xl font-bold">{Object.keys(counts).length}</p>
              <p className="text-sm text-muted-foreground">Unique Techniques</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold">
                {new Set(
                  Object.keys(counts).flatMap(
                    (t) => TECHNIQUE_DB[t]?.tactics ?? [],
                  ),
                ).size}
              </p>
              <p className="text-sm text-muted-foreground">Tactics Covered</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold">
                {Object.values(counts).reduce((a, b) => a + b, 0)}
              </p>
              <p className="text-sm text-muted-foreground">Total Detections</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold">{(incidents ?? []).length}</p>
              <p className="text-sm text-muted-foreground">Incidents Analyzed</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
