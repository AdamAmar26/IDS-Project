"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Incident } from "@/lib/api";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { severityColor, formatTimestamp, cn } from "@/lib/utils";
import { ChevronRight, ExternalLink } from "lucide-react";

export default function IncidentsPage() {
  const [selected, setSelected] = useState<number | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const queryClient = useQueryClient();

  const { data: incidents } = useQuery<Incident[]>({
    queryKey: ["incidents", statusFilter],
    queryFn: () => api.getIncidents(statusFilter ? `status=${statusFilter}` : ""),
  });

  const { data: detail } = useQuery<Incident>({
    queryKey: ["incident", selected],
    queryFn: () => api.getIncident(selected!),
    enabled: selected !== null,
  });

  const mutation = useMutation({
    mutationFn: ({ id, status }: { id: number; status: string }) =>
      api.patchIncidentStatus(id, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["incident", selected] });
    },
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Incidents</h1>
        <div className="flex gap-2">
          {["", "open", "acknowledged", "resolved"].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={cn(
                "px-3 py-1 rounded-md text-sm transition-colors",
                statusFilter === s
                  ? "bg-primary text-primary-foreground"
                  : "bg-secondary text-secondary-foreground hover:bg-accent",
              )}
            >
              {s || "All"}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 space-y-3">
          {(incidents ?? []).map((inc) => (
            <Card
              key={inc.id}
              className={cn(
                "cursor-pointer transition-colors hover:border-primary/50",
                selected === inc.id && "border-primary",
              )}
              onClick={() => setSelected(inc.id)}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <Badge className={severityColor(inc.severity)}>
                        {inc.severity.toUpperCase()}
                      </Badge>
                      <span className="text-sm text-muted-foreground">
                        #{inc.id}
                      </span>
                    </div>
                    <p className="text-sm line-clamp-2">{inc.summary}</p>
                    <p className="text-xs text-muted-foreground">
                      {formatTimestamp(inc.created_at)}
                    </p>
                  </div>
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                </div>
              </CardContent>
            </Card>
          ))}
          {(incidents ?? []).length === 0 && (
            <p className="text-muted-foreground text-center py-8">
              No incidents found
            </p>
          )}
        </div>

        <div className="lg:col-span-2">
          {detail ? (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="flex items-center gap-3">
                    Incident #{detail.id}
                    <Badge className={severityColor(detail.severity)}>
                      {detail.severity.toUpperCase()}
                    </Badge>
                    <Badge variant="outline">{detail.status}</Badge>
                  </CardTitle>
                  <div className="flex gap-2">
                    {detail.status === "open" && (
                      <button
                        className="px-3 py-1 rounded-md text-sm bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30"
                        onClick={() =>
                          mutation.mutate({ id: detail.id, status: "acknowledged" })
                        }
                      >
                        Acknowledge
                      </button>
                    )}
                    {detail.status !== "resolved" && (
                      <button
                        className="px-3 py-1 rounded-md text-sm bg-green-500/20 text-green-400 hover:bg-green-500/30"
                        onClick={() =>
                          mutation.mutate({ id: detail.id, status: "resolved" })
                        }
                      >
                        Resolve
                      </button>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <h4 className="text-sm font-semibold text-muted-foreground mb-1">
                    Summary
                  </h4>
                  <p className="text-sm">{detail.summary}</p>
                </div>

                <div>
                  <h4 className="text-sm font-semibold text-muted-foreground mb-1">
                    Analysis
                  </h4>
                  <pre className="text-sm whitespace-pre-wrap bg-secondary/50 rounded-md p-4">
                    {detail.explanation}
                  </pre>
                </div>

                <div>
                  <h4 className="text-sm font-semibold text-muted-foreground mb-1">
                    Suggested Actions
                  </h4>
                  <pre className="text-sm whitespace-pre-wrap">{detail.suggested_actions}</pre>
                </div>

                {detail.mitre_techniques.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-2">
                      MITRE ATT&CK Techniques
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {detail.mitre_techniques.map((t) => (
                        <a
                          key={t.id}
                          href={t.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs bg-purple-500/20 text-purple-400 border border-purple-500/30 hover:bg-purple-500/30"
                        >
                          {t.id} {t.name}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {detail.mitre_tactics.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-2">
                      Tactics
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {detail.mitre_tactics.map((t) => (
                        <Badge key={t.id} variant="outline">
                          {t.id}: {t.name}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {detail.threat_intel_hits.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-2">
                      Threat Intelligence Hits
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {detail.threat_intel_hits.map((ip) => (
                        <Badge key={ip} variant="destructive">
                          {ip}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                <div className="text-xs text-muted-foreground">
                  <p>Risk Score: {detail.risk_score}</p>
                  <p>Correlated Alerts: {detail.alert_ids.length}</p>
                  <p>Created: {formatTimestamp(detail.created_at)}</p>
                  <p>Updated: {formatTimestamp(detail.updated_at)}</p>
                </div>
              </CardContent>
            </Card>
          ) : (
            <div className="flex items-center justify-center h-64 text-muted-foreground">
              Select an incident to view details
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
