"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Incident, type TimelineItem } from "@/lib/api";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { EmptyState } from "@/components/ui/empty-state";
import { useToast } from "@/components/ui/toast";
import { severityColor, formatTimestamp, cn } from "@/lib/utils";
import { ChevronRight, ExternalLink, Shield } from "lucide-react";

export default function IncidentsPage() {
  const [selected, setSelected] = useState<number | null>(null);
  const [statusFilter, setStatusFilter] = useState("");
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: incidents, isLoading } = useQuery<Incident[]>({
    queryKey: ["incidents", statusFilter],
    queryFn: () => api.getIncidents(statusFilter ? `status=${statusFilter}` : ""),
  });

  const { data: detail } = useQuery<Incident>({
    queryKey: ["incident", selected],
    queryFn: () => api.getIncident(selected!),
    enabled: selected !== null,
  });
  const { data: timeline } = useQuery<{ incident_id: number; items: TimelineItem[] }>({
    queryKey: ["incident-timeline", selected],
    queryFn: () => api.getIncidentTimeline(selected!),
    enabled: selected !== null,
  });

  const mutation = useMutation({
    mutationFn: ({ id, status }: { id: number; status: string }) =>
      api.patchIncidentStatus(id, status),
    onSuccess: (_, { status }) => {
      queryClient.invalidateQueries({ queryKey: ["incidents"] });
      queryClient.invalidateQueries({ queryKey: ["incident", selected] });
      toast(`Incident status updated to ${status}`, "success");
    },
    onError: () => toast("Failed to update incident status", "error"),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Incidents"
        description="Correlated security incidents with MITRE ATT&CK mapping and threat intelligence"
        breadcrumbs={[{ label: "Overview", href: "/" }, { label: "Incidents" }]}
        actions={
          <div className="flex gap-1">
            {["", "open", "acknowledged", "investigating", "resolved", "closed"].map((s) => (
              <Button
                key={s}
                variant={statusFilter === s ? "primary" : "secondary"}
                size="sm"
                onClick={() => setStatusFilter(s)}
              >
                {s || "All"}
              </Button>
            ))}
          </div>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 space-y-2">
          {isLoading && (
            <div className="space-y-2">
              {[1, 2, 3].map((i) => (
                <div key={i} className="rounded-lg border border-border bg-card p-4 space-y-2">
                  <div className="h-4 w-1/3 rounded bg-muted animate-pulse" />
                  <div className="h-3 w-2/3 rounded bg-muted animate-pulse" />
                </div>
              ))}
            </div>
          )}
          {(incidents ?? []).map((inc) => (
            <Card
              key={inc.id}
              className={cn(
                "cursor-pointer transition-colors hover:border-primary/50",
                selected === inc.id && "border-primary",
              )}
              onClick={() => setSelected(inc.id)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === "Enter" && setSelected(inc.id)}
            >
              <CardContent className="p-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <StatusBadge severity={inc.severity} />
                      <StatusBadge status={inc.status} />
                      <span className="text-xs text-muted-foreground">#{inc.id}</span>
                    </div>
                    <p className="text-sm line-clamp-2">{inc.summary}</p>
                    <p className="text-xs text-muted-foreground">
                      {formatTimestamp(inc.created_at)}
                    </p>
                  </div>
                  <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
                </div>
              </CardContent>
            </Card>
          ))}
          {!isLoading && (incidents ?? []).length === 0 && (
            <EmptyState
              icon={Shield}
              title="No incidents found"
              description="Your environment is clear. Monitoring continues."
            />
          )}
        </div>

        <div className="lg:col-span-2">
          {detail ? (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between flex-wrap gap-2">
                  <CardTitle className="flex items-center gap-3">
                    Incident #{detail.id}
                    <StatusBadge severity={detail.severity} />
                    <StatusBadge status={detail.status} />
                  </CardTitle>
                  <div className="flex gap-2">
                    {detail.status === "open" && (
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => mutation.mutate({ id: detail.id, status: "acknowledged" })}
                      >
                        Acknowledge
                      </Button>
                    )}
                    {detail.status === "acknowledged" && (
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => mutation.mutate({ id: detail.id, status: "investigating" })}
                      >
                        Investigate
                      </Button>
                    )}
                    {detail.status !== "resolved" && detail.status !== "closed" && (
                      <Button
                        variant="primary"
                        size="sm"
                        onClick={() => mutation.mutate({ id: detail.id, status: "resolved" })}
                      >
                        Resolve
                      </Button>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <div>
                  <h4 className="text-sm font-semibold text-muted-foreground mb-1">Summary</h4>
                  <p className="text-sm">{detail.summary}</p>
                </div>

                <div>
                  <h4 className="text-sm font-semibold text-muted-foreground mb-1">Analysis</h4>
                  <pre className="text-sm whitespace-pre-wrap bg-secondary/50 rounded-md p-4">
                    {detail.explanation}
                  </pre>
                </div>

                <div>
                  <h4 className="text-sm font-semibold text-muted-foreground mb-1">Suggested Actions</h4>
                  <pre className="text-sm whitespace-pre-wrap">{detail.suggested_actions}</pre>
                </div>

                {detail.mitre_techniques.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-2">MITRE ATT&CK Techniques</h4>
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
                    <h4 className="text-sm font-semibold text-muted-foreground mb-2">Tactics</h4>
                    <div className="flex flex-wrap gap-2">
                      {detail.mitre_tactics.map((t) => (
                        <Badge key={t.id} variant="outline">{t.id}: {t.name}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {detail.threat_intel_hits.length > 0 && (
                  <div>
                    <h4 className="text-sm font-semibold text-muted-foreground mb-2">Threat Intelligence Hits</h4>
                    <div className="flex flex-wrap gap-2">
                      {detail.threat_intel_hits.map((ip) => (
                        <Badge key={ip} variant="destructive">{ip}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                  <p>Risk Score: {detail.risk_score}</p>
                  <p>Correlated Alerts: {detail.alert_ids.length}</p>
                  <p>Created: {formatTimestamp(detail.created_at)}</p>
                  <p>Updated: {formatTimestamp(detail.updated_at)}</p>
                </div>

                <div>
                  <h4 className="text-sm font-semibold text-muted-foreground mb-2">Timeline</h4>
                  <div className="space-y-2 max-h-56 overflow-y-auto">
                    {(timeline?.items ?? []).slice(0, 20).map((item) => (
                      <div key={`${item.type}-${item.id}`} className="text-xs border rounded-md p-2">
                        <div className="flex items-center justify-between">
                          <Badge variant="outline">{item.type}</Badge>
                          <span className="text-muted-foreground">{formatTimestamp(item.time)}</span>
                        </div>
                        <p className="mt-1 font-medium">{item.title}</p>
                        <p className="text-muted-foreground">{item.detail}</p>
                      </div>
                    ))}
                  </div>
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
