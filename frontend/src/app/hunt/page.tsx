"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type SavedHunt, type HuntResults } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { PageHeader } from "@/components/ui/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { useToast } from "@/components/ui/toast";
import { formatTimestamp, cn } from "@/lib/utils";
import { Search, Play, Save, Clock } from "lucide-react";

export default function HuntPage() {
  const [name, setName] = useState("");
  const [hostId, setHostId] = useState("");
  const [eventType, setEventType] = useState("");
  const [isAnomaly, setIsAnomaly] = useState("");
  const [selectedHunt, setSelectedHunt] = useState<number | null>(null);
  const [results, setResults] = useState<HuntResults | null>(null);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: hunts, isLoading } = useQuery<SavedHunt[]>({
    queryKey: ["hunts"],
    queryFn: api.getHunts,
  });

  const saveMutation = useMutation({
    mutationFn: () => {
      const filters: Record<string, string> = {};
      if (hostId) filters.host_id = hostId;
      if (eventType) filters.event_type = eventType;
      if (isAnomaly) filters.is_anomaly = isAnomaly;
      return api.createHunt(name || "Untitled Hunt", filters);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hunts"] });
      setName("");
      toast("Hunt saved successfully", "success");
    },
    onError: () => toast("Failed to save hunt", "error"),
  });

  const runMutation = useMutation({
    mutationFn: (id: number) => api.runHunt(id),
    onSuccess: (data) => {
      setResults(data);
      toast(`Hunt returned ${data.total} results`, "info");
    },
    onError: () => toast("Hunt execution failed", "error"),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Hunt"
        description="Create, save, and execute threat hunting queries against telemetry and alerts"
        breadcrumbs={[{ label: "Overview", href: "/" }, { label: "Hunt" }]}
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Query Builder */}
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Hunt Query Builder</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <Input
                label="Hunt Name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., Lateral Movement Scan"
              />
              <Input
                label="Host ID"
                value={hostId}
                onChange={(e) => setHostId(e.target.value)}
                placeholder="Filter by host"
              />
              <Select
                label="Event Type"
                value={eventType}
                onChange={(e) => setEventType(e.target.value)}
              >
                <option value="">All event types</option>
                <option value="login_failure">Login Failure</option>
                <option value="login_success">Login Success</option>
                <option value="connection">Connection</option>
                <option value="new_process">New Process</option>
                <option value="dns_query">DNS Query</option>
                <option value="file_access">File Access</option>
                <option value="net_io">Network I/O</option>
              </Select>
              <Select
                label="Anomaly Filter"
                value={isAnomaly}
                onChange={(e) => setIsAnomaly(e.target.value)}
              >
                <option value="">All alerts</option>
                <option value="true">Anomalies only</option>
                <option value="false">Normal only</option>
              </Select>
            </div>
            <div className="flex gap-2">
              <Button onClick={() => saveMutation.mutate()} variant="secondary">
                <Save className="h-4 w-4" />
                Save Hunt
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Saved Hunts */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Clock className="h-4 w-4" />
              Saved Hunts
            </CardTitle>
          </CardHeader>
          <CardContent>
            {(hunts ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-6">
                No saved hunts yet
              </p>
            ) : (
              <div className="space-y-2 max-h-[300px] overflow-y-auto">
                {(hunts ?? []).map((h) => (
                  <div
                    key={h.id}
                    className={cn(
                      "rounded-md border p-3 cursor-pointer transition-colors hover:border-primary/50",
                      selectedHunt === h.id && "border-primary bg-primary/5",
                    )}
                    onClick={() => setSelectedHunt(h.id)}
                  >
                    <div className="flex items-center justify-between">
                      <p className="text-sm font-medium">{h.name}</p>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={(e) => {
                          e.stopPropagation();
                          runMutation.mutate(h.id);
                        }}
                        disabled={runMutation.isPending}
                      >
                        <Play className="h-3 w-3" />
                      </Button>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      {Object.entries(h.filters).map(([k, v]) => `${k}=${v}`).join(", ") || "No filters"}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Results */}
      {results && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Hunt Results — {results.total} match{results.total !== 1 ? "es" : ""}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {results.events.length > 0 && (
              <div className="mb-6">
                <h4 className="text-sm font-medium text-muted-foreground mb-2">
                  Events ({results.events.length})
                </h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border text-left text-muted-foreground">
                        <th className="px-3 py-2 font-medium">ID</th>
                        <th className="px-3 py-2 font-medium">Type</th>
                        <th className="px-3 py-2 font-medium">Host</th>
                        <th className="px-3 py-2 font-medium">Time</th>
                        <th className="px-3 py-2 font-medium">Data</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.events.slice(0, 50).map((ev) => (
                        <tr key={ev.id} className="border-b border-border/50">
                          <td className="px-3 py-2 font-mono text-xs">{ev.id}</td>
                          <td className="px-3 py-2">
                            <Badge variant="outline">{ev.event_type}</Badge>
                          </td>
                          <td className="px-3 py-2 text-xs">{ev.host_id}</td>
                          <td className="px-3 py-2 text-xs text-muted-foreground">
                            {formatTimestamp(ev.timestamp)}
                          </td>
                          <td className="px-3 py-2 text-xs text-muted-foreground font-mono max-w-[200px] truncate">
                            {JSON.stringify(ev.data).slice(0, 100)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {results.alerts.length > 0 && (
              <div>
                <h4 className="text-sm font-medium text-muted-foreground mb-2">
                  Alerts ({results.alerts.length})
                </h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border text-left text-muted-foreground">
                        <th className="px-3 py-2 font-medium">ID</th>
                        <th className="px-3 py-2 font-medium">Host</th>
                        <th className="px-3 py-2 font-medium">Score</th>
                        <th className="px-3 py-2 font-medium">Anomaly</th>
                        <th className="px-3 py-2 font-medium">Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.alerts.slice(0, 50).map((a) => (
                        <tr key={a.id} className="border-b border-border/50">
                          <td className="px-3 py-2 font-mono text-xs">{a.id}</td>
                          <td className="px-3 py-2 text-xs">{a.host_id}</td>
                          <td className="px-3 py-2 font-mono text-xs">{a.anomaly_score.toFixed(4)}</td>
                          <td className="px-3 py-2">
                            {a.is_anomaly ? (
                              <Badge variant="destructive">Yes</Badge>
                            ) : (
                              <Badge variant="outline">No</Badge>
                            )}
                          </td>
                          <td className="px-3 py-2 text-xs text-muted-foreground">
                            {formatTimestamp(a.created_at)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {results.total === 0 && (
              <EmptyState
                icon={Search}
                title="No results found"
                description="Try adjusting your hunt filters or running a different query."
              />
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
