"use client";

import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type RawEvent, type FeatureWindow } from "@/lib/api";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { SkeletonTable } from "@/components/ui/skeleton";
import { formatTimestamp, cn } from "@/lib/utils";
import { Database, Save } from "lucide-react";

type Tab = "events" | "features";

export default function TelemetryPage() {
  const [tab, setTab] = useState<Tab>("events");
  const [eventTypeFilter, setEventTypeFilter] = useState("");
  const [savedName, setSavedName] = useState("");
  const [savedFilters, setSavedFilters] = useState<Array<{ name: string; eventTypeFilter: string }>>([]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const raw = window.localStorage.getItem("ids_telemetry_filters");
    if (raw) setSavedFilters(JSON.parse(raw));
  }, []);

  const saveCurrentFilter = () => {
    if (!savedName.trim()) return;
    const next = [{ name: savedName, eventTypeFilter }, ...savedFilters];
    setSavedFilters(next);
    setSavedName("");
    if (typeof window !== "undefined") {
      window.localStorage.setItem("ids_telemetry_filters", JSON.stringify(next));
    }
  };

  const { data: events, isLoading: eventsLoading } = useQuery<RawEvent[]>({
    queryKey: ["events", eventTypeFilter],
    queryFn: () => api.getEvents(eventTypeFilter ? `event_type=${eventTypeFilter}` : "limit=100"),
    enabled: tab === "events",
  });

  const { data: features, isLoading: featuresLoading } = useQuery<FeatureWindow[]>({
    queryKey: ["features-explorer"],
    queryFn: () => api.getFeatures("limit=100"),
    enabled: tab === "features",
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Telemetry Explorer"
        description="Browse raw events and computed feature windows from host monitoring"
        breadcrumbs={[{ label: "Overview", href: "/" }, { label: "Telemetry" }]}
        actions={
          <div className="flex gap-1">
            {(["events", "features"] as Tab[]).map((t) => (
              <Button
                key={t}
                variant={tab === t ? "primary" : "secondary"}
                size="sm"
                onClick={() => setTab(t)}
                className="capitalize"
              >
                {t}
              </Button>
            ))}
          </div>
        }
      />

      {tab === "events" && (
        <>
          <div className="flex flex-wrap gap-3 items-end">
            <div className="flex gap-1">
              {["", "login_failure", "login_success", "connection", "new_process", "system_stats"].map(
                (t) => (
                  <Button
                    key={t}
                    variant={eventTypeFilter === t ? "primary" : "ghost"}
                    size="sm"
                    onClick={() => setEventTypeFilter(t)}
                  >
                    {t || "All"}
                  </Button>
                ),
              )}
            </div>
            <div className="flex gap-2 ml-auto items-end">
              <Input
                value={savedName}
                onChange={(e) => setSavedName(e.target.value)}
                placeholder="Filter name"
                className="w-36"
              />
              <Button variant="secondary" size="sm" onClick={saveCurrentFilter}>
                <Save className="h-3 w-3" />
                Save
              </Button>
              {savedFilters.length > 0 && (
                <select
                  className="h-8 rounded-md border border-border bg-background px-2 text-sm"
                  onChange={(e) => setEventTypeFilter(e.target.value)}
                  value={eventTypeFilter}
                >
                  <option value="">Saved Filters</option>
                  {savedFilters.map((f) => (
                    <option key={`${f.name}-${f.eventTypeFilter}`} value={f.eventTypeFilter}>
                      {f.name}
                    </option>
                  ))}
                </select>
              )}
            </div>
          </div>

          <Card>
            <CardContent className="p-0">
              {eventsLoading ? (
                <SkeletonTable rows={8} />
              ) : (events ?? []).length === 0 ? (
                <EmptyState
                  icon={Database}
                  title="No events found"
                  description="Events will appear here as telemetry is collected."
                />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border text-left text-muted-foreground">
                        <th className="px-4 py-3 font-medium">ID</th>
                        <th className="px-4 py-3 font-medium">Type</th>
                        <th className="px-4 py-3 font-medium">Host</th>
                        <th className="px-4 py-3 font-medium">Timestamp</th>
                        <th className="px-4 py-3 font-medium">Data</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(events ?? []).map((ev) => (
                        <tr key={ev.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                          <td className="px-4 py-3 font-mono text-xs">{ev.id}</td>
                          <td className="px-4 py-3">
                            <Badge variant="outline">{ev.event_type}</Badge>
                          </td>
                          <td className="px-4 py-3 text-xs">{ev.host_id}</td>
                          <td className="px-4 py-3 text-xs text-muted-foreground">
                            {formatTimestamp(ev.timestamp)}
                          </td>
                          <td className="px-4 py-3 text-xs font-mono text-muted-foreground max-w-xs truncate">
                            {JSON.stringify(ev.data).slice(0, 120)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </>
      )}

      {tab === "features" && (
        <Card>
          <CardContent className="p-0">
            {featuresLoading ? (
              <SkeletonTable rows={8} />
            ) : (features ?? []).length === 0 ? (
              <EmptyState
                icon={Database}
                title="No feature windows"
                description="Feature windows are computed from collected telemetry."
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-muted-foreground">
                      <th className="px-3 py-3 font-medium">ID</th>
                      <th className="px-3 py-3 font-medium">Window</th>
                      <th className="px-3 py-3 font-medium">Failed Login</th>
                      <th className="px-3 py-3 font-medium">Dest IPs</th>
                      <th className="px-3 py-3 font-medium">Dest Ports</th>
                      <th className="px-3 py-3 font-medium">Outbound</th>
                      <th className="px-3 py-3 font-medium">Bytes Sent</th>
                      <th className="px-3 py-3 font-medium">New Procs</th>
                      <th className="px-3 py-3 font-medium">CPU</th>
                      <th className="px-3 py-3 font-medium">Unusual</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(features ?? []).map((fw) => (
                      <tr key={fw.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                        <td className="px-3 py-3 font-mono text-xs">{fw.id}</td>
                        <td className="px-3 py-3 text-xs text-muted-foreground">
                          {new Date(fw.window_start).toLocaleTimeString()} –{" "}
                          {new Date(fw.window_end).toLocaleTimeString()}
                        </td>
                        <td className="px-3 py-3">{fw.failed_login_count}</td>
                        <td className="px-3 py-3">{fw.unique_dest_ips}</td>
                        <td className="px-3 py-3">{fw.unique_dest_ports}</td>
                        <td className="px-3 py-3">{fw.outbound_conn_count}</td>
                        <td className="px-3 py-3 font-mono text-xs">{Math.round(fw.bytes_sent)}</td>
                        <td className="px-3 py-3">{fw.new_process_count}</td>
                        <td className="px-3 py-3 font-mono text-xs">{fw.avg_process_cpu.toFixed(1)}%</td>
                        <td className="px-3 py-3">
                          {fw.unusual_hour_flag ? (
                            <Badge variant="destructive">Yes</Badge>
                          ) : (
                            <span className="text-muted-foreground">–</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
