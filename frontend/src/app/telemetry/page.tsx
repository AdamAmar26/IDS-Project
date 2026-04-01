"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type RawEvent, type FeatureWindow } from "@/lib/api";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { formatTimestamp, cn } from "@/lib/utils";

type Tab = "events" | "features";

export default function TelemetryPage() {
  const [tab, setTab] = useState<Tab>("events");
  const [eventTypeFilter, setEventTypeFilter] = useState("");

  const { data: events } = useQuery<RawEvent[]>({
    queryKey: ["events", eventTypeFilter],
    queryFn: () => api.getEvents(eventTypeFilter ? `event_type=${eventTypeFilter}` : "limit=100"),
    enabled: tab === "events",
  });

  const { data: features } = useQuery<FeatureWindow[]>({
    queryKey: ["features-explorer"],
    queryFn: () => api.getFeatures("limit=100"),
    enabled: tab === "features",
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Telemetry Explorer</h1>
        <div className="flex gap-2">
          {(["events", "features"] as Tab[]).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                "px-4 py-1.5 rounded-md text-sm font-medium transition-colors capitalize",
                tab === t
                  ? "bg-primary text-primary-foreground"
                  : "bg-secondary text-secondary-foreground hover:bg-accent",
              )}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {tab === "events" && (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Raw Events</CardTitle>
              <div className="flex gap-2">
                {["", "login_failure", "login_success", "connection", "new_process", "system_stats"].map(
                  (t) => (
                    <button
                      key={t}
                      onClick={() => setEventTypeFilter(t)}
                      className={cn(
                        "px-2 py-0.5 rounded text-xs transition-colors",
                        eventTypeFilter === t
                          ? "bg-primary/20 text-primary"
                          : "bg-secondary text-muted-foreground hover:text-foreground",
                      )}
                    >
                      {t || "All"}
                    </button>
                  ),
                )}
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-muted-foreground">
                    <th className="pb-2 pr-4">ID</th>
                    <th className="pb-2 pr-4">Type</th>
                    <th className="pb-2 pr-4">Host</th>
                    <th className="pb-2 pr-4">Timestamp</th>
                    <th className="pb-2">Data</th>
                  </tr>
                </thead>
                <tbody>
                  {(events ?? []).map((ev) => (
                    <tr key={ev.id} className="border-b border-border/50">
                      <td className="py-2 pr-4 font-mono text-xs">{ev.id}</td>
                      <td className="py-2 pr-4">
                        <Badge variant="outline">{ev.event_type}</Badge>
                      </td>
                      <td className="py-2 pr-4">{ev.host_id}</td>
                      <td className="py-2 pr-4 text-xs text-muted-foreground">
                        {formatTimestamp(ev.timestamp)}
                      </td>
                      <td className="py-2 text-xs font-mono text-muted-foreground max-w-xs truncate">
                        {JSON.stringify(ev.data).slice(0, 120)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {tab === "features" && (
        <Card>
          <CardHeader>
            <CardTitle>Feature Windows</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border text-left text-muted-foreground">
                    <th className="pb-2 pr-3">ID</th>
                    <th className="pb-2 pr-3">Window</th>
                    <th className="pb-2 pr-3">Failed Login</th>
                    <th className="pb-2 pr-3">Dest IPs</th>
                    <th className="pb-2 pr-3">Dest Ports</th>
                    <th className="pb-2 pr-3">Outbound</th>
                    <th className="pb-2 pr-3">Bytes Sent</th>
                    <th className="pb-2 pr-3">New Procs</th>
                    <th className="pb-2 pr-3">CPU</th>
                    <th className="pb-2">Unusual</th>
                  </tr>
                </thead>
                <tbody>
                  {(features ?? []).map((fw) => (
                    <tr key={fw.id} className="border-b border-border/50">
                      <td className="py-2 pr-3 font-mono text-xs">{fw.id}</td>
                      <td className="py-2 pr-3 text-xs text-muted-foreground">
                        {new Date(fw.window_start).toLocaleTimeString()} -{" "}
                        {new Date(fw.window_end).toLocaleTimeString()}
                      </td>
                      <td className="py-2 pr-3">{fw.failed_login_count}</td>
                      <td className="py-2 pr-3">{fw.unique_dest_ips}</td>
                      <td className="py-2 pr-3">{fw.unique_dest_ports}</td>
                      <td className="py-2 pr-3">{fw.outbound_conn_count}</td>
                      <td className="py-2 pr-3 font-mono text-xs">
                        {Math.round(fw.bytes_sent)}
                      </td>
                      <td className="py-2 pr-3">{fw.new_process_count}</td>
                      <td className="py-2 pr-3 font-mono text-xs">
                        {fw.avg_process_cpu.toFixed(1)}%
                      </td>
                      <td className="py-2">
                        {fw.unusual_hour_flag ? (
                          <Badge variant="destructive">Yes</Badge>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
