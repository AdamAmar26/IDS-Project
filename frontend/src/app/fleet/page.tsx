"use client";

import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/ui/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { SkeletonTable } from "@/components/ui/skeleton";
import { StatusBadge } from "@/components/ui/status-badge";
import { formatTimestamp, cn } from "@/lib/utils";
import { Server, Wifi, WifiOff, AlertTriangle } from "lucide-react";

interface FleetHost {
  host_id: string;
  alert_count: number;
  incident_count: number;
  open_incidents: number;
  last_seen: string | null;
  risk_score: number;
}

function hostStatus(lastSeen: string | null): { label: string; color: string; icon: React.ElementType } {
  if (!lastSeen) return { label: "Unknown", color: "text-gray-400", icon: WifiOff };
  const age = Date.now() - new Date(lastSeen).getTime();
  const minutes = age / 60_000;
  if (minutes < 5) return { label: "Online", color: "text-green-400", icon: Wifi };
  if (minutes < 30) return { label: "Stale", color: "text-yellow-400", icon: AlertTriangle };
  return { label: "Offline", color: "text-red-400", icon: WifiOff };
}

export default function FleetPage() {
  const { data, isLoading } = useQuery<FleetHost[]>({
    queryKey: ["fleet-summary"],
    queryFn: api.getFleetSummary,
  });

  const hosts = data ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Fleet"
        description="Monitored hosts, health status, and risk overview"
        breadcrumbs={[{ label: "Overview", href: "/" }, { label: "Fleet" }]}
      />

      {isLoading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div key={i} className="rounded-lg border border-border bg-card p-6 space-y-3">
              <div className="h-4 w-1/3 rounded bg-muted animate-pulse" />
              <div className="h-6 w-1/2 rounded bg-muted animate-pulse" />
              <div className="h-3 w-2/3 rounded bg-muted animate-pulse" />
            </div>
          ))}
        </div>
      ) : hosts.length === 0 ? (
        <EmptyState
          icon={Server}
          title="No hosts detected"
          description="Hosts will appear here once telemetry data is collected."
        />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {hosts.map((host) => {
            const status = hostStatus(host.last_seen);
            const StatusIcon = status.icon;
            return (
              <Card key={host.host_id} className="hover:border-primary/30 transition-colors">
                <CardContent className="p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Server className="h-4 w-4 text-muted-foreground" />
                      <span className="font-medium text-sm">{host.host_id}</span>
                    </div>
                    <div className={cn("flex items-center gap-1 text-xs", status.color)}>
                      <StatusIcon className="h-3 w-3" />
                      {status.label}
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div>
                      <p className="text-lg font-bold">{host.alert_count}</p>
                      <p className="text-[10px] text-muted-foreground uppercase">Alerts</p>
                    </div>
                    <div>
                      <p className="text-lg font-bold">{host.incident_count}</p>
                      <p className="text-[10px] text-muted-foreground uppercase">Incidents</p>
                    </div>
                    <div>
                      <p className={cn("text-lg font-bold", host.open_incidents > 0 && "text-orange-400")}>
                        {host.open_incidents}
                      </p>
                      <p className="text-[10px] text-muted-foreground uppercase">Open</p>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>
                      Risk: <span className={cn("font-medium", host.risk_score >= 5 ? "text-red-400" : host.risk_score >= 3 ? "text-orange-400" : "text-foreground")}>
                        {host.risk_score.toFixed(1)}
                      </span>
                    </span>
                    {host.last_seen && (
                      <span>Last: {formatTimestamp(host.last_seen)}</span>
                    )}
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
