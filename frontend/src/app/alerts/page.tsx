"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Alert } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/ui/page-header";
import { formatTimestamp, cn } from "@/lib/utils";
import { ExternalLink } from "lucide-react";
import Link from "next/link";

export default function AlertsPage() {
  const [severityFilter, setSeverityFilter] = useState("");
  const [anomalyFilter, setAnomalyFilter] = useState<"" | "true" | "false">("");
  const queryClient = useQueryClient();

  const params = new URLSearchParams();
  params.set("limit", "100");
  if (anomalyFilter) params.set("is_anomaly", anomalyFilter);

  const { data: alerts, isLoading } = useQuery<Alert[]>({
    queryKey: ["alerts-page", anomalyFilter],
    queryFn: () => api.getAlerts(params.toString()),
  });

  const filtered = (alerts ?? []).filter((a) => {
    if (severityFilter) {
      const score = a.anomaly_score;
      if (severityFilter === "critical" && score < 0.8) return false;
      if (severityFilter === "high" && (score < 0.6 || score >= 0.8))
        return false;
      if (severityFilter === "medium" && (score < 0.4 || score >= 0.6))
        return false;
      if (severityFilter === "low" && score >= 0.4) return false;
    }
    return true;
  });

  const scoreSeverity = (score: number) => {
    if (score >= 0.8) return "critical";
    if (score >= 0.6) return "high";
    if (score >= 0.4) return "medium";
    return "low";
  };

  const severityBadge = (severity: string) => {
    const colors: Record<string, string> = {
      critical: "bg-red-500/20 text-red-400 border-red-500/30",
      high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
      medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
      low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    };
    return colors[severity] ?? "bg-gray-500/20 text-gray-400 border-gray-500/30";
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Alerts"
        description="All detection alerts with anomaly scores and feature attribution"
        breadcrumbs={[{ label: "Overview", href: "/" }, { label: "Alerts" }]}
      />

      <div className="flex flex-wrap gap-2">
        <div className="flex gap-1">
          {["", "true", "false"].map((val) => (
            <button
              key={val}
              onClick={() => setAnomalyFilter(val as typeof anomalyFilter)}
              className={cn(
                "px-3 py-1.5 rounded-md text-sm transition-colors",
                anomalyFilter === val
                  ? "bg-primary text-primary-foreground"
                  : "bg-secondary text-secondary-foreground hover:bg-accent",
              )}
            >
              {val === "" ? "All" : val === "true" ? "Anomalies" : "Normal"}
            </button>
          ))}
        </div>
        <div className="flex gap-1">
          {["", "critical", "high", "medium", "low"].map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              className={cn(
                "px-3 py-1.5 rounded-md text-sm transition-colors",
                severityFilter === s
                  ? "bg-primary text-primary-foreground"
                  : "bg-secondary text-secondary-foreground hover:bg-accent",
              )}
            >
              {s || "All Severity"}
            </button>
          ))}
        </div>
      </div>

      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="px-4 py-3 font-medium">ID</th>
                  <th className="px-4 py-3 font-medium">Host</th>
                  <th className="px-4 py-3 font-medium">Severity</th>
                  <th className="px-4 py-3 font-medium">Score</th>
                  <th className="px-4 py-3 font-medium">Anomaly</th>
                  <th className="px-4 py-3 font-medium">Top Features</th>
                  <th className="px-4 py-3 font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {isLoading && (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-muted-foreground">
                      Loading alerts...
                    </td>
                  </tr>
                )}
                {!isLoading && filtered.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-muted-foreground">
                      No alerts match the current filters
                    </td>
                  </tr>
                )}
                {filtered.map((alert) => {
                  const sev = scoreSeverity(alert.anomaly_score);
                  return (
                    <tr
                      key={alert.id}
                      className="border-b border-border/50 hover:bg-accent/30 transition-colors"
                    >
                      <td className="px-4 py-3 font-mono text-xs">
                        {alert.id}
                      </td>
                      <td className="px-4 py-3">
                        <Link
                          href={`/fleet`}
                          className="text-primary hover:underline"
                        >
                          {alert.host_id}
                        </Link>
                      </td>
                      <td className="px-4 py-3">
                        <Badge className={severityBadge(sev)}>
                          {sev.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 font-mono">
                        {alert.anomaly_score.toFixed(4)}
                      </td>
                      <td className="px-4 py-3">
                        {alert.is_anomaly ? (
                          <Badge variant="destructive">Yes</Badge>
                        ) : (
                          <Badge variant="outline">No</Badge>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground max-w-[200px]">
                        {alert.top_features
                          ? Object.entries(alert.top_features)
                              .slice(0, 3)
                              .map(([k, v]) => `${k}: ${v}`)
                              .join(", ")
                          : "-"}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                        {formatTimestamp(alert.created_at)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
