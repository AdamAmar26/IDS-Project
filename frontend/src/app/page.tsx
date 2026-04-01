"use client";

import { useQuery } from "@tanstack/react-query";
import { api, type Alert, type Metrics } from "@/lib/api";
import { useAlertStream } from "@/lib/useAlertStream";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { formatTimestamp, severityColor } from "@/lib/utils";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import { Activity, ShieldAlert, Cpu, Wifi, WifiOff } from "lucide-react";

function MetricCard({
  title,
  value,
  icon: Icon,
  sub,
}: {
  title: string;
  value: string | number;
  icon: React.ElementType;
  sub?: string;
}) {
  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-muted-foreground">{title}</p>
            <p className="text-3xl font-bold mt-1">{value}</p>
            {sub && <p className="text-xs text-muted-foreground mt-1">{sub}</p>}
          </div>
          <Icon className="h-8 w-8 text-muted-foreground/50" />
        </div>
      </CardContent>
    </Card>
  );
}

export default function OverviewPage() {
  const { data: metrics } = useQuery<Metrics>({
    queryKey: ["metrics"],
    queryFn: api.getMetrics,
  });

  const { data: alerts } = useQuery<Alert[]>({
    queryKey: ["alerts"],
    queryFn: () => api.getAlerts("limit=50"),
  });

  const { events, connected } = useAlertStream();

  const chartData = (alerts ?? [])
    .filter((a) => a.is_anomaly)
    .slice(0, 30)
    .reverse()
    .map((a) => ({
      time: new Date(a.created_at).toLocaleTimeString(),
      score: a.anomaly_score,
    }));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Overview</h1>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          {connected ? (
            <>
              <Wifi className="h-4 w-4 text-green-400" />
              <span>Live</span>
            </>
          ) : (
            <>
              <WifiOff className="h-4 w-4 text-red-400" />
              <span>Disconnected</span>
            </>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Alerts"
          value={metrics?.total_alerts ?? 0}
          icon={Activity}
        />
        <MetricCard
          title="Active Incidents"
          value={metrics?.active_incidents ?? 0}
          icon={ShieldAlert}
        />
        <MetricCard
          title="Anomaly Rate"
          value={`${((metrics?.anomaly_rate ?? 0) * 100).toFixed(1)}%`}
          icon={Cpu}
          sub={metrics?.model_trained ? "Model active" : `Training ${metrics?.training_samples ?? 0}/${metrics?.min_training_samples ?? 0}`}
        />
        <MetricCard
          title="Total Events"
          value={metrics?.total_events ?? 0}
          icon={Activity}
          sub={`${metrics?.total_windows ?? 0} feature windows`}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Anomaly Score Trend</CardTitle>
          </CardHeader>
          <CardContent>
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={260}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(216, 34%, 17%)" />
                  <XAxis dataKey="time" tick={{ fontSize: 11, fill: "hsl(215, 20%, 55%)" }} />
                  <YAxis tick={{ fontSize: 11, fill: "hsl(215, 20%, 55%)" }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "hsl(224, 71%, 6%)", border: "1px solid hsl(216, 34%, 17%)" }}
                  />
                  <Line type="monotone" dataKey="score" stroke="hsl(210, 100%, 56%)" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-muted-foreground text-center py-12">No anomaly data yet</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Live Feed</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 max-h-[260px] overflow-y-auto">
              {events.length === 0 && (
                <p className="text-muted-foreground text-center py-8">Waiting for events...</p>
              )}
              {events.slice(0, 20).map((ev, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between text-sm border-b border-border pb-2"
                >
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={ev.type === "incident" ? "destructive" : "outline"}
                    >
                      {ev.type}
                    </Badge>
                    <span className="text-muted-foreground">
                      {ev.data.host_id as string}
                    </span>
                  </div>
                  <span className="text-xs text-muted-foreground">
                    {ev.data.timestamp
                      ? formatTimestamp(ev.data.timestamp as string)
                      : "now"}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent Alerts</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-muted-foreground">
                  <th className="pb-2 pr-4">ID</th>
                  <th className="pb-2 pr-4">Host</th>
                  <th className="pb-2 pr-4">Score</th>
                  <th className="pb-2 pr-4">Anomaly</th>
                  <th className="pb-2 pr-4">Top Features</th>
                  <th className="pb-2">Time</th>
                </tr>
              </thead>
              <tbody>
                {(alerts ?? []).slice(0, 15).map((alert) => (
                  <tr key={alert.id} className="border-b border-border/50">
                    <td className="py-2 pr-4 font-mono text-xs">{alert.id}</td>
                    <td className="py-2 pr-4">{alert.host_id}</td>
                    <td className="py-2 pr-4 font-mono">
                      {alert.anomaly_score.toFixed(4)}
                    </td>
                    <td className="py-2 pr-4">
                      {alert.is_anomaly ? (
                        <Badge variant="destructive">Yes</Badge>
                      ) : (
                        <Badge variant="outline">No</Badge>
                      )}
                    </td>
                    <td className="py-2 pr-4 text-xs text-muted-foreground">
                      {alert.top_features
                        ? Object.entries(alert.top_features)
                            .slice(0, 3)
                            .map(([k, v]) => `${k}: ${v}`)
                            .join(", ")
                        : "-"}
                    </td>
                    <td className="py-2 text-xs text-muted-foreground">
                      {formatTimestamp(alert.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
