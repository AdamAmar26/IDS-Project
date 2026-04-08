"use client";

import { useQuery } from "@tanstack/react-query";
import { api, type Alert, type Incident, type Metrics, type ThreatSummary } from "@/lib/api";
import { useAlertStream } from "@/lib/useAlertStream";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { formatTimestamp, severityColor, cn } from "@/lib/utils";
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";
import {
  Activity, ShieldAlert, Cpu, Wifi, WifiOff, BrainCircuit, RefreshCw,
  TrendingUp, TrendingDown, Minus, AlertTriangle, Shield, ChevronRight,
} from "lucide-react";
import Link from "next/link";

function MetricCard({
  title,
  value,
  icon: Icon,
  sub,
  accent,
}: {
  title: string;
  value: string | number;
  icon: React.ElementType;
  sub?: string;
  accent?: string;
}) {
  return (
    <Card>
      <CardContent className="p-5">
        <div className="flex items-center justify-between">
          <div className="space-y-1">
            <p className="text-sm text-muted-foreground">{title}</p>
            <p className={cn("text-2xl font-bold", accent)}>{value}</p>
            {sub && <p className="text-xs text-muted-foreground">{sub}</p>}
          </div>
          <div className="rounded-lg bg-accent/50 p-2.5">
            <Icon className="h-5 w-5 text-muted-foreground" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ThreatBriefing() {
  const { data, isLoading, refetch, dataUpdatedAt } = useQuery<ThreatSummary>({
    queryKey: ["threat-summary"],
    queryFn: api.getSummary,
    refetchInterval: 300_000,
    staleTime: 60_000,
  });

  const TrendIcon = data?.data.trend === "worsening"
    ? TrendingUp
    : data?.data.trend === "improving"
      ? TrendingDown
      : Minus;

  const trendColor = data?.data.trend === "worsening"
    ? "text-red-400"
    : data?.data.trend === "improving"
      ? "text-green-400"
      : "text-muted-foreground";

  return (
    <Card className="border-primary/20 bg-gradient-to-r from-card to-primary/[0.03]">
      <CardContent className="p-6">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3 flex-1 min-w-0">
            <div className="rounded-lg bg-primary/10 p-2.5 shrink-0 mt-0.5">
              <BrainCircuit className="h-5 w-5 text-primary" />
            </div>
            <div className="min-w-0 space-y-2">
              <div className="flex items-center gap-2">
                <h2 className="font-semibold">Threat Briefing</h2>
                {data?.llm_available && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-primary/10 text-primary font-medium">
                    AI
                  </span>
                )}
              </div>
              {isLoading ? (
                <div className="space-y-2">
                  <div className="h-4 w-3/4 rounded bg-muted animate-pulse" />
                  <div className="h-4 w-1/2 rounded bg-muted animate-pulse" />
                </div>
              ) : (
                <p className="text-sm text-muted-foreground leading-relaxed">
                  {data?.briefing}
                </p>
              )}
              {data && (
                <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground pt-1">
                  <span className="flex items-center gap-1">
                    <TrendIcon className={cn("h-3 w-3", trendColor)} />
                    <span className={trendColor}>{data.data.trend}</span>
                  </span>
                  {data.data.severity_counts.critical > 0 && (
                    <span className="flex items-center gap-1 text-red-400">
                      <AlertTriangle className="h-3 w-3" />
                      {data.data.severity_counts.critical} critical
                    </span>
                  )}
                  <span>Model: {data.data.model_health}</span>
                </div>
              )}
            </div>
          </div>
          <button
            onClick={() => refetch()}
            title="Refresh briefing"
            className="shrink-0 rounded-md p-2 text-muted-foreground hover:bg-accent/50 hover:text-foreground transition-colors"
          >
            <RefreshCw className={cn("h-4 w-4", isLoading && "animate-spin")} />
          </button>
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

  const { data: incidents } = useQuery<Incident[]>({
    queryKey: ["incidents-overview"],
    queryFn: () => api.getIncidents("status=open"),
  });

  const { events, connected } = useAlertStream();

  const chartData = (alerts ?? [])
    .filter((a) => a.is_anomaly)
    .slice(0, 30)
    .reverse()
    .map((a) => ({
      time: new Date(a.created_at).toLocaleTimeString(),
      score: parseFloat(a.anomaly_score.toFixed(3)),
    }));

  const activeIncidents = (incidents ?? []).slice(0, 5);

  return (
    <div className="space-y-6">
      {/* Connection status */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Overview</h1>
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

      {/* AI Threat Briefing */}
      <ThreatBriefing />

      {/* Key metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Active Incidents"
          value={metrics?.active_incidents ?? 0}
          icon={ShieldAlert}
          accent={(metrics?.active_incidents ?? 0) > 0 ? "text-orange-400" : undefined}
        />
        <MetricCard
          title="Total Alerts"
          value={metrics?.total_alerts ?? 0}
          icon={Activity}
        />
        <MetricCard
          title="Anomaly Rate"
          value={`${((metrics?.anomaly_rate ?? 0) * 100).toFixed(1)}%`}
          icon={Cpu}
          sub={
            metrics?.model_trained
              ? "Model active"
              : `Training ${metrics?.training_samples ?? 0}/${metrics?.min_training_samples ?? 0}`
          }
        />
        <MetricCard
          title="Total Events"
          value={metrics?.total_events ?? 0}
          icon={Activity}
          sub={`${metrics?.total_windows ?? 0} feature windows`}
        />
      </div>

      {/* Charts + Active Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base">Anomaly Score Trend</CardTitle>
          </CardHeader>
          <CardContent>
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={280}>
                <AreaChart data={chartData}>
                  <defs>
                    <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="hsl(210, 100%, 56%)" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="hsl(210, 100%, 56%)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(216, 34%, 17%)" />
                  <XAxis dataKey="time" tick={{ fontSize: 11, fill: "hsl(215, 20%, 55%)" }} />
                  <YAxis tick={{ fontSize: 11, fill: "hsl(215, 20%, 55%)" }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(224, 71%, 6%)",
                      border: "1px solid hsl(216, 34%, 17%)",
                      borderRadius: "0.5rem",
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="score"
                    stroke="hsl(210, 100%, 56%)"
                    strokeWidth={2}
                    fill="url(#scoreGradient)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-muted-foreground text-center py-16">
                No anomaly data yet
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-row items-center justify-between space-y-0 pb-3">
            <CardTitle className="text-base">Active Incidents</CardTitle>
            <Link
              href="/incidents"
              className="text-xs text-primary hover:underline flex items-center gap-0.5"
            >
              View all <ChevronRight className="h-3 w-3" />
            </Link>
          </CardHeader>
          <CardContent>
            {activeIncidents.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                <Shield className="h-8 w-8 mb-2 opacity-50" />
                <p className="text-sm">No active incidents</p>
              </div>
            ) : (
              <div className="space-y-2">
                {activeIncidents.map((inc) => (
                  <Link
                    key={inc.id}
                    href="/incidents"
                    className="flex items-center justify-between rounded-md border border-border/50 p-3 hover:bg-accent/30 transition-colors group"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <Badge className={cn(severityColor(inc.severity), "text-[10px]")}>
                          {inc.severity.toUpperCase()}
                        </Badge>
                        <span className="text-xs text-muted-foreground">#{inc.id}</span>
                      </div>
                      <p className="text-sm truncate">{inc.summary}</p>
                    </div>
                    <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0 group-hover:text-foreground transition-colors" />
                  </Link>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Live Feed */}
      <Card>
        <CardHeader className="flex-row items-center justify-between space-y-0 pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            Live Feed
            {connected && (
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-1.5 max-h-[220px] overflow-y-auto">
            {events.length === 0 && (
              <p className="text-muted-foreground text-center py-8 text-sm">
                Waiting for events...
              </p>
            )}
            {events.slice(0, 20).map((ev, i) => (
              <div
                key={i}
                className="flex items-center justify-between text-sm border-b border-border/30 pb-1.5"
              >
                <div className="flex items-center gap-2">
                  <Badge
                    variant={ev.type === "incident" ? "destructive" : "outline"}
                    className="text-[10px]"
                  >
                    {ev.type}
                  </Badge>
                  <span className="text-muted-foreground text-xs">
                    {ev.data.host_id as string}
                  </span>
                </div>
                <span className="text-[11px] text-muted-foreground">
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
  );
}
