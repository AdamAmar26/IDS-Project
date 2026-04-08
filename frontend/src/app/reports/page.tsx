"use client";

import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, type WeeklyReport } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page-header";
import { StatusBadge } from "@/components/ui/status-badge";
import { useToast } from "@/components/ui/toast";
import { SkeletonTable } from "@/components/ui/skeleton";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  PieChart, Pie, Cell,
} from "recharts";
import { Download, Mail, FileText } from "lucide-react";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

export default function ReportsPage() {
  const { toast } = useToast();

  const { data, isLoading } = useQuery<WeeklyReport>({
    queryKey: ["weekly-report"],
    queryFn: () => api.getWeeklyReport("json"),
    staleTime: 60_000,
  });

  const htmlMutation = useMutation({
    mutationFn: api.getWeeklyReportHtml,
    onSuccess: (html) => {
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "weekly_report.html";
      a.click();
      URL.revokeObjectURL(url);
      toast("HTML report downloaded", "success");
    },
    onError: () => toast("Failed to download report", "error"),
  });

  const emailMutation = useMutation({
    mutationFn: api.emailWeeklyReport,
    onSuccess: () => toast("Weekly report email dispatched", "success"),
    onError: () => toast("Failed to send email", "error"),
  });

  const severityData = data?.severity_counts
    ? Object.entries(data.severity_counts)
        .filter(([, count]) => count > 0)
        .map(([severity, count]) => ({ severity, count }))
    : [];

  const techniqueData = (data?.top_techniques ?? []).slice(0, 8);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Reports"
        description="Weekly security summaries, severity breakdowns, and top MITRE techniques"
        breadcrumbs={[{ label: "Overview", href: "/" }, { label: "Reports" }]}
        actions={
          <div className="flex gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => htmlMutation.mutate()}
              disabled={htmlMutation.isPending}
            >
              <Download className="h-4 w-4" />
              Download HTML
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => emailMutation.mutate()}
              disabled={emailMutation.isPending}
            >
              <Mail className="h-4 w-4" />
              Email Report
            </Button>
          </div>
        }
      />

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-5">
            <p className="text-sm text-muted-foreground">Total Incidents</p>
            <p className="text-2xl font-bold mt-1">{data?.incident_count ?? 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-5">
            <p className="text-sm text-muted-foreground">Resolved</p>
            <p className="text-2xl font-bold mt-1 text-green-400">{data?.closed_count ?? 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-5">
            <p className="text-sm text-muted-foreground">Period</p>
            <p className="text-sm font-medium mt-1">
              {data?.since ? new Date(data.since).toLocaleDateString() : "—"} →{" "}
              {data?.generated_at ? new Date(data.generated_at).toLocaleDateString() : "—"}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-5">
            <p className="text-sm text-muted-foreground">Top Techniques</p>
            <p className="text-2xl font-bold mt-1">{techniqueData.length}</p>
          </CardContent>
        </Card>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Severity Breakdown</CardTitle>
          </CardHeader>
          <CardContent>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={severityData}
                    dataKey="count"
                    nameKey="severity"
                    cx="50%"
                    cy="50%"
                    outerRadius={90}
                    label={({ severity, count }) => `${severity}: ${count}`}
                  >
                    {severityData.map((entry) => (
                      <Cell
                        key={entry.severity}
                        fill={SEVERITY_COLORS[entry.severity] ?? "#6b7280"}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(224, 71%, 6%)",
                      border: "1px solid hsl(216, 34%, 17%)",
                      borderRadius: "0.5rem",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-muted-foreground text-center py-12 text-sm">
                No severity data for this period
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Top MITRE Techniques</CardTitle>
          </CardHeader>
          <CardContent>
            {techniqueData.length > 0 ? (
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={techniqueData} layout="vertical" margin={{ left: 100 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(216, 34%, 17%)" />
                  <XAxis type="number" tick={{ fontSize: 11, fill: "hsl(215, 20%, 55%)" }} />
                  <YAxis
                    type="category"
                    dataKey="technique"
                    tick={{ fontSize: 10, fill: "hsl(215, 20%, 55%)" }}
                    width={100}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "hsl(224, 71%, 6%)",
                      border: "1px solid hsl(216, 34%, 17%)",
                      borderRadius: "0.5rem",
                    }}
                  />
                  <Bar dataKey="count" fill="hsl(210, 100%, 56%)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-muted-foreground text-center py-12 text-sm">
                No technique data for this period
              </p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
