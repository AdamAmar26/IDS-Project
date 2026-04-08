"use client";

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { EmptyState } from "@/components/ui/empty-state";
import { SkeletonTable } from "@/components/ui/skeleton";
import { formatTimestamp, cn } from "@/lib/utils";
import { Download, ClipboardList, ChevronLeft, ChevronRight } from "lucide-react";

interface AuditRow {
  id: number;
  actor: string;
  action: string;
  resource: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export default function AuditPage() {
  const [actorFilter, setActorFilter] = useState("");
  const [actionFilter, setActionFilter] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 25;

  const params = new URLSearchParams();
  params.set("limit", String(pageSize));
  params.set("offset", String(page * pageSize));
  if (actorFilter) params.set("actor", actorFilter);
  if (actionFilter) params.set("action", actionFilter);

  const { data, isLoading } = useQuery<{ total: number; items: AuditRow[] }>({
    queryKey: ["audit-events", actorFilter, actionFilter, page],
    queryFn: () =>
      fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/audit?${params.toString()}`,
        {
          headers: {
            "Content-Type": "application/json",
            ...(typeof window !== "undefined" && window.localStorage.getItem("ids_token")
              ? { Authorization: `Bearer ${window.localStorage.getItem("ids_token")}` }
              : {}),
          },
        },
      ).then((r) => r.json()),
  });

  const total = data?.total ?? 0;
  const items = data?.items ?? [];
  const totalPages = Math.ceil(total / pageSize);

  const exportCsv = () => {
    const rows = [["ID", "Actor", "Action", "Resource", "Time"]];
    items.forEach((r) => rows.push([String(r.id), r.actor, r.action, r.resource, r.created_at]));
    const csv = rows.map((r) => r.join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "audit_log.csv";
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit Log"
        description="Immutable record of all platform actions and system events"
        breadcrumbs={[{ label: "Overview", href: "/" }, { label: "Audit" }]}
        actions={
          <Button variant="secondary" size="sm" onClick={exportCsv}>
            <Download className="h-4 w-4" />
            Export CSV
          </Button>
        }
      />

      <div className="flex flex-wrap gap-3">
        <Input
          placeholder="Filter by actor..."
          value={actorFilter}
          onChange={(e) => { setActorFilter(e.target.value); setPage(0); }}
          className="w-48"
        />
        <Input
          placeholder="Filter by action..."
          value={actionFilter}
          onChange={(e) => { setActionFilter(e.target.value); setPage(0); }}
          className="w-48"
        />
      </div>

      <Card>
        <CardContent className="p-0">
          {isLoading ? (
            <SkeletonTable rows={8} />
          ) : items.length === 0 ? (
            <EmptyState
              icon={ClipboardList}
              title="No audit events"
              description="Actions will be logged here as they occur."
            />
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border text-left text-muted-foreground">
                      <th className="px-4 py-3 font-medium">ID</th>
                      <th className="px-4 py-3 font-medium">Actor</th>
                      <th className="px-4 py-3 font-medium">Action</th>
                      <th className="px-4 py-3 font-medium">Resource</th>
                      <th className="px-4 py-3 font-medium">Time</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((row) => (
                      <tr key={row.id} className="border-b border-border/50 hover:bg-accent/30 transition-colors">
                        <td className="px-4 py-3 font-mono text-xs">{row.id}</td>
                        <td className="px-4 py-3">
                          <Badge variant="outline">{row.actor}</Badge>
                        </td>
                        <td className="px-4 py-3 text-xs font-mono">{row.action}</td>
                        <td className="px-4 py-3 text-xs text-muted-foreground">{row.resource}</td>
                        <td className="px-4 py-3 text-xs text-muted-foreground whitespace-nowrap">
                          {formatTimestamp(row.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {totalPages > 1 && (
                <div className="flex items-center justify-between px-4 py-3 border-t border-border">
                  <p className="text-xs text-muted-foreground">
                    Showing {page * pageSize + 1}–{Math.min((page + 1) * pageSize, total)} of {total}
                  </p>
                  <div className="flex gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={page === 0}
                      onClick={() => setPage(page - 1)}
                    >
                      <ChevronLeft className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={page >= totalPages - 1}
                      onClick={() => setPage(page + 1)}
                    >
                      <ChevronRight className="h-4 w-4" />
                    </Button>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
