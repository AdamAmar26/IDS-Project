"use client";

import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { Dialog } from "@/components/ui/dialog";
import { EmptyState } from "@/components/ui/empty-state";
import { useToast } from "@/components/ui/toast";
import { formatTimestamp } from "@/lib/utils";
import { Wrench, Shield, Play, AlertTriangle, History } from "lucide-react";

const AVAILABLE_ACTIONS = [
  {
    id: "block_ip",
    name: "Block IP Address",
    description: "Add a Windows Firewall outbound block rule for a specific IP address.",
    params: ["target (IP address)"],
    severity: "high",
  },
];

export default function SoarPage() {
  const [ip, setIp] = useState("");
  const [dryRun, setDryRun] = useState(true);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const { toast } = useToast();

  const mutation = useMutation({
    mutationFn: () => api.runSoarAction("block_ip", ip, dryRun),
    onSuccess: (data) => {
      if (data.dry_run) {
        toast("Dry run complete — no changes made", "info");
      } else {
        toast(data.ok ? "IP blocked successfully" : "Action failed — check SOAR logs", data.ok ? "success" : "error");
      }
      setConfirmOpen(false);
    },
    onError: (err) => {
      toast(String(err), "error");
      setConfirmOpen(false);
    },
  });

  const { data: auditData } = useQuery({
    queryKey: ["soar-history"],
    queryFn: () =>
      fetch(
        `${process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"}/audit?action=soar&limit=20`,
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

  const history = auditData?.items ?? [];

  const handleRun = () => {
    if (!ip.trim()) {
      toast("Please enter a valid IP address", "error");
      return;
    }
    if (!dryRun) {
      setConfirmOpen(true);
    } else {
      mutation.mutate();
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="SOAR"
        description="Security Orchestration, Automation and Response actions"
        breadcrumbs={[{ label: "Overview", href: "/" }, { label: "SOAR" }]}
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Available Actions */}
        <div className="lg:col-span-2 space-y-4">
          {AVAILABLE_ACTIONS.map((action) => (
            <Card key={action.id}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Shield className="h-4 w-4 text-primary" />
                    {action.name}
                  </CardTitle>
                  <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30">
                    {action.severity}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground">{action.description}</p>

                <div className="flex flex-wrap gap-3 items-end">
                  <Input
                    label="Target IP Address"
                    value={ip}
                    onChange={(e) => setIp(e.target.value)}
                    placeholder="e.g., 185.220.101.1"
                    className="w-56"
                  />
                  <label className="flex items-center gap-2 text-sm h-9 px-3 rounded-md border border-border cursor-pointer">
                    <input
                      type="checkbox"
                      checked={dryRun}
                      onChange={(e) => setDryRun(e.target.checked)}
                      className="accent-primary"
                    />
                    <span className={dryRun ? "text-foreground" : "text-red-400 font-medium"}>
                      {dryRun ? "Dry Run" : "LIVE"}
                    </span>
                  </label>
                  <Button onClick={handleRun} disabled={mutation.isPending}>
                    <Play className="h-4 w-4" />
                    {dryRun ? "Preview" : "Execute"}
                  </Button>
                </div>

                {mutation.data && (
                  <div className="rounded-md border bg-secondary/30 p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <Badge variant={mutation.data.dry_run ? "outline" : mutation.data.ok ? "default" : "destructive"}>
                        {mutation.data.dry_run ? "Dry Run" : mutation.data.ok ? "Success" : "Failed"}
                      </Badge>
                    </div>
                    <pre className="text-xs whitespace-pre-wrap text-muted-foreground">
                      {JSON.stringify(mutation.data, null, 2)}
                    </pre>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Execution History */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <History className="h-4 w-4" />
              Execution History
            </CardTitle>
          </CardHeader>
          <CardContent>
            {history.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-6">
                No SOAR actions executed yet
              </p>
            ) : (
              <div className="space-y-2 max-h-[400px] overflow-y-auto">
                {history.map((h: any) => (
                  <div key={h.id} className="rounded border p-2.5 text-xs">
                    <div className="flex items-center justify-between">
                      <Badge variant="outline" className="text-[10px]">
                        {h.action}
                      </Badge>
                      <span className="text-muted-foreground">
                        {formatTimestamp(h.created_at)}
                      </span>
                    </div>
                    <p className="text-muted-foreground mt-1">
                      {h.actor} → {h.resource}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Confirmation dialog for live execution */}
      <Dialog
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        title="Confirm Live Action"
        description="This will make real changes to the system firewall."
      >
        <div className="space-y-4">
          <div className="flex items-center gap-3 rounded-md border border-destructive/30 bg-destructive/5 p-3">
            <AlertTriangle className="h-5 w-5 text-destructive shrink-0" />
            <div className="text-sm">
              <p className="font-medium text-destructive">Live execution mode</p>
              <p className="text-muted-foreground">
                This will add a firewall rule blocking outbound traffic to <strong>{ip}</strong>.
                This action can be reversed manually.
              </p>
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => mutation.mutate()}
              disabled={mutation.isPending}
            >
              Confirm & Execute
            </Button>
          </div>
        </div>
      </Dialog>
    </div>
  );
}
