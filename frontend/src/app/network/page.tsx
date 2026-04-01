"use client";

import { useQuery } from "@tanstack/react-query";
import { api, type FeatureWindow } from "@/lib/api";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from "recharts";

function extractConnections(windows: FeatureWindow[]) {
  const nodes = new Map<string, { id: string; type: string; connections: number }>();
  const edges: { source: string; target: string; count: number }[] = [];

  for (const w of windows) {
    if (!nodes.has(w.host_id)) {
      nodes.set(w.host_id, { id: w.host_id, type: "host", connections: 0 });
    }
    const host = nodes.get(w.host_id)!;
    host.connections += w.outbound_conn_count;

    const ctx = w.context as Record<string, unknown> | null;
    if (ctx?.top_connected_processes) {
      const procs = ctx.top_connected_processes as Record<string, number>;
      for (const [proc, count] of Object.entries(procs)) {
        const procId = `${w.host_id}:${proc}`;
        if (!nodes.has(procId)) {
          nodes.set(procId, { id: proc, type: "process", connections: 0 });
        }
        nodes.get(procId)!.connections += count;
        edges.push({ source: w.host_id, target: procId, count });
      }
    }
  }

  return { nodes: Array.from(nodes.values()), edges };
}

export default function NetworkPage() {
  const { data: features } = useQuery<FeatureWindow[]>({
    queryKey: ["features-network"],
    queryFn: () => api.getFeatures("limit=50"),
  });

  const windows = features ?? [];
  const { nodes } = extractConnections(windows);

  const connectionData = windows
    .slice(0, 20)
    .reverse()
    .map((w) => ({
      time: new Date(w.window_end).toLocaleTimeString(),
      outbound: w.outbound_conn_count,
      ips: w.unique_dest_ips,
      ports: w.unique_dest_ports,
    }));

  const trafficData = windows
    .slice(0, 20)
    .reverse()
    .map((w) => ({
      time: new Date(w.window_end).toLocaleTimeString(),
      sent: Math.round(w.bytes_sent / 1024),
      received: Math.round(w.bytes_received / 1024),
    }));

  const topProcesses = nodes
    .filter((n) => n.type === "process")
    .sort((a, b) => b.connections - a.connections)
    .slice(0, 10);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold">Network Connections</h1>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle>Outbound Connections</CardTitle>
          </CardHeader>
          <CardContent>
            {connectionData.length > 0 ? (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={connectionData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(216, 34%, 17%)" />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: "hsl(215, 20%, 55%)" }} />
                  <YAxis tick={{ fontSize: 10, fill: "hsl(215, 20%, 55%)" }} />
                  <Tooltip contentStyle={{ backgroundColor: "hsl(224, 71%, 6%)", border: "1px solid hsl(216, 34%, 17%)" }} />
                  <Bar dataKey="outbound" fill="hsl(210, 100%, 56%)" radius={[2, 2, 0, 0]} />
                  <Bar dataKey="ips" fill="hsl(142, 71%, 45%)" radius={[2, 2, 0, 0]} />
                  <Bar dataKey="ports" fill="hsl(280, 65%, 60%)" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-muted-foreground text-center py-12">No data</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Traffic Volume (KB)</CardTitle>
          </CardHeader>
          <CardContent>
            {trafficData.length > 0 ? (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={trafficData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(216, 34%, 17%)" />
                  <XAxis dataKey="time" tick={{ fontSize: 10, fill: "hsl(215, 20%, 55%)" }} />
                  <YAxis tick={{ fontSize: 10, fill: "hsl(215, 20%, 55%)" }} />
                  <Tooltip contentStyle={{ backgroundColor: "hsl(224, 71%, 6%)", border: "1px solid hsl(216, 34%, 17%)" }} />
                  <Bar dataKey="sent" fill="hsl(0, 63%, 51%)" radius={[2, 2, 0, 0]} name="Sent (KB)" />
                  <Bar dataKey="received" fill="hsl(210, 100%, 56%)" radius={[2, 2, 0, 0]} name="Received (KB)" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-muted-foreground text-center py-12">No data</p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Top Connected Processes</CardTitle>
        </CardHeader>
        <CardContent>
          {topProcesses.length > 0 ? (
            <div className="space-y-3">
              {topProcesses.map((proc) => (
                <div key={proc.id} className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Badge variant="outline" className="font-mono">
                      {proc.id}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="w-40 h-2 bg-secondary rounded-full overflow-hidden">
                      <div
                        className="h-full bg-primary rounded-full"
                        style={{
                          width: `${Math.min(100, (proc.connections / Math.max(topProcesses[0]?.connections || 1, 1)) * 100)}%`,
                        }}
                      />
                    </div>
                    <span className="text-sm text-muted-foreground w-16 text-right">
                      {proc.connections} conns
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-muted-foreground text-center py-8">No connection data</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
