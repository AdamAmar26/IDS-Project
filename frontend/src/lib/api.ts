const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

export interface Alert {
  id: number;
  host_id: string;
  feature_window_id: number | null;
  anomaly_score: number;
  is_anomaly: boolean;
  top_features: Record<string, number> | null;
  created_at: string;
}

export interface Incident {
  id: number;
  host_id: string;
  risk_score: number;
  status: string;
  severity: string;
  summary: string;
  explanation: string;
  suggested_actions: string;
  mitre_tactics: { id: string; name: string }[];
  mitre_techniques: { id: string; name: string; url: string; tactics: string[]; triggered_by: string[] }[];
  threat_intel_hits: string[];
  created_at: string;
  updated_at: string;
  alert_ids: number[];
}

export interface FeatureWindow {
  id: number;
  host_id: string;
  window_start: string;
  window_end: string;
  failed_login_count: number;
  successful_login_count: number;
  unique_dest_ips: number;
  unique_dest_ports: number;
  outbound_conn_count: number;
  bytes_sent: number;
  bytes_received: number;
  avg_process_cpu: number;
  new_process_count: number;
  inbound_outbound_ratio: number;
  unusual_hour_flag: boolean;
  context: Record<string, unknown> | null;
}

export interface RawEvent {
  id: number;
  host_id: string;
  event_type: string;
  timestamp: string;
  data: Record<string, unknown>;
}

export interface Metrics {
  total_events: number;
  total_windows: number;
  total_alerts: number;
  total_incidents: number;
  active_incidents: number;
  anomaly_rate: number;
  model_trained: boolean;
  training_samples: number;
  min_training_samples: number;
  security_log_available: boolean;
}

export interface HostDetail {
  host_id: string;
  baseline: Record<string, number> | null;
  current_features: Record<string, number> | null;
  alert_count: number;
  incident_count: number;
}

export const api = {
  getMetrics: () => apiFetch<Metrics>("/metrics/summary"),
  getAlerts: (params?: string) => apiFetch<Alert[]>(`/alerts${params ? `?${params}` : ""}`),
  getIncidents: (params?: string) => apiFetch<Incident[]>(`/incidents${params ? `?${params}` : ""}`),
  getIncident: (id: number) => apiFetch<Incident>(`/incidents/${id}`),
  patchIncidentStatus: (id: number, status: string) =>
    apiFetch(`/incidents/${id}/status?status=${status}`, { method: "PATCH" }),
  getEvents: (params?: string) => apiFetch<RawEvent[]>(`/events${params ? `?${params}` : ""}`),
  getFeatures: (params?: string) => apiFetch<FeatureWindow[]>(`/features${params ? `?${params}` : ""}`),
  getHost: (hostId: string) => apiFetch<HostDetail>(`/hosts/${hostId}`),
  simulate: (scenario: string) =>
    apiFetch(`/admin/simulate?scenario=${scenario}`, { method: "POST" }),
};
