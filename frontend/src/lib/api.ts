const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
let authToken = "";
let loginPromise: Promise<void> | null = null;

export function setAuthToken(token: string) {
  authToken = token;
  if (typeof window !== "undefined") {
    window.localStorage.setItem("ids_token", token);
  }
}

export function getAuthToken(): string {
  return authToken;
}

if (typeof window !== "undefined") {
  authToken = window.localStorage.getItem("ids_token") || "";
}

const DEV_USERNAME = process.env.NEXT_PUBLIC_IDS_USERNAME || "";
const DEV_PASSWORD = process.env.NEXT_PUBLIC_IDS_PASSWORD || "";

async function ensureAuth(): Promise<void> {
  if (authToken) return;
  if (!DEV_USERNAME || !DEV_PASSWORD) return;
  if (loginPromise) return loginPromise;

  loginPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: DEV_USERNAME, password: DEV_PASSWORD }),
      });
      if (res.ok) {
        const data = await res.json();
        setAuthToken(data.access_token);
      }
    } catch {
      // backend unreachable, will fail on actual request
    } finally {
      loginPromise = null;
    }
  })();
  return loginPromise;
}

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  await ensureAuth();
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      ...init?.headers,
    },
  });
  if (res.status === 401 && authToken) {
    authToken = "";
    if (typeof window !== "undefined") window.localStorage.removeItem("ids_token");
    await ensureAuth();
    const retry = await fetch(url, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
        ...init?.headers,
      },
    });
    if (!retry.ok) throw new Error(`API ${retry.status}: ${retry.statusText}`);
    return retry.json();
  }
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

export interface TimelineItem {
  type: string;
  time: string;
  id: number;
  title: string;
  detail: string;
}

export interface WeeklyReport {
  since: string;
  generated_at: string;
  incident_count: number;
  closed_count: number;
  severity_counts: Record<string, number>;
  top_techniques: { technique: string; count: number }[];
}

export interface ThreatSummary {
  briefing: string;
  data: {
    open_incidents: number;
    total_incidents_24h: number;
    alerts_24h: number;
    anomaly_alerts_24h: number;
    hosts_at_risk: number;
    severity_counts: { critical: number; high: number; medium: number; low: number };
    top_rules: string[];
    threat_intel_hits_24h: number;
    trend: string;
    model_health: string;
  };
  generated_at: string;
  llm_available: boolean;
}

export interface SavedHunt {
  id: number;
  name: string;
  filters: Record<string, string>;
  created_at: string;
}

export interface HuntResults {
  total: number;
  events: RawEvent[];
  alerts: Alert[];
}

export const api = {
  login: (username: string, password: string) =>
    apiFetch<{ access_token: string }>("/auth/token", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  getMetrics: () => apiFetch<Metrics>("/metrics/summary"),
  getAlerts: (params?: string) => apiFetch<Alert[]>(`/alerts${params ? `?${params}` : ""}`),
  getIncidents: (params?: string) => apiFetch<Incident[]>(`/incidents${params ? `?${params}` : ""}`),
  getIncident: (id: number) => apiFetch<Incident>(`/incidents/${id}`),
  patchIncidentStatus: (id: number, status: string) =>
    apiFetch(`/incidents/${id}/status?status=${status}`, { method: "PATCH" }),
  getIncidentTimeline: (id: number) =>
    apiFetch<{ incident_id: number; items: TimelineItem[] }>(`/incidents/${id}/timeline`),
  getEvents: (params?: string) => apiFetch<RawEvent[]>(`/events${params ? `?${params}` : ""}`),
  getFeatures: (params?: string) => apiFetch<FeatureWindow[]>(`/features${params ? `?${params}` : ""}`),
  getHost: (hostId: string) => apiFetch<HostDetail>(`/hosts/${hostId}`),
  simulate: (scenario: string) =>
    apiFetch(`/admin/simulate?scenario=${scenario}`, { method: "POST" }),
  getNotificationSettings: () => apiFetch<{ teams_configured: boolean; generic_webhook_configured: boolean; email_configured: boolean }>("/settings/notifications"),
  testNotifications: () => apiFetch("/settings/notifications/test", { method: "POST" }),
  reloadRules: () => apiFetch<{ loaded_rules: number }>("/admin/reload-rules", { method: "POST" }),
  getWeeklyReport: (format: "json" | "html" = "json") =>
    apiFetch<WeeklyReport>(`/reports/weekly?format=${format}`),
  getWeeklyReportHtml: async () => {
    const res = await fetch(`${API_BASE}/reports/weekly?format=html`, {
      headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
    });
    if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
    return res.text();
  },
  emailWeeklyReport: () => apiFetch("/reports/weekly/email", { method: "POST" }),
  getAuditEvents: () => apiFetch<Array<{ id: number; actor: string; action: string; resource: string; metadata: Record<string, unknown>; created_at: string }>>("/audit"),
  getFleetSummary: () => apiFetch<Array<{ host_id: string; alert_count: number; incident_count: number }>>("/fleet/summary"),
  runSoarAction: (action: string, target: string, dry_run = true) =>
    apiFetch<{ ok: boolean; dry_run?: boolean; command?: string; stdout?: string; stderr?: string }>(
      "/soar/action",
      { method: "POST", body: JSON.stringify({ action, target, dry_run }) },
    ),
  getSummary: () => apiFetch<ThreatSummary>("/summary"),
  getHunts: () => apiFetch<SavedHunt[]>("/hunts"),
  createHunt: (name: string, filters: Record<string, string>) =>
    apiFetch<SavedHunt>("/hunts", {
      method: "POST",
      body: JSON.stringify({ name, filters }),
    }),
  runHunt: (id: number) =>
    apiFetch<HuntResults>(`/hunts/${id}/run`, { method: "POST" }),
};
