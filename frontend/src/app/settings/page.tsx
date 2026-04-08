"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, setAuthToken } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/ui/page-header";
import { useToast } from "@/components/ui/toast";
import {
  LogIn, LogOut, Bell, BellOff, RefreshCw, Shield, CheckCircle, XCircle,
  Settings as SettingsIcon,
} from "lucide-react";

function ChannelStatus({ configured, label }: { configured: boolean; label: string }) {
  return (
    <div className="flex items-center justify-between py-2">
      <span className="text-sm">{label}</span>
      <div className="flex items-center gap-1.5 text-xs">
        {configured ? (
          <>
            <CheckCircle className="h-3.5 w-3.5 text-green-400" />
            <span className="text-green-400">Configured</span>
          </>
        ) : (
          <>
            <XCircle className="h-3.5 w-3.5 text-muted-foreground" />
            <span className="text-muted-foreground">Not configured</span>
          </>
        )}
      </div>
    </div>
  );
}

export default function SettingsPage() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const isLoggedIn =
    typeof window !== "undefined" && !!window.localStorage.getItem("ids_token");

  const loginMutation = useMutation({
    mutationFn: () => api.login(username, password),
    onSuccess: (data) => {
      setAuthToken(data.access_token);
      setPassword("");
      toast("Authenticated successfully", "success");
    },
    onError: () => toast("Invalid credentials", "error"),
  });

  const handleLogout = () => {
    setAuthToken("");
    queryClient.clear();
    toast("Logged out", "info");
  };

  const testMutation = useMutation({
    mutationFn: api.testNotifications,
    onSuccess: () => toast("Test notification sent", "success"),
    onError: () => toast("Failed to send test notification", "error"),
  });

  const reloadMutation = useMutation({
    mutationFn: api.reloadRules,
    onSuccess: (data) => toast(`Loaded ${data.loaded_rules} correlation rules`, "success"),
    onError: () => toast("Failed to reload rules", "error"),
  });

  const { data: settings, refetch } = useQuery({
    queryKey: ["notification-settings"],
    queryFn: api.getNotificationSettings,
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="Authentication, notifications, and system configuration"
        breadcrumbs={[{ label: "Overview", href: "/" }, { label: "Settings" }]}
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Authentication */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <Shield className="h-4 w-4" />
              Authentication
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {isLoggedIn ? (
              <div className="space-y-3">
                <div className="flex items-center gap-2 text-sm">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span>Authenticated — token stored in browser</span>
                </div>
                <Button variant="secondary" onClick={handleLogout}>
                  <LogOut className="h-4 w-4" />
                  Logout
                </Button>
              </div>
            ) : (
              <div className="space-y-3">
                <Input
                  label="Username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
                <Input
                  label="Password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
                <Button
                  onClick={() => loginMutation.mutate()}
                  disabled={loginMutation.isPending}
                >
                  <LogIn className="h-4 w-4" />
                  Login
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Notifications */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="text-base flex items-center gap-2">
                <Bell className="h-4 w-4" />
                Notifications
              </CardTitle>
              <Button
                variant="ghost"
                size="icon"
                onClick={() => refetch()}
              >
                <RefreshCw className="h-4 w-4" />
              </Button>
            </div>
          </CardHeader>
          <CardContent className="space-y-1">
            <ChannelStatus
              configured={settings?.teams_configured ?? false}
              label="Microsoft Teams"
            />
            <ChannelStatus
              configured={settings?.generic_webhook_configured ?? false}
              label="Generic Webhook"
            />
            <ChannelStatus
              configured={settings?.email_configured ?? false}
              label="Email (SMTP)"
            />
            <div className="pt-3">
              <Button
                variant="secondary"
                size="sm"
                onClick={() => testMutation.mutate()}
                disabled={testMutation.isPending}
              >
                Send Test Notification
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Correlation Rules */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <SettingsIcon className="h-4 w-4" />
              Correlation Engine
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <p className="text-sm text-muted-foreground">
              Reload correlation rules from the YAML configuration file.
              This picks up any changes without restarting the backend.
            </p>
            <Button
              variant="secondary"
              onClick={() => reloadMutation.mutate()}
              disabled={reloadMutation.isPending}
            >
              <RefreshCw className="h-4 w-4" />
              Reload Rules
            </Button>
          </CardContent>
        </Card>

        {/* About */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">About</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Platform</span>
                <span>IDS Platform v3.0</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Detection</span>
                <span>Isolation Forest + SHAP</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Correlation</span>
                <span>Rule-based + YAML dynamic</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">AI Engine</span>
                <span>Ollama (local LLM)</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Framework</span>
                <span>MITRE ATT&CK</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
