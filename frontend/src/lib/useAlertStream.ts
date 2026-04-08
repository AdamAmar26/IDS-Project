"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import { getAuthToken } from "./api";

export interface StreamEvent {
  type: string;
  data: Record<string, unknown>;
}

const WS_BASE = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/ws/events";

export function useAlertStream() {
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout>>();
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const token = getAuthToken() ||
      (typeof window !== "undefined"
        ? window.localStorage.getItem("ids_token") || ""
        : "");

    if (!token) {
      reconnectRef.current = setTimeout(connect, 2000);
      return;
    }

    const url = `${WS_BASE}?token=${encodeURIComponent(token)}`;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      if (mountedRef.current) setConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const parsed: StreamEvent = JSON.parse(event.data);
        if (mountedRef.current) {
          setEvents((prev) => [parsed, ...prev].slice(0, 100));
        }
      } catch {
        // ignore malformed messages
      }
    };

    ws.onclose = () => {
      if (mountedRef.current) {
        setConnected(false);
        reconnectRef.current = setTimeout(connect, 3000);
      }
    };

    ws.onerror = () => ws.close();
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    const delay = setTimeout(connect, 1500);
    return () => {
      mountedRef.current = false;
      clearTimeout(delay);
      clearTimeout(reconnectRef.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const clearEvents = useCallback(() => setEvents([]), []);

  return { events, connected, clearEvents };
}
