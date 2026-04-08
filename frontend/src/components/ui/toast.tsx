"use client";

import {
  createContext,
  useContext,
  useState,
  useCallback,
  type ReactNode,
} from "react";
import { cn } from "@/lib/utils";
import { CheckCircle2, AlertTriangle, Info, X } from "lucide-react";

type ToastVariant = "success" | "error" | "info";

interface Toast {
  id: number;
  message: string;
  variant: ToastVariant;
}

interface ToastContextValue {
  toast: (message: string, variant?: ToastVariant) => void;
}

const ToastContext = createContext<ToastContextValue>({
  toast: () => {},
});

export function useToast() {
  return useContext(ToastContext);
}

let nextId = 0;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const addToast = useCallback((message: string, variant: ToastVariant = "info") => {
    const id = nextId++;
    setToasts((prev) => [...prev, { id, message, variant }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  }, []);

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={{ toast: addToast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-[60] space-y-2 max-w-sm">
        {toasts.map((t) => {
          const Icon =
            t.variant === "success"
              ? CheckCircle2
              : t.variant === "error"
                ? AlertTriangle
                : Info;
          return (
            <div
              key={t.id}
              className={cn(
                "flex items-start gap-3 rounded-lg border px-4 py-3 shadow-lg backdrop-blur-sm text-sm animate-in slide-in-from-right-5",
                t.variant === "success" &&
                  "border-green-500/30 bg-green-500/10 text-green-400",
                t.variant === "error" &&
                  "border-red-500/30 bg-red-500/10 text-red-400",
                t.variant === "info" &&
                  "border-border bg-card text-foreground",
              )}
            >
              <Icon className="h-4 w-4 shrink-0 mt-0.5" />
              <p className="flex-1">{t.message}</p>
              <button
                onClick={() => dismiss(t.id)}
                className="shrink-0 text-muted-foreground hover:text-foreground"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}
