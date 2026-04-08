import { cn } from "@/lib/utils";

interface SkeletonProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: "text" | "card" | "table-row";
}

export function Skeleton({ className, variant = "text", ...props }: SkeletonProps) {
  if (variant === "card") {
    return (
      <div className={cn("rounded-lg border border-border bg-card p-6 space-y-3", className)} {...props}>
        <div className="h-4 w-1/3 rounded bg-muted animate-pulse" />
        <div className="h-8 w-1/2 rounded bg-muted animate-pulse" />
        <div className="h-3 w-2/3 rounded bg-muted animate-pulse" />
      </div>
    );
  }

  if (variant === "table-row") {
    return (
      <div className={cn("flex items-center gap-4 py-3 px-4", className)} {...props}>
        <div className="h-4 w-16 rounded bg-muted animate-pulse" />
        <div className="h-4 w-24 rounded bg-muted animate-pulse" />
        <div className="h-4 w-20 rounded bg-muted animate-pulse" />
        <div className="h-4 w-32 rounded bg-muted animate-pulse flex-1" />
      </div>
    );
  }

  return (
    <div
      className={cn("h-4 rounded bg-muted animate-pulse", className)}
      {...props}
    />
  );
}

export function SkeletonTable({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-0 divide-y divide-border/30">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} variant="table-row" />
      ))}
    </div>
  );
}
