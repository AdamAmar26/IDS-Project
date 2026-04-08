import { cn, severityColor } from "@/lib/utils";
import { Badge } from "./badge";

interface StatusBadgeProps {
  severity?: string;
  status?: string;
  className?: string;
}

const STATUS_STYLES: Record<string, string> = {
  open: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  acknowledged: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  investigating: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  resolved: "bg-green-500/20 text-green-400 border-green-500/30",
  closed: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

export function StatusBadge({ severity, status, className }: StatusBadgeProps) {
  if (severity) {
    return (
      <Badge className={cn(severityColor(severity), className)}>
        {severity.toUpperCase()}
      </Badge>
    );
  }

  if (status) {
    return (
      <Badge
        className={cn(
          STATUS_STYLES[status] ?? "bg-gray-500/20 text-gray-400 border-gray-500/30",
          className,
        )}
      >
        {status}
      </Badge>
    );
  }

  return null;
}
