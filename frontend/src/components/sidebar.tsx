"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useEffect, createContext, useContext } from "react";
import { cn } from "@/lib/utils";
import {
  Activity,
  Shield,
  Bell,
  Network,
  Database,
  Grid3X3,
  Search,
  Server,
  Wrench,
  FileText,
  ClipboardList,
  Settings,
  ChevronLeft,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import { ThemeToggle } from "./theme-toggle";

interface NavItem {
  href: string;
  label: string;
  icon: React.ElementType;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const PRIMARY_ITEMS: NavItem[] = [
  { href: "/", label: "Overview", icon: Activity },
  { href: "/incidents", label: "Incidents", icon: Shield },
  { href: "/alerts", label: "Alerts", icon: Bell },
  { href: "/network", label: "Network", icon: Network },
];

const NAV_GROUPS: NavGroup[] = [
  {
    label: "Investigate",
    items: [
      { href: "/telemetry", label: "Telemetry", icon: Database },
      { href: "/mitre", label: "ATT&CK Matrix", icon: Grid3X3 },
      { href: "/hunt", label: "Hunt", icon: Search },
    ],
  },
  {
    label: "Operations",
    items: [
      { href: "/fleet", label: "Fleet", icon: Server },
      { href: "/soar", label: "SOAR", icon: Wrench },
      { href: "/reports", label: "Reports", icon: FileText },
      { href: "/audit", label: "Audit", icon: ClipboardList },
    ],
  },
];

const SidebarContext = createContext({ collapsed: false });

export function useSidebar() {
  return useContext(SidebarContext);
}

function NavLink({ href, label, icon: Icon, collapsed }: NavItem & { collapsed: boolean }) {
  const pathname = usePathname();
  const active = href === "/" ? pathname === "/" : pathname.startsWith(href);

  return (
    <Link
      href={href}
      title={collapsed ? label : undefined}
      className={cn(
        "flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors",
        active
          ? "bg-primary/10 text-primary"
          : "text-muted-foreground hover:bg-accent/50 hover:text-foreground",
        collapsed && "justify-center px-2",
      )}
    >
      <Icon className="h-4 w-4 shrink-0" />
      {!collapsed && <span>{label}</span>}
    </Link>
  );
}

function CollapsibleGroup({
  group,
  collapsed,
}: {
  group: NavGroup;
  collapsed: boolean;
}) {
  const pathname = usePathname();
  const hasActive = group.items.some((item) =>
    item.href === "/" ? pathname === "/" : pathname.startsWith(item.href),
  );
  const [open, setOpen] = useState(hasActive);

  useEffect(() => {
    if (hasActive) setOpen(true);
  }, [hasActive]);

  if (collapsed) {
    return (
      <div className="space-y-1">
        {group.items.map((item) => (
          <NavLink key={item.href} {...item} collapsed={collapsed} />
        ))}
      </div>
    );
  }

  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center justify-between px-3 py-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground/70 hover:text-muted-foreground transition-colors"
      >
        <span>{group.label}</span>
        {open ? (
          <ChevronDown className="h-3 w-3" />
        ) : (
          <ChevronRight className="h-3 w-3" />
        )}
      </button>
      {open && (
        <div className="space-y-0.5">
          {group.items.map((item) => (
            <NavLink key={item.href} {...item} collapsed={collapsed} />
          ))}
        </div>
      )}
    </div>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const saved = window.localStorage.getItem("ids_sidebar_collapsed");
    if (saved === "true") setCollapsed(true);
  }, []);

  const toggle = () => {
    const next = !collapsed;
    setCollapsed(next);
    if (typeof window !== "undefined") {
      window.localStorage.setItem("ids_sidebar_collapsed", String(next));
    }
  };

  return (
    <SidebarContext.Provider value={{ collapsed }}>
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex flex-col border-r border-border bg-card/80 backdrop-blur-sm transition-all duration-200",
          collapsed ? "w-16" : "w-56",
        )}
      >
        <div
          className={cn(
            "flex h-14 items-center border-b border-border px-4 shrink-0",
            collapsed && "justify-center px-2",
          )}
        >
          <Shield className="h-6 w-6 text-primary shrink-0" />
          {!collapsed && (
            <span className="ml-2 font-bold text-base whitespace-nowrap">
              IDS Platform
            </span>
          )}
        </div>

        <nav className="flex-1 overflow-y-auto px-2 py-4 space-y-6">
          <div className="space-y-0.5">
            {PRIMARY_ITEMS.map((item) => (
              <NavLink key={item.href} {...item} collapsed={collapsed} />
            ))}
          </div>

          {NAV_GROUPS.map((group) => (
            <CollapsibleGroup
              key={group.label}
              group={group}
              collapsed={collapsed}
            />
          ))}
        </nav>

        <div className="shrink-0 border-t border-border px-2 py-3 space-y-1">
          <NavLink
            href="/settings"
            label="Settings"
            icon={Settings}
            collapsed={collapsed}
          />
          <ThemeToggle collapsed={collapsed} />
          <button
            onClick={toggle}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className={cn(
              "flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-accent/50 hover:text-foreground transition-colors",
              collapsed && "justify-center px-2",
            )}
          >
            <ChevronLeft
              className={cn(
                "h-4 w-4 shrink-0 transition-transform",
                collapsed && "rotate-180",
              )}
            />
            {!collapsed && <span>Collapse</span>}
          </button>
        </div>
      </aside>

      <div
        className={cn(
          "transition-all duration-200",
          collapsed ? "pl-16" : "pl-56",
        )}
      >
        <main id="main-content" className="max-w-[1400px] mx-auto px-6 py-6">{children}</main>
      </div>
    </SidebarContext.Provider>
  );
}
