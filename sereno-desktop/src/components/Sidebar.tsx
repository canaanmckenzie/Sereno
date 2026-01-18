import { Activity, List, ScrollText, Settings } from "lucide-react";
import type { Tab } from "../App";

interface SidebarProps {
  activeTab: Tab;
  onTabChange: (tab: Tab) => void;
}

const tabs: { id: Tab; label: string; icon: typeof Activity }[] = [
  { id: "connections", label: "Connections", icon: Activity },
  { id: "rules", label: "Rules", icon: List },
  { id: "logs", label: "Logs", icon: ScrollText },
  { id: "settings", label: "Settings", icon: Settings },
];

export default function Sidebar({ activeTab, onTabChange }: SidebarProps) {
  return (
    <aside className="w-48 bg-sereno-surface border-r border-sereno-border flex flex-col">
      <nav className="flex-1 py-2">
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => onTabChange(id)}
            className={`w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-colors ${
              activeTab === id
                ? "bg-sereno-hover text-sereno-text border-r-2 border-sereno-accent"
                : "text-sereno-muted hover:text-sereno-text hover:bg-sereno-hover/50"
            }`}
          >
            <Icon className="w-4 h-4" />
            <span>{label}</span>
          </button>
        ))}
      </nav>

      {/* Version info at bottom */}
      <div className="p-4 border-t border-sereno-border">
        <p className="text-xs text-sereno-muted">Sereno v0.1.0</p>
        <p className="text-xs text-sereno-muted/50">Kernel Driver Mode</p>
      </div>
    </aside>
  );
}
