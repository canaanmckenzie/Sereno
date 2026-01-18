import { Shield, ChevronUp, ChevronDown } from "lucide-react";

interface HeaderProps {
  driverStatus: "running" | "stopped" | "unknown";
  bandwidth: { up: number; down: number; flows: number };
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

export default function Header({ driverStatus, bandwidth }: HeaderProps) {
  return (
    <header className="h-12 bg-sereno-surface border-b border-sereno-border flex items-center px-4 justify-between">
      {/* Left: Logo and title */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-sereno-accent" />
          <span className="font-semibold text-sm tracking-tight">SERENO</span>
        </div>

        {/* Driver status */}
        <div className="flex items-center gap-2 text-xs">
          <div
            className={`status-dot ${
              driverStatus === "running"
                ? "status-dot-success"
                : driverStatus === "stopped"
                ? "status-dot-danger"
                : "status-dot-warning"
            }`}
          />
          <span className="text-sereno-muted">
            {driverStatus === "running" ? "Protected" : "Not Protected"}
          </span>
        </div>
      </div>

      {/* Right: Bandwidth stats */}
      <div className="flex items-center gap-4 text-xs font-mono">
        <div className="flex items-center gap-1.5 text-sereno-success">
          <ChevronUp className="w-3.5 h-3.5" />
          <span>{formatBytes(bandwidth.up)}</span>
        </div>
        <div className="flex items-center gap-1.5 text-sereno-accent">
          <ChevronDown className="w-3.5 h-3.5" />
          <span>{formatBytes(bandwidth.down)}</span>
        </div>
        <div className="text-sereno-muted">
          {bandwidth.flows} flows
        </div>
      </div>
    </header>
  );
}
