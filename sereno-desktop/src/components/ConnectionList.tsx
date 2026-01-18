import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Search,
  ArrowRight,
  ArrowLeft,
  Shield,
  ShieldOff,
  ShieldQuestion,
  Layers,
} from "lucide-react";
import type { Connection } from "../types/connection";

export default function ConnectionList() {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [isGrouped, setIsGrouped] = useState(false);
  const [filters, setFilters] = useState({
    hideLocalhost: true,
    hideSystem: true,
    hideInactive: false,
  });

  useEffect(() => {
    fetchConnections();
    const interval = setInterval(fetchConnections, 1000);
    return () => clearInterval(interval);
  }, []);

  async function fetchConnections() {
    try {
      const conns = await invoke<Connection[]>("get_connections");
      setConnections(conns);
    } catch (e) {
      console.error("Failed to fetch connections:", e);
    }
  }

  const filteredConnections = connections.filter((conn) => {
    if (filters.hideLocalhost && isLocalhost(conn.remoteAddress)) return false;
    if (filters.hideSystem && isSystemProcess(conn.processName, conn.processId)) return false;
    if (filters.hideInactive && !conn.isActive) return false;
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      return (
        conn.processName.toLowerCase().includes(query) ||
        conn.destination.toLowerCase().includes(query) ||
        conn.remoteAddress.includes(query)
      );
    }
    return true;
  });

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="h-12 border-b border-sereno-border flex items-center px-4 gap-4">
        {/* Search */}
        <div className="relative flex-1 max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-sereno-muted" />
          <input
            type="text"
            placeholder="Search connections..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="input w-full pl-9 py-1.5 text-sm"
          />
        </div>

        {/* Filter toggles */}
        <div className="flex items-center gap-2">
          <FilterToggle
            label="Localhost"
            active={filters.hideLocalhost}
            onClick={() => setFilters((f) => ({ ...f, hideLocalhost: !f.hideLocalhost }))}
          />
          <FilterToggle
            label="System"
            active={filters.hideSystem}
            onClick={() => setFilters((f) => ({ ...f, hideSystem: !f.hideSystem }))}
          />
          <FilterToggle
            label="Inactive"
            active={filters.hideInactive}
            onClick={() => setFilters((f) => ({ ...f, hideInactive: !f.hideInactive }))}
          />
        </div>

        {/* Group toggle */}
        <button
          onClick={() => setIsGrouped(!isGrouped)}
          className={`btn-secondary flex items-center gap-1.5 ${isGrouped ? "bg-sereno-hover" : ""}`}
        >
          <Layers className="w-4 h-4" />
          <span>Group</span>
        </button>

        {/* Count */}
        <span className="text-xs text-sereno-muted ml-auto">
          {filteredConnections.length} connections
        </span>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-sereno-surface border-b border-sereno-border">
            <tr className="text-left text-xs text-sereno-muted font-medium">
              <th className="px-4 py-2 w-20">Time</th>
              <th className="px-4 py-2 w-16">Status</th>
              <th className="px-4 py-2 w-8">Dir</th>
              <th className="px-4 py-2 w-12">Sig</th>
              <th className="px-4 py-2">Process</th>
              <th className="px-4 py-2">Destination</th>
              <th className="px-4 py-2 w-24">Port</th>
              <th className="px-4 py-2 w-20 text-right">Sent</th>
              <th className="px-4 py-2 w-20 text-right">Recv</th>
            </tr>
          </thead>
          <tbody>
            {filteredConnections.map((conn, i) => (
              <ConnectionRow
                key={conn.id}
                connection={conn}
                isSelected={i === selectedIndex}
                onClick={() => setSelectedIndex(i)}
              />
            ))}
            {filteredConnections.length === 0 && (
              <tr>
                <td colSpan={9} className="px-4 py-12 text-center text-sereno-muted">
                  No connections to display
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

interface ConnectionRowProps {
  connection: Connection;
  isSelected: boolean;
  onClick: () => void;
}

function ConnectionRow({ connection: conn, isSelected, onClick }: ConnectionRowProps) {
  const statusColor = {
    allow: "text-sereno-success",
    deny: "text-sereno-danger",
    ask: "text-sereno-warning",
    auto: "text-sereno-accent",
  }[conn.authStatus];

  const StatusIcon = {
    allow: Shield,
    deny: ShieldOff,
    ask: ShieldQuestion,
    auto: Shield,
  }[conn.authStatus];

  return (
    <tr
      onClick={onClick}
      className={`border-b border-sereno-border/50 cursor-pointer transition-colors ${
        isSelected
          ? "bg-sereno-accent/10"
          : conn.isActive
          ? "hover:bg-sereno-hover/50"
          : "opacity-50 hover:bg-sereno-hover/30"
      }`}
    >
      <td className="px-4 py-2 font-mono text-xs text-sereno-muted">{conn.time}</td>
      <td className={`px-4 py-2 ${statusColor}`}>
        <div className="flex items-center gap-1.5">
          <StatusIcon className="w-3.5 h-3.5" />
          <span className="text-xs font-medium uppercase">{conn.authStatus}</span>
        </div>
      </td>
      <td className="px-4 py-2">
        {conn.direction === "outbound" ? (
          <ArrowRight className="w-4 h-4 text-sereno-muted" />
        ) : (
          <ArrowLeft className="w-4 h-4 text-sereno-accent" />
        )}
      </td>
      <td className="px-4 py-2">
        <SignatureBadge status={conn.signatureStatus} />
      </td>
      <td className="px-4 py-2">
        <span className="font-medium">{conn.processName}</span>
        <span className="text-sereno-muted">[{conn.processId}]</span>
      </td>
      <td className="px-4 py-2 text-sereno-muted truncate max-w-xs">{conn.destination}</td>
      <td className="px-4 py-2 font-mono text-xs">
        {conn.remotePort}:{conn.protocol.toUpperCase()}
      </td>
      <td className="px-4 py-2 text-right font-mono text-xs text-sereno-success">
        {formatBytes(conn.bytesSent)}
      </td>
      <td className="px-4 py-2 text-right font-mono text-xs text-sereno-accent">
        {formatBytes(conn.bytesReceived)}
      </td>
    </tr>
  );
}

function SignatureBadge({ status }: { status: string }) {
  if (status === "signed") {
    return <span className="text-xs px-1.5 py-0.5 rounded bg-sereno-success/10 text-sereno-success">OK</span>;
  }
  if (status === "unsigned") {
    return <span className="text-xs px-1.5 py-0.5 rounded bg-sereno-danger/10 text-sereno-danger">!!</span>;
  }
  if (status === "system") {
    return <span className="text-xs px-1.5 py-0.5 rounded bg-sereno-accent/10 text-sereno-accent">SYS</span>;
  }
  return <span className="text-xs px-1.5 py-0.5 rounded bg-sereno-border text-sereno-muted">?</span>;
}

function FilterToggle({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`text-xs px-2 py-1 rounded transition-colors ${
        active
          ? "bg-sereno-accent/20 text-sereno-accent"
          : "bg-sereno-surface text-sereno-muted hover:text-sereno-text"
      }`}
    >
      {active ? `Hide ${label}` : label}
    </button>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return "0B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + sizes[i];
}

function isLocalhost(ip: string): boolean {
  return ip.startsWith("127.") || ip === "::1";
}

function isSystemProcess(name: string, pid: number): boolean {
  const lname = name.toLowerCase();
  return pid === 0 || pid === 4 || lname === "system" || lname.startsWith("svchost");
}
