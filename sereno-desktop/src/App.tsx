import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Activity, List, Settings } from "lucide-react";
import ConnectionList from "./components/ConnectionList";
import Sidebar from "./components/Sidebar";
import Header from "./components/Header";

export type Tab = "connections" | "rules" | "logs" | "settings";

function App() {
  const [activeTab, setActiveTab] = useState<Tab>("connections");
  const [driverStatus, setDriverStatus] = useState<"running" | "stopped" | "unknown">("unknown");
  const [bandwidth, setBandwidth] = useState({ up: 0, down: 0, flows: 0 });

  useEffect(() => {
    // Initial driver status check
    checkDriverStatus();

    // Poll for updates
    const interval = setInterval(() => {
      checkDriverStatus();
      fetchBandwidth();
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  async function checkDriverStatus() {
    try {
      const status = await invoke<string>("get_driver_status");
      setDriverStatus(status === "running" ? "running" : "stopped");
    } catch {
      setDriverStatus("unknown");
    }
  }

  async function fetchBandwidth() {
    try {
      const bw = await invoke<{ up: number; down: number; flows: number }>("get_bandwidth");
      setBandwidth(bw);
    } catch {
      // Silently fail
    }
  }

  return (
    <div className="h-screen flex flex-col bg-sereno-bg overflow-hidden no-select">
      {/* Header */}
      <Header
        driverStatus={driverStatus}
        bandwidth={bandwidth}
      />

      {/* Main content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Sidebar */}
        <Sidebar activeTab={activeTab} onTabChange={setActiveTab} />

        {/* Content area */}
        <main className="flex-1 overflow-hidden">
          {activeTab === "connections" && <ConnectionList />}
          {activeTab === "rules" && <RulesPlaceholder />}
          {activeTab === "logs" && <LogsPlaceholder />}
          {activeTab === "settings" && <SettingsPlaceholder />}
        </main>
      </div>
    </div>
  );
}

// Placeholder components - will be implemented in Phase 3.2+
function RulesPlaceholder() {
  return (
    <div className="h-full flex items-center justify-center text-sereno-muted">
      <div className="text-center">
        <List className="w-12 h-12 mx-auto mb-4 opacity-50" />
        <p>Rules management coming soon</p>
      </div>
    </div>
  );
}

function LogsPlaceholder() {
  return (
    <div className="h-full flex items-center justify-center text-sereno-muted">
      <div className="text-center">
        <Activity className="w-12 h-12 mx-auto mb-4 opacity-50" />
        <p>Connection logs coming soon</p>
      </div>
    </div>
  );
}

function SettingsPlaceholder() {
  return (
    <div className="h-full flex items-center justify-center text-sereno-muted">
      <div className="text-center">
        <Settings className="w-12 h-12 mx-auto mb-4 opacity-50" />
        <p>Settings coming soon</p>
      </div>
    </div>
  );
}

export default App;
