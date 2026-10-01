/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import {
  Shield,
  AlertTriangle,
  Terminal,
  Activity,
  Server,
  Lock,
  Unlock,
  FileText,
  Play,
  Search,
  Cpu,
  CheckCircle2,
  XCircle,
  Clock,
  UserCheck,
  Zap,
  Download,
  RefreshCw,
  Eye,
  HelpCircle,
  ChevronRight,
  Radio,
  Sliders,
  Filter,
  ArrowUpRight,
  ShieldAlert,
  TerminalSquare
} from 'lucide-react';

interface Alert {
  alert_id: string;
  timestamp: string;
  rule_id: string;
  rule_name: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  risk_score: number;
  source_host: string;
  source_ip: string;
  target_account: string;
  mitre_technique: string;
  mitre_tactic: string;
  evidence_raw: string;
  status: 'Unassigned' | 'Investigating' | 'Resolved' | 'False Positive';
}

interface Incident {
  incident_id: string;
  title: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  status: 'Investigating' | 'Mitigated' | 'Closed';
  risk_score: number;
  affected_asset: string;
  associated_alert_ids: string[];
  mitre_mappings: string[];
  assigned_analyst: string;
  notes: string;
  response_action_taken: string;
  created_at: string;
}

interface EndpointAsset {
  host_id: string;
  hostname: string;
  ip_address: string;
  os: string;
  status: 'Online' | 'Offline' | 'Isolated';
  wazuh_agent_version: string;
  sysmon_status: 'Active' | 'Degraded' | 'Inactive';
  last_heartbeat: string;
}

interface AuditLog {
  audit_id: string;
  timestamp: string;
  analyst_id: string;
  action_type: string;
  target: string;
  details: string;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'alerts' | 'incidents' | 'investigation' | 'endpoints' | 'simulator' | 'reports'>('dashboard');
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointAsset[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('');
  const [selectedAlertForModal, setSelectedAlertForModal] = useState<Alert | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  
  // Simulation loading state
  const [simulating, setSimulating] = useState<boolean>(false);
  const [simulationMessage, setSimulationMessage] = useState<string>('');

  const fetchData = async () => {
    try {
      const res = await fetch('/api/data');
      const data = await res.json();
      setAlerts(data.alerts || []);
      setIncidents(data.incidents || []);
      setEndpoints(data.endpoints || []);
      setAuditLogs(data.auditLogs || []);
      if (data.incidents && data.incidents.length > 0 && !selectedIncidentId) {
        setSelectedIncidentId(data.incidents[0].incident_id);
      }
      setLoading(false);
    } catch (err) {
      console.error('Failed to fetch SOC data:', err);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  const triggerSimulation = async (scenario: string) => {
    setSimulating(true);
    setSimulationMessage(`Executing scenario [${scenario}] through Wazuh ingestion pipeline...`);
    try {
      const res = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      const data = await res.json();
      if (data.success) {
        setSimulationMessage(`Simulation successful. Telemetry ingested & correlated.`);
        await fetchData();
      }
    } catch (err) {
      setSimulationMessage(`Simulation error: ${err}`);
    } finally {
      setTimeout(() => setSimulating(false), 2000);
    }
  };

  const isolateEndpoint = async (hostId: string) => {
    try {
      const res = await fetch('/api/response/isolate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host_id: hostId, analyst_id: 'Analyst_1' })
      });
      const data = await res.json();
      if (data.success) {
        await fetchData();
        alert(data.message);
      }
    } catch (err) {
      alert(`Error isolating endpoint: ${err}`);
    }
  };

  const disableAccount = async (username: string) => {
    try {
      const res = await fetch('/api/response/disable-account', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, analyst_id: 'Analyst_1' })
      });
      const data = await res.json();
      if (data.success) {
        await fetchData();
        alert(data.message);
      }
    } catch (err) {
      alert(`Error disabling account: ${err}`);
    }
  };

  const decodeBase64Evidence = (evidence: string) => {
    try {
      const match = evidence.match(/-enc\s+([A-Za-z0-9+/=]+)/);
      if (match && match[1]) {
        const decoded = atob(match[1]);
        return `Decoded PowerShell Command: ${decoded}`;
      }
      return 'No base64 encoded payload pattern found.';
    } catch (e) {
      return 'Failed to decode base64 string.';
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-[#090D16] text-slate-200 flex items-center justify-center font-mono text-xs tracking-wider">
        <div className="flex items-center gap-3">
          <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />
          <span>CONNECTING TO SOC-X SIEM ENGINE...</span>
        </div>
      </div>
    );
  }

  const criticalIncidentsCount = incidents.filter(i => i.severity === 'Critical').length;
  const selectedIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0];

  return (
    <div className="min-h-screen bg-[#090D16] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Header */}
      <header className="h-14 border-b border-slate-800/80 bg-[#0B101D] px-6 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Shield className="w-4 h-4" />
            </div>
            <span className="text-sm font-bold tracking-tight text-white font-mono">SOC-X</span>
          </div>
          <span className="text-slate-700">/</span>
          <span className="text-xs text-slate-400 font-mono">Enterprise Security Operations Center</span>
        </div>

        {/* Navigation Tabs */}
        <nav className="hidden xl:flex items-center gap-1 bg-[#070A12] p-1 rounded border border-slate-800/80 text-xs">
          {[
            { id: 'dashboard', label: 'Dashboard' },
            { id: 'alerts', label: 'Alerts & Telemetry' },
            { id: 'incidents', label: 'Incidents & Correlation' },
            { id: 'investigation', label: 'Investigation Workspace' },
            { id: 'endpoints', label: 'Endpoints & Assets' },
            { id: 'simulator', label: 'Threat Lab' },
            { id: 'reports', label: 'Reports' }
          ].map((tab) => {
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`px-3 py-1.5 font-medium transition-colors rounded ${
                  active
                    ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {tab.label}
              </button>
            );
          })}
        </nav>

        {/* Status & Analyst */}
        <div className="flex items-center gap-4 text-xs">
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-mono rounded">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>Cluster Nominal</span>
          </div>
          <div className="flex items-center gap-2 pl-3 border-l border-slate-800 text-slate-300 font-mono">
            <span className="text-cyan-400">#A1</span>
            <span>Analyst_1</span>
          </div>
        </div>
      </header>

      {/* Mobile Subheader Navigation */}
      <div className="flex xl:hidden overflow-x-auto bg-[#0B101D] border-b border-slate-800/80 px-4 py-2 gap-2">
        {[
          { id: 'dashboard', label: 'Dashboard' },
          { id: 'alerts', label: 'Alerts' },
          { id: 'incidents', label: 'Incidents' },
          { id: 'investigation', label: 'Workspace' },
          { id: 'endpoints', label: 'Endpoints' },
          { id: 'simulator', label: 'Threat Lab' },
          { id: 'reports', label: 'Reports' }
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id as any)}
            className={`px-3 py-1 rounded text-xs whitespace-nowrap font-medium font-mono ${
              activeTab === t.id ? 'bg-cyan-500 text-slate-950 font-bold' : 'bg-slate-900 text-slate-400 border border-slate-800'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Main Viewport */}
      <main className="flex-1 p-6 max-w-[1500px] w-full mx-auto space-y-6">
        {/* -------------------- DASHBOARD VIEW -------------------- */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* Metric Row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-4">
                <div className="text-xs font-mono text-slate-400 uppercase tracking-wider">Critical Incidents</div>
                <div className="mt-2 flex items-baseline justify-between">
                  <span className="text-2xl font-bold font-mono text-white tabular-nums">{criticalIncidentsCount}</span>
                  <span className="text-xs font-mono text-red-400 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Action Req.</span>
                </div>
              </div>

              <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-4">
                <div className="text-xs font-mono text-slate-400 uppercase tracking-wider">High Severity Alerts</div>
                <div className="mt-2 flex items-baseline justify-between">
                  <span className="text-2xl font-bold font-mono text-white tabular-nums">{alerts.filter(a => a.severity === 'High').length}</span>
                  <span className="text-xs font-mono text-amber-400">Past 24h</span>
                </div>
              </div>

              <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-4">
                <div className="text-xs font-mono text-slate-400 uppercase tracking-wider">Monitored Endpoints</div>
                <div className="mt-2 flex items-baseline justify-between">
                  <span className="text-2xl font-bold font-mono text-white tabular-nums">{endpoints.length}</span>
                  <span className="text-xs font-mono text-emerald-400">{endpoints.filter(e => e.status === 'Online').length} Online</span>
                </div>
              </div>

              <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-4">
                <div className="text-xs font-mono text-slate-400 uppercase tracking-wider">Telemetry Ingestion</div>
                <div className="mt-2 flex items-baseline justify-between">
                  <span className="text-2xl font-bold font-mono text-white tabular-nums">1.4k</span>
                  <span className="text-xs font-mono text-emerald-400">Events/min</span>
                </div>
              </div>
            </div>

            {/* Quick Threat Simulation Bar */}
            <div className="bg-[#0B101D] border border-cyan-500/30 rounded-lg p-4 flex flex-col lg:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
                  <Zap className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-white font-mono uppercase tracking-wider">Attack Simulation & Verification Lab</h3>
                  <p className="text-xs text-slate-400">Simulate real adversary behaviors (Brute force, encoded PowerShell, persistence tasks) to test Wazuh detection rules.</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  disabled={simulating}
                  onClick={() => triggerSimulation('brute-force')}
                  className="px-3 py-1.5 bg-[#070A12] hover:bg-slate-800 text-xs font-mono text-cyan-300 rounded border border-slate-800 transition-colors"
                >
                  Brute Force (T1110)
                </button>
                <button
                  disabled={simulating}
                  onClick={() => triggerSimulation('powershell')}
                  className="px-3 py-1.5 bg-[#070A12] hover:bg-slate-800 text-xs font-mono text-cyan-300 rounded border border-slate-800 transition-colors"
                >
                  PowerShell (T1059.001)
                </button>
                <button
                  disabled={simulating}
                  onClick={() => triggerSimulation('correlated')}
                  className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-xs font-mono text-slate-950 font-bold rounded transition-colors"
                >
                  Run Multi-Stage Chain
                </button>
              </div>
            </div>

            {simulationMessage && (
              <div className="bg-cyan-950/40 border border-cyan-500/30 p-3 rounded text-xs font-mono text-cyan-200 flex items-center gap-2">
                <RefreshCw className="w-4 h-4 animate-spin shrink-0 text-cyan-400" />
                <span>{simulationMessage}</span>
              </div>
            )}

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left 2 Cols: Active Incidents */}
              <div className="lg:col-span-2 space-y-6">
                <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5">
                  <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800/80">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono flex items-center gap-2">
                      <Shield className="w-4 h-4 text-cyan-400" /> Active Correlated Incidents
                    </h3>
                    <button onClick={() => setActiveTab('incidents')} className="text-xs text-cyan-400 hover:underline font-mono">View All ({incidents.length})</button>
                  </div>
                  <div className="space-y-3">
                    {incidents.slice(0, 3).map(inc => (
                      <div key={inc.incident_id} className="bg-[#070A12] border border-slate-800/80 rounded p-4 hover:border-slate-700 transition-colors">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                              inc.severity === 'Critical' ? 'bg-red-500/15 text-red-400 border border-red-500/30' :
                              inc.severity === 'High' ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' : 'bg-blue-500/15 text-blue-400'
                            }`}>
                              {inc.severity}
                            </span>
                            <span className="text-xs font-mono text-slate-400">{inc.incident_id}</span>
                            <span className="text-xs font-mono text-cyan-400 font-semibold">{inc.affected_asset}</span>
                          </div>
                          <span className="text-xs font-mono text-slate-400">Risk: <strong className="text-white">{inc.risk_score}/100</strong></span>
                        </div>
                        <h4 className="text-sm font-semibold text-white mt-2">{inc.title}</h4>
                        <p className="text-xs text-slate-400 mt-1 line-clamp-1">{inc.notes}</p>
                        <div className="mt-3 flex items-center justify-between pt-3 border-t border-slate-900 text-xs font-mono">
                          <span className="text-slate-400">Analyst: <strong className="text-slate-200">{inc.assigned_analyst}</strong></span>
                          <button
                            onClick={() => { setSelectedIncidentId(inc.incident_id); setActiveTab('investigation'); }}
                            className="text-cyan-400 hover:underline flex items-center gap-1"
                          >
                            <span>Investigate Workspace</span>
                            <ChevronRight className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Monitored Endpoints Grid */}
                <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5">
                  <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800/80">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono flex items-center gap-2">
                      <Server className="w-4 h-4 text-cyan-400" /> Monitored Endpoint Fleet
                    </h3>
                    <button onClick={() => setActiveTab('endpoints')} className="text-xs text-cyan-400 hover:underline font-mono">Manage Fleet</button>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {endpoints.map(ep => (
                      <div key={ep.host_id} className="bg-[#070A12] border border-slate-800/80 rounded p-3 font-mono">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-white">{ep.hostname}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] ${
                            ep.status === 'Isolated' ? 'bg-red-500/15 text-red-400' :
                            ep.status === 'Online' ? 'bg-emerald-500/15 text-emerald-400' : 'bg-slate-800 text-slate-400'
                          }`}>
                            {ep.status}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">{ep.ip_address}</p>
                        <div className="mt-2 pt-2 border-t border-slate-900 flex items-center justify-between text-[10px] text-slate-400">
                          <span>Wazuh v{ep.wazuh_agent_version}</span>
                          {ep.status !== 'Isolated' ? (
                            <button onClick={() => isolateEndpoint(ep.hostname)} className="text-red-400 hover:underline">Isolate</button>
                          ) : (
                            <span className="text-red-400 font-bold">Isolated</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Right Col: Live Ingested Alert Stream */}
              <div className="space-y-6">
                <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 flex flex-col h-full">
                  <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800/80">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono flex items-center gap-2">
                      <Radio className="w-4 h-4 text-cyan-400 animate-pulse" /> Live Telemetry Feed
                    </h3>
                    <span className="text-xs font-mono text-slate-400">{alerts.length} events</span>
                  </div>

                  <div className="space-y-2.5 overflow-y-auto max-h-[500px] pr-1">
                    {alerts.map(alert => (
                      <div
                        key={alert.alert_id}
                        onClick={() => setSelectedAlertForModal(alert)}
                        className="bg-[#070A12] border border-slate-800/80 rounded p-3 hover:border-cyan-500/40 transition-colors cursor-pointer group font-mono"
                      >
                        <div className="flex items-center justify-between">
                          <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                            alert.severity === 'Critical' ? 'bg-red-500/15 text-red-400' :
                            alert.severity === 'High' ? 'bg-amber-500/15 text-amber-400' : 'bg-blue-500/15 text-blue-400'
                          }`}>
                            {alert.severity}
                          </span>
                          <span className="text-[10px] text-slate-500">
                            {new Date(alert.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <h4 className="text-xs font-semibold text-white mt-1.5 group-hover:text-cyan-300 transition-colors">{alert.rule_name}</h4>
                        <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                          <span className="text-cyan-400">{alert.source_host}</span>
                          <span>{alert.mitre_technique}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* -------------------- ALERTS & TELEMETRY VIEW -------------------- */}
        {activeTab === 'alerts' && (
          <div className="space-y-6">
            <div className="flex flex-col md:flex-row items-center justify-between gap-4 bg-[#0B101D] border border-slate-800/80 p-4 rounded-lg">
              <div>
                <h2 className="text-base font-bold text-white font-mono">Alerts & Sysmon Telemetry Ingestion</h2>
                <p className="text-xs text-slate-400">Real-time log ingestion from Windows Event Logs, Sysmon, and Wazuh security rules.</p>
              </div>
              <div className="flex items-center gap-3 w-full md:w-auto">
                <div className="relative flex-1 md:w-64">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-3" />
                  <input
                    type="text"
                    placeholder="Search host, rule, MITRE..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full bg-[#070A12] border border-slate-800 rounded px-3 py-2 text-xs text-white pl-9 font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="bg-[#070A12] border border-slate-800 rounded px-3 py-2 text-xs text-white font-mono"
                >
                  <option value="All">All Severities</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>
            </div>

            <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-[#070A12] text-slate-400 uppercase tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="p-3">Alert ID</th>
                      <th className="p-3">Timestamp</th>
                      <th className="p-3">Rule Name / ID</th>
                      <th className="p-3">Severity</th>
                      <th className="p-3">Source Host</th>
                      <th className="p-3">MITRE</th>
                      <th className="p-3">Status</th>
                      <th className="p-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {alerts
                      .filter(a => severityFilter === 'All' || a.severity === severityFilter)
                      .filter(a => searchQuery === '' || a.source_host.toLowerCase().includes(searchQuery.toLowerCase()) || a.rule_name.toLowerCase().includes(searchQuery.toLowerCase()) || a.mitre_technique.toLowerCase().includes(searchQuery.toLowerCase()))
                      .map(alert => (
                        <tr key={alert.alert_id} className="hover:bg-slate-900/60 transition-colors">
                          <td className="p-3 text-cyan-400 font-semibold">{alert.alert_id}</td>
                          <td className="p-3 text-slate-400">{new Date(alert.timestamp).toLocaleTimeString()}</td>
                          <td className="p-3">
                            <div className="font-semibold text-white">{alert.rule_name}</div>
                            <div className="text-[10px] text-slate-400">{alert.rule_id}</div>
                          </td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded text-[10px] ${
                              alert.severity === 'Critical' ? 'bg-red-500/15 text-red-400' :
                              alert.severity === 'High' ? 'bg-amber-500/15 text-amber-400' : 'bg-blue-500/15 text-blue-400'
                            }`}>
                              {alert.severity}
                            </span>
                          </td>
                          <td className="p-3 text-slate-300">{alert.source_host} ({alert.source_ip})</td>
                          <td className="p-3 text-indigo-300">{alert.mitre_technique}</td>
                          <td className="p-3 text-slate-400">{alert.status}</td>
                          <td className="p-3 text-right">
                            <button
                              onClick={() => setSelectedAlertForModal(alert)}
                              className="px-2.5 py-1 bg-[#070A12] hover:bg-slate-800 text-cyan-300 rounded border border-slate-800 transition-colors"
                            >
                              Inspect Log
                            </button>
                          </td>
                        </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* -------------------- INCIDENTS & CORRELATION VIEW -------------------- */}
        {activeTab === 'incidents' && (
          <div className="space-y-6">
            <div className="bg-[#0B101D] border border-slate-800/80 p-4 rounded-lg flex items-center justify-between font-mono">
              <div>
                <h2 className="text-base font-bold text-white">Incident Correlation & Risk Scoring</h2>
                <p className="text-xs text-slate-400">Automatic multi-alert correlation engine grouped by host asset and 15-minute time window.</p>
              </div>
              <span className="text-xs bg-[#070A12] px-3 py-1.5 rounded border border-slate-800 text-slate-300">
                Total Incidents: <strong className="text-white">{incidents.length}</strong>
              </span>
            </div>

            <div className="space-y-4">
              {incidents.map(inc => (
                <div key={inc.incident_id} className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 font-mono">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          inc.severity === 'Critical' ? 'bg-red-500/15 text-red-400 border border-red-500/30' :
                          inc.severity === 'High' ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' : 'bg-blue-500/15 text-blue-400'
                        }`}>
                          {inc.severity}
                        </span>
                        <span className="text-xs text-cyan-400 font-bold">{inc.incident_id}</span>
                        <span className="text-xs text-slate-400">Asset: <strong className="text-white">{inc.affected_asset}</strong></span>
                      </div>
                      <h3 className="text-base font-bold text-white font-sans">{inc.title}</h3>
                      <p className="text-xs text-slate-400 font-sans">{inc.notes}</p>
                    </div>

                    <div className="flex items-center gap-4 shrink-0">
                      <div className="text-right">
                        <div className="text-xs text-slate-400">Risk Score</div>
                        <div className="text-2xl font-bold text-cyan-400 tabular-nums">{inc.risk_score}/100</div>
                      </div>
                      <button
                        onClick={() => { setSelectedIncidentId(inc.incident_id); setActiveTab('investigation'); }}
                        className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded transition-colors flex items-center gap-1.5"
                      >
                        <span>Workspace</span>
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  <div className="mt-4 pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between text-xs text-slate-400 gap-2">
                    <div className="flex items-center gap-4">
                      <span>Analyst: <strong className="text-white">{inc.assigned_analyst}</strong></span>
                      <span>Alerts: <strong className="text-cyan-400">{inc.associated_alert_ids.join(', ')}</strong></span>
                      <span>MITRE: <strong className="text-indigo-300">{inc.mitre_mappings.join(', ')}</strong></span>
                    </div>
                    <div>
                      <span>Status: <strong className="text-amber-400">{inc.status}</strong></span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* -------------------- INVESTIGATION WORKSPACE VIEW -------------------- */}
        {activeTab === 'investigation' && (
          <div className="space-y-6">
            <div className="bg-[#0B101D] border border-slate-800/80 p-4 rounded-lg flex flex-col md:flex-row items-center justify-between gap-4 font-mono">
              <div>
                <h2 className="text-base font-bold text-white">Investigation Workspace</h2>
                <p className="text-xs text-slate-400">Chronological timeline analysis, raw log forensics, and active response execution.</p>
              </div>
              <div className="flex items-center gap-2">
                <label className="text-xs text-slate-400">Incident:</label>
                <select
                  value={selectedIncidentId}
                  onChange={(e) => setSelectedIncidentId(e.target.value)}
                  className="bg-[#070A12] border border-slate-800 rounded px-3 py-1.5 text-xs text-white font-mono"
                >
                  {incidents.map(i => (
                    <option key={i.incident_id} value={i.incident_id}>{i.incident_id} - {i.title}</option>
                  ))}
                </select>
              </div>
            </div>

            {selectedIncident && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono">
                {/* Left 2 Cols: Incident Details & Timeline */}
                <div className="lg:col-span-2 space-y-6">
                  <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xs bg-cyan-500/10 text-cyan-400 px-2 py-0.5 rounded border border-cyan-500/20">{selectedIncident.incident_id}</span>
                        <span className="text-xs text-slate-400">Host: <strong className="text-white">{selectedIncident.affected_asset}</strong></span>
                      </div>
                      <span className="text-xs text-amber-400">Risk Score: {selectedIncident.risk_score}/100</span>
                    </div>
                    <h3 className="text-base font-bold text-white font-sans">{selectedIncident.title}</h3>
                    <p className="text-xs text-slate-300 bg-[#070A12] p-3 rounded border border-slate-800">{selectedIncident.notes}</p>

                    <div className="pt-4 border-t border-slate-800/80">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-4 flex items-center gap-2">
                        <Clock className="w-4 h-4 text-cyan-400" /> Chronological Timeline & Attack Chain
                      </h4>
                      <div className="space-y-3">
                        {alerts
                          .filter(a => selectedIncident.associated_alert_ids.includes(a.alert_id) || a.source_host === selectedIncident.affected_asset)
                          .slice(0, 5)
                          .map((alert) => (
                            <div key={alert.alert_id} className="relative pl-6 pb-4 border-l border-cyan-500/30 last:border-0 last:pb-0">
                              <div className="absolute -left-1.5 top-0 w-3 h-3 rounded-full bg-cyan-500 border-2 border-[#090D16]"></div>
                              <div className="bg-[#070A12] border border-slate-800 rounded p-3">
                                <div className="flex items-center justify-between text-xs">
                                  <span className="text-cyan-400 font-bold">{alert.rule_name}</span>
                                  <span className="text-slate-500">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                                </div>
                                <p className="text-xs text-slate-300 mt-1">{alert.evidence_raw}</p>
                                <div className="mt-2 flex items-center gap-2 text-[10px]">
                                  <span className="bg-indigo-500/20 text-indigo-300 px-1.5 py-0.5 rounded">{alert.mitre_technique}</span>
                                  <span className="bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded">{alert.mitre_tactic}</span>
                                </div>
                              </div>
                            </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Right Col: Automated Active Response Playbooks */}
                <div className="space-y-6">
                  <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 space-y-4">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
                      <Zap className="w-4 h-4 text-amber-400" /> Active Response Playbooks
                    </h3>
                    <p className="text-xs text-slate-400">Execute automated containment scripts on the target host.</p>

                    <div className="space-y-3 pt-2">
                      <div className="bg-[#070A12] p-4 rounded border border-slate-800 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-white">Endpoint Isolation</span>
                          <span className="text-[10px] text-red-400">High Impact</span>
                        </div>
                        <p className="text-[11px] text-slate-400">Isolate {selectedIncident.affected_asset} from network, blocking all non-SOC traffic.</p>
                        <button
                          onClick={() => isolateEndpoint(selectedIncident.affected_asset)}
                          className="w-full mt-2 py-2 bg-red-600 hover:bg-red-500 text-white font-bold text-xs rounded transition-colors flex items-center justify-center gap-1.5"
                        >
                          <Lock className="w-3.5 h-3.5" />
                          <span>Isolate Host Now</span>
                        </button>
                      </div>

                      <div className="bg-[#070A12] p-4 rounded border border-slate-800 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-white">Disable Compromised Account</span>
                          <span className="text-[10px] text-amber-400">Targeted</span>
                        </div>
                        <p className="text-[11px] text-slate-400">Trigger API command `net user admin_test /active:no`.</p>
                        <button
                          onClick={() => disableAccount('admin_test')}
                          className="w-full mt-2 py-2 bg-amber-600 hover:bg-amber-500 text-slate-950 font-bold text-xs rounded transition-colors flex items-center justify-center gap-1.5"
                        >
                          <UserCheck className="w-3.5 h-3.5" />
                          <span>Disable Account (admin_test)</span>
                        </button>
                      </div>
                    </div>
                  </div>

                  {/* Audit Trail */}
                  <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
                      <FileText className="w-4 h-4 text-cyan-400" /> Audit Trail
                    </h3>
                    <div className="space-y-2 max-h-48 overflow-y-auto">
                      {auditLogs.map(audit => (
                        <div key={audit.audit_id} className="bg-[#070A12] p-2.5 rounded border border-slate-800 text-[11px]">
                          <div className="flex items-center justify-between text-slate-500">
                            <span className="text-cyan-400">{audit.analyst_id}</span>
                            <span>{new Date(audit.timestamp).toLocaleTimeString()}</span>
                          </div>
                          <p className="text-slate-300 mt-1">{audit.details}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* -------------------- ENDPOINTS & ASSETS VIEW -------------------- */}
        {activeTab === 'endpoints' && (
          <div className="space-y-6 font-mono">
            <div className="bg-[#0B101D] border border-slate-800/80 p-4 rounded-lg flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white">Monitored Endpoints & Sysmon Fleet</h2>
                <p className="text-xs text-slate-400 font-sans">Manage Wazuh agents, host isolation state, and telemetry health across Windows endpoints.</p>
              </div>
              <span className="text-xs bg-[#070A12] px-3 py-1.5 rounded border border-slate-800 text-emerald-400">
                {endpoints.filter(e => e.status === 'Online').length} / {endpoints.length} Active Agents
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {endpoints.map(ep => (
                <div key={ep.host_id} className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-bold text-white">{ep.hostname}</span>
                    <span className={`px-2.5 py-0.5 rounded text-xs ${
                      ep.status === 'Isolated' ? 'bg-red-500/15 text-red-400 border border-red-500/30' :
                      ep.status === 'Online' ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' : 'bg-slate-800 text-slate-400'
                    }`}>
                      {ep.status}
                    </span>
                  </div>

                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between text-slate-400">
                      <span>IP Address:</span>
                      <span className="text-white">{ep.ip_address}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>OS:</span>
                      <span className="text-white truncate max-w-[180px]">{ep.os}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Wazuh Agent:</span>
                      <span className="text-cyan-400">v{ep.wazuh_agent_version}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Sysmon Status:</span>
                      <span className="text-emerald-400">{ep.sysmon_status}</span>
                    </div>
                  </div>

                  <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                    <span className="text-[10px] text-slate-500">Heartbeat: Nominal</span>
                    {ep.status !== 'Isolated' ? (
                      <button
                        onClick={() => isolateEndpoint(ep.hostname)}
                        className="px-3 py-1 bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 rounded text-xs transition-colors flex items-center gap-1"
                      >
                        <Lock className="w-3.5 h-3.5" />
                        <span>Isolate Host</span>
                      </button>
                    ) : (
                      <span className="text-xs text-red-400 font-bold">Network Isolated</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* -------------------- THREAT SIMULATION LAB VIEW -------------------- */}
        {activeTab === 'simulator' && (
          <div className="space-y-6 font-mono">
            <div className="bg-[#0B101D] border border-slate-800/80 p-4 rounded-lg">
              <h2 className="text-base font-bold text-white">Threat Simulation & Evaluation Lab</h2>
              <p className="text-xs text-slate-400 font-sans">Execute the 5 mandatory MVP attack scenarios and verify SIEM detection and correlation rule output.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {[
                {
                  id: 'brute-force',
                  title: 'Scenario 1: Brute Force Attack',
                  mitre: 'T1110 (Credential Access)',
                  source: 'Windows Event ID 4625',
                  desc: 'Triggers high-volume authentication failures from remote test runner IP targeting service accounts.'
                },
                {
                  id: 'powershell',
                  title: 'Scenario 2: Suspicious PowerShell',
                  mitre: 'T1059.001 (Execution)',
                  source: 'Sysmon Event ID 1',
                  desc: 'Executes base64 encoded command lines attempting reflective DLL loading and C2 beaconing.'
                },
                {
                  id: 'account-creation',
                  title: 'Scenario 3: Unauthorized Account Creation',
                  mitre: 'T1098 (Persistence)',
                  source: 'Windows Event ID 4720',
                  desc: 'Creates unauthorized local administrator account via net user command.'
                },
                {
                  id: 'persistence',
                  title: 'Scenario 4: Scheduled Task Persistence',
                  mitre: 'T1053.005 (Persistence)',
                  source: 'Sysmon Event ID 1 / Event 4698',
                  desc: 'Registers malicious scheduled task executing payload on startup / logon.'
                },
                {
                  id: 'correlated',
                  title: 'Scenario 5: Multi-Stage Correlated Campaign',
                  mitre: 'Multiple ATT&CK Techniques',
                  source: 'Correlation Engine',
                  desc: 'Executes sequence 1 -> 2 -> 4 simultaneously, auto-generating a Critical Correlated Incident with risk score.'
                }
              ].map(scen => (
                <div key={scen.id} className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 flex flex-col justify-between space-y-4">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs bg-cyan-500/10 text-cyan-400 px-2 py-0.5 rounded border border-cyan-500/20">{scen.mitre}</span>
                      <span className="text-xs text-slate-500">{scen.source}</span>
                    </div>
                    <h3 className="text-base font-bold text-white font-sans">{scen.title}</h3>
                    <p className="text-xs text-slate-300 font-sans">{scen.desc}</p>
                  </div>
                  <button
                    disabled={simulating}
                    onClick={() => triggerSimulation(scen.id)}
                    className="w-full py-2.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded transition-colors flex items-center justify-center gap-2"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Run Attack Scenario</span>
                  </button>
                </div>
              ))}
            </div>

            {simulationMessage && (
              <div className="bg-cyan-950/40 border border-cyan-500/30 p-4 rounded text-xs text-cyan-200 flex items-center gap-3">
                <RefreshCw className="w-4 h-4 animate-spin shrink-0 text-cyan-400" />
                <span>{simulationMessage}</span>
              </div>
            )}
          </div>
        )}

        {/* -------------------- REPORTS & EXPORT VIEW -------------------- */}
        {activeTab === 'reports' && (
          <div className="space-y-6 font-mono">
            <div className="bg-[#0B101D] border border-slate-800/80 p-4 rounded-lg flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white">Incident Reporting & Markdown Export</h2>
                <p className="text-xs text-slate-400 font-sans">Generate professional executive audit reports containing timelines, mitigations, and status.</p>
              </div>
            </div>

            <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-6 space-y-6">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-4">
                <div>
                  <h3 className="text-base font-bold text-white">{selectedIncident.title} ({selectedIncident.incident_id})</h3>
                  <p className="text-xs text-slate-400 mt-1">Generated for Asset: <strong className="text-cyan-400">{selectedIncident.affected_asset}</strong></p>
                </div>
                <button
                  onClick={() => {
                    const mdContent = `# SOC-X INCIDENT REPORT: ${selectedIncident.incident_id}
Title: ${selectedIncident.title}
Severity: ${selectedIncident.severity}
Risk Score: ${selectedIncident.risk_score}/100
Affected Asset: ${selectedIncident.affected_asset}
Status: ${selectedIncident.status}
Assigned Analyst: ${selectedIncident.assigned_analyst}
MITRE Mappings: ${selectedIncident.mitre_mappings.join(', ')}

## Analyst Notes & Summary
${selectedIncident.notes}

## Response Actions Taken
${selectedIncident.response_action_taken}

## Associated Alerts
${selectedIncident.associated_alert_ids.join(', ')}
`;
                    const blob = new Blob([mdContent], { type: 'text/markdown' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `${selectedIncident.incident_id}_Report.md`;
                    a.click();
                  }}
                  className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded transition-colors flex items-center gap-2"
                >
                  <Download className="w-4 h-4" />
                  <span>Download Markdown Report</span>
                </button>
              </div>

              <div className="bg-[#070A12] p-6 rounded border border-slate-800 text-xs space-y-4 text-slate-300">
                <div className="text-cyan-400 font-bold text-sm"># SOC-X INCIDENT REPORT: {selectedIncident.incident_id}</div>
                <div><strong>Title:</strong> {selectedIncident.title}</div>
                <div><strong>Severity:</strong> {selectedIncident.severity} | <strong>Risk Score:</strong> {selectedIncident.risk_score}/100</div>
                <div><strong>Affected Asset:</strong> {selectedIncident.affected_asset} | <strong>Status:</strong> {selectedIncident.status}</div>
                <div><strong>MITRE Mappings:</strong> {selectedIncident.mitre_mappings.join(', ')}</div>
                
                <div className="pt-2 border-t border-slate-900">
                  <div className="text-white font-bold mb-1">## Analyst Notes</div>
                  <p className="text-slate-400">{selectedIncident.notes}</p>
                </div>

                <div className="pt-2 border-t border-slate-900">
                  <div className="text-white font-bold mb-1">## Response Actions</div>
                  <p className="text-slate-400">{selectedIncident.response_action_taken}</p>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Raw Alert Inspection Modal */}
      {selectedAlertForModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0B101D] border border-slate-800 rounded-lg max-w-2xl w-full p-6 space-y-4 shadow-2xl font-mono">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-xs bg-cyan-500/15 text-cyan-400">{selectedAlertForModal.alert_id}</span>
                <h3 className="text-sm font-bold text-white">{selectedAlertForModal.rule_name}</h3>
              </div>
              <button onClick={() => setSelectedAlertForModal(null)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <span className="text-slate-500">Timestamp:</span>
                  <div className="text-white">{new Date(selectedAlertForModal.timestamp).toLocaleString()}</div>
                </div>
                <div>
                  <span className="text-slate-500">Severity / Score:</span>
                  <div className="text-amber-400">{selectedAlertForModal.severity} ({selectedAlertForModal.risk_score})</div>
                </div>
                <div>
                  <span className="text-slate-500">Source Host & IP:</span>
                  <div className="text-cyan-400">{selectedAlertForModal.source_host} ({selectedAlertForModal.source_ip})</div>
                </div>
                <div>
                  <span className="text-slate-500">MITRE Technique:</span>
                  <div className="text-indigo-300">{selectedAlertForModal.mitre_technique} ({selectedAlertForModal.mitre_tactic})</div>
                </div>
              </div>

              <div>
                <span className="text-slate-500 block mb-1">Raw Sysmon / Windows Event Evidence:</span>
                <div className="bg-[#070A12] p-3 rounded border border-slate-800 text-slate-300 overflow-x-auto whitespace-pre-wrap">
                  {selectedAlertForModal.evidence_raw}
                </div>
              </div>

              {selectedAlertForModal.evidence_raw.includes('-enc') && (
                <div>
                  <span className="text-cyan-400 font-bold block mb-1">Base64 Decoder Helper:</span>
                  <div className="bg-cyan-950/40 p-3 rounded border border-cyan-500/30 text-cyan-200">
                    {decodeBase64Evidence(selectedAlertForModal.evidence_raw)}
                  </div>
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-slate-800/80 flex justify-end">
              <button
                onClick={() => setSelectedAlertForModal(null)}
                className="px-4 py-2 bg-[#070A12] hover:bg-slate-800 text-white rounded text-xs transition-colors"
              >
                Close Inspection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
