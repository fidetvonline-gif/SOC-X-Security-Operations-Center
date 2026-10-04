/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import {
  Shield,
  AlertTriangle,
  Server,
  Lock,
  Unlock,
  FileText,
  Play,
  Search,
  Clock,
  UserCheck,
  Zap,
  Download,
  RefreshCw,
  Eye,
  ChevronRight,
  Radio,
  RotateCcw,
  Globe,
  Grid,
  BarChart3,
  CheckCircle2,
  XCircle,
  Info,
  ExternalLink,
  ShieldAlert,
  UserPlus,
  Layers,
  Sliders,
  Check,
  HelpCircle
} from 'lucide-react';
import { supabase, isSupabaseConfigured } from './lib/supabase';

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
  status: 'New' | 'Investigating' | 'Contained' | 'Resolved' | 'Closed';
  risk_score: number;
  risk_breakdown?: {
    severity_factor: number;
    asset_criticality: number;
    confidence_score: number;
    threat_intel_score: number;
  };
  affected_asset: string;
  associated_alert_ids: string[];
  mitre_mappings: string[];
  assigned_analyst: string;
  notes: string;
  response_action_taken: string;
  created_at: string;
  updated_at: string;
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
  criticality: 'High' | 'Critical' | 'Medium';
}

interface AuditLog {
  audit_id: string;
  timestamp: string;
  analyst_id: string;
  action_type: string;
  target: string;
  details: string;
}

interface ThreatIntelResult {
  ip: string;
  is_known_threat: boolean;
  threat_score: number;
  confidence: string;
  actor: string;
  category: string;
  country: string;
  isp: string;
  last_seen: string;
  details: string;
}

const DEFAULT_ENDPOINTS: EndpointAsset[] = [
  {
    host_id: "EP-01",
    hostname: "WIN-EP01",
    ip_address: "192.168.1.105",
    os: "Windows 11 Enterprise (23H2)",
    status: "Online",
    wazuh_agent_version: "4.7.2",
    sysmon_status: "Active",
    last_heartbeat: new Date().toISOString(),
    criticality: "Medium"
  },
  {
    host_id: "EP-02",
    hostname: "DC-SRV01",
    ip_address: "192.168.1.10",
    os: "Windows Server 2022 Datacenter",
    status: "Online",
    wazuh_agent_version: "4.7.2",
    sysmon_status: "Active",
    last_heartbeat: new Date().toISOString(),
    criticality: "Critical"
  },
  {
    host_id: "EP-03",
    hostname: "FIN-LAPTOP04",
    ip_address: "192.168.1.142",
    os: "Windows 10 Pro",
    status: "Online",
    wazuh_agent_version: "4.7.1",
    sysmon_status: "Active",
    last_heartbeat: new Date().toISOString(),
    criticality: "High"
  }
];

const DEFAULT_ALERTS: Alert[] = [
  {
    alert_id: "ALT-1001",
    timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
    rule_id: "RULE-BF-01",
    rule_name: "Multiple Failed Logins (Brute Force)",
    severity: "High",
    risk_score: 40,
    source_host: "WIN-EP01",
    source_ip: "185.220.101.5",
    target_account: "admin_test",
    mitre_technique: "T1110",
    mitre_tactic: "Credential Access",
    evidence_raw: "Windows Event ID 4625: 14 failed authentication attempts in 60 seconds from IP 185.220.101.5 targeting user admin_test.",
    status: "Investigating"
  },
  {
    alert_id: "ALT-1002",
    timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    rule_id: "RULE-PS-01",
    rule_name: "Suspicious Encoded PowerShell Execution",
    severity: "High",
    risk_score: 55,
    source_host: "WIN-EP01",
    source_ip: "192.168.1.105",
    target_account: "system",
    mitre_technique: "T1059.001",
    mitre_tactic: "Execution",
    evidence_raw: "Sysmon Event ID 1: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC-ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEOWNk...",
    status: "Investigating"
  }
];

const DEFAULT_INCIDENTS: Incident[] = [
  {
    incident_id: "INC-2001",
    title: "Suspicious Brute Force & PowerShell Execution on WIN-EP01",
    severity: "High",
    status: "Investigating",
    risk_score: 68,
    risk_breakdown: {
      severity_factor: 75,
      asset_criticality: 60,
      confidence_score: 85,
      threat_intel_score: 90
    },
    affected_asset: "WIN-EP01",
    associated_alert_ids: ["ALT-1001", "ALT-1002"],
    mitre_mappings: ["T1110", "T1059.001"],
    assigned_analyst: "Unassigned",
    notes: "Detected brute force attempts from remote IP 185.220.101.5 followed by encoded PowerShell execution.",
    response_action_taken: "Awaiting analyst triage.",
    created_at: new Date(Date.now() - 25 * 60 * 1000).toISOString(),
    updated_at: new Date(Date.now() - 25 * 60 * 1000).toISOString()
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'alerts' | 'incidents' | 'investigation' | 'endpoints' | 'simulator' | 'reports'>('dashboard');
  const [alerts, setAlerts] = useState<Alert[]>(DEFAULT_ALERTS);
  const [incidents, setIncidents] = useState<Incident[]>(DEFAULT_INCIDENTS);
  const [endpoints, setEndpoints] = useState<EndpointAsset[]>(DEFAULT_ENDPOINTS);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]); // Clean, empty start!
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>('INC-2001');
  const [selectedAlertForModal, setSelectedAlertForModal] = useState<Alert | null>(null);
  
  // Search & Filter
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('All');
  
  // Threat Intel Inspector State
  const [threatIntelIp, setThreatIntelIp] = useState<string>('');
  const [threatIntelData, setThreatIntelData] = useState<ThreatIntelResult | null>(null);
  const [intelLoading, setIntelLoading] = useState<boolean>(false);
  const [showIntelModal, setShowIntelModal] = useState<boolean>(false);

  // Simulation loading state
  const [simulating, setSimulating] = useState<boolean>(false);
  const [simulationMessage, setSimulationMessage] = useState<string>('');

  // Analyst Action Input State
  const [analystNameInput, setAnalystNameInput] = useState<string>('Analyst_1');
  const [customNoteInput, setCustomNoteInput] = useState<string>('');

  const fetchData = async () => {
    try {
      const res = await fetch('/api/data');
      if (res.ok) {
        const text = await res.text();
        if (!text.trim().startsWith('<')) {
          const data = JSON.parse(text);
          if (data.alerts?.length) setAlerts(data.alerts);
          if (data.incidents?.length) {
            setIncidents(data.incidents);
            if (!selectedIncidentId && data.incidents[0]) {
              setSelectedIncidentId(data.incidents[0].incident_id);
            }
          }
          if (data.endpoints?.length) setEndpoints(data.endpoints);
          if (data.auditLogs) setAuditLogs(data.auditLogs);
          return;
        }
      }
    } catch {
      // Offline / Static mode fallback
    }

    if (supabase && isSupabaseConfigured) {
      try {
        const { data: sbAlerts } = await supabase.from('alerts').select('*').order('timestamp', { ascending: false });
        if (sbAlerts?.length) setAlerts(sbAlerts as Alert[]);

        const { data: sbIncidents } = await supabase.from('incidents').select('*').order('created_at', { ascending: false });
        if (sbIncidents?.length) {
          setIncidents(sbIncidents as Incident[]);
          if (!selectedIncidentId) setSelectedIncidentId(sbIncidents[0].incident_id);
        }

        const { data: sbEndpoints } = await supabase.from('endpoints').select('*');
        if (sbEndpoints?.length) setEndpoints(sbEndpoints as EndpointAsset[]);

        const { data: sbAudits } = await supabase.from('audit_logs').select('*').order('timestamp', { ascending: false });
        if (sbAudits) setAuditLogs(sbAudits as AuditLog[]);
      } catch {
        // Fallback to local state
      }
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Calculate dynamic risk score based on formula
  const computeRiskScore = (severity: 'Low' | 'Medium' | 'High' | 'Critical', host: string, alertCount: number, isExt: boolean) => {
    const sevMap = { Low: 25, Medium: 45, High: 75, Critical: 95 };
    const criticalityMap: Record<string, number> = { 'DC-SRV01': 95, 'FIN-LAPTOP04': 80, 'WIN-EP01': 60 };
    
    const sevFactor = sevMap[severity] || 45;
    const assetFactor = criticalityMap[host] || 60;
    const confidenceScore = Math.min(95, 70 + (alertCount * 8));
    const threatIntelScore = isExt ? 90 : 35;

    const score = Math.min(100, Math.round(
      (sevFactor * 0.40) +
      (assetFactor * 0.30) +
      (confidenceScore * 0.15) +
      (threatIntelScore * 0.15)
    ));

    return {
      score,
      breakdown: {
        severity_factor: sevFactor,
        asset_criticality: assetFactor,
        confidence_score: confidenceScore,
        threat_intel_score: threatIntelScore
      }
    };
  };

  // Reset Demo API
  const handleResetDemo = async () => {
    try {
      await fetch('/api/reset', { method: 'POST' });
    } catch {
      // Fallback
    }

    setAlerts(DEFAULT_ALERTS);
    setIncidents(DEFAULT_INCIDENTS);
    setEndpoints(DEFAULT_ENDPOINTS);
    setAuditLogs([]);
    setSelectedIncidentId('INC-2001');
    setSimulationMessage('Demo environment reset to baseline clean state.');
    setTimeout(() => setSimulationMessage(''), 3000);
  };

  // Lookup Threat Intel
  const handleLookupThreatIntel = async (ipToLookup: string) => {
    setThreatIntelIp(ipToLookup);
    setIntelLoading(true);
    setShowIntelModal(true);

    try {
      const res = await fetch(`/api/threat-intel/${encodeURIComponent(ipToLookup)}`);
      if (res.ok) {
        const data = await res.json();
        setThreatIntelData(data);
        setIntelLoading(false);
        return;
      }
    } catch {
      // Fallback simulated intel logic
    }

    // Client fallback intel logic
    setTimeout(() => {
      if (ipToLookup === '185.220.101.5') {
        setThreatIntelData({
          ip: ipToLookup,
          is_known_threat: true,
          threat_score: 92,
          confidence: 'High (88%)',
          actor: 'UNC2452 / Tor Exit Node',
          category: 'Brute Force Botnet & Scanner',
          country: 'NL (Netherlands)',
          isp: 'Tor Anonymizing Service',
          last_seen: new Date().toISOString(),
          details: 'Identified in global threat feeds conducting automated RDP/SSH credential stuffing.'
        });
      } else if (ipToLookup === '198.51.100.42') {
        setThreatIntelData({
          ip: ipToLookup,
          is_known_threat: true,
          threat_score: 96,
          confidence: 'High (94%)',
          actor: 'CobaltStrike C2 Infrastructure',
          category: 'Command & Control (C2)',
          country: 'RU (Russian Federation)',
          isp: 'Offshore Bulletproof Hosting',
          last_seen: new Date().toISOString(),
          details: 'Flagged as active beacon receiver for Empire / CobaltStrike malware framework.'
        });
      } else if (ipToLookup.startsWith('192.168.')) {
        setThreatIntelData({
          ip: ipToLookup,
          is_known_threat: false,
          threat_score: 5,
          confidence: 'High (99%)',
          actor: 'Internal Corporate Subnet',
          category: 'Local Subnet Endpoint',
          country: 'LAN',
          isp: 'Internal DHCP Gateway',
          last_seen: 'Current Session',
          details: 'Private RFC1918 address space. No external threat reputation alerts.'
        });
      } else {
        setThreatIntelData({
          ip: ipToLookup,
          is_known_threat: false,
          threat_score: 15,
          confidence: 'Medium (50%)',
          actor: 'Unknown / Neutral',
          category: 'Unflagged IP Address',
          country: 'Global',
          isp: 'Standard Telecom Provider',
          last_seen: 'N/A',
          details: 'No malicious activity associated with this IP in threat intelligence feeds.'
        });
      }
      setIntelLoading(false);
    }, 400);
  };

  // Run Simulation Scenario with Deduplication Logic
  const triggerSimulation = async (scenario: string) => {
    setSimulating(true);
    setSimulationMessage(`Ingesting attack scenario [${scenario}] into Wazuh pipeline...`);

    let targetHost = "WIN-EP01";
    let generatedAlerts: Alert[] = [];
    const now = new Date();

    if (scenario === 'brute-force') {
      targetHost = "WIN-EP01";
      generatedAlerts.push({
        alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
        timestamp: new Date().toISOString(),
        rule_id: "RULE-BF-01",
        rule_name: "Hydra SSH/RDP Brute Force Attack",
        severity: "High",
        risk_score: 40,
        source_host: "WIN-EP01",
        source_ip: "185.220.101.5",
        target_account: "administrator",
        mitre_technique: "T1110",
        mitre_tactic: "Credential Access",
        evidence_raw: "Windows Event ID 4625: 38 failed logon attempts recorded in 120 seconds from IP 185.220.101.5.",
        status: "Unassigned"
      });
    } else if (scenario === 'powershell') {
      targetHost = "WIN-EP01";
      generatedAlerts.push({
        alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
        timestamp: new Date().toISOString(),
        rule_id: "RULE-PS-01",
        rule_name: "Suspicious Encoded PowerShell Execution",
        severity: "High",
        risk_score: 55,
        source_host: "WIN-EP01",
        source_ip: "192.168.1.105",
        target_account: "system",
        mitre_technique: "T1059.001",
        mitre_tactic: "Execution",
        evidence_raw: "Sysmon Event ID 1: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC-ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEOWNk...",
        status: "Unassigned"
      });
    } else if (scenario === 'account-creation') {
      targetHost = "WIN-EP01";
      generatedAlerts.push({
        alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
        timestamp: new Date().toISOString(),
        rule_id: "RULE-USR-01",
        rule_name: "Unauthorized Local User Creation",
        severity: "Medium",
        risk_score: 30,
        source_host: "WIN-EP01",
        source_ip: "192.168.1.105",
        target_account: "test_admin",
        mitre_technique: "T1098",
        mitre_tactic: "Persistence",
        evidence_raw: "Windows Event ID 4720: User account created: test_admin via cmd.exe /c net user test_admin /add.",
        status: "Unassigned"
      });
    } else if (scenario === 'persistence') {
      targetHost = "WIN-EP01";
      generatedAlerts.push({
        alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
        timestamp: new Date().toISOString(),
        rule_id: "RULE-TSK-01",
        rule_name: "Scheduled Task Persistence Registered",
        severity: "High",
        risk_score: 45,
        source_host: "WIN-EP01",
        source_ip: "192.168.1.105",
        target_account: "SYSTEM",
        mitre_technique: "T1053.005",
        mitre_tactic: "Persistence",
        evidence_raw: "Sysmon Event ID 1: schtasks /create /tn 'WindowsSecurityUpdate' /tr 'cmd.exe /c calc.exe'",
        status: "Unassigned"
      });
    } else if (scenario === 'correlated') {
      targetHost = "FIN-LAPTOP04";
      const a1: Alert = {
        alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
        timestamp: new Date(now.getTime() - 10000).toISOString(),
        rule_id: "RULE-BF-01",
        rule_name: "Hydra Brute Force Attack",
        severity: "High",
        risk_score: 40,
        source_host: "FIN-LAPTOP04",
        source_ip: "198.51.100.42",
        target_account: "finance_admin",
        mitre_technique: "T1110",
        mitre_tactic: "Credential Access",
        evidence_raw: "Event ID 4625: 50 failed logins on FIN-LAPTOP04 from IP 198.51.100.42",
        status: "Investigating"
      };
      const a2: Alert = {
        alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
        timestamp: new Date(now.getTime() - 5000).toISOString(),
        rule_id: "RULE-PS-01",
        rule_name: "Suspicious Encoded PowerShell Execution",
        severity: "High",
        risk_score: 55,
        source_host: "FIN-LAPTOP04",
        source_ip: "192.168.1.142",
        target_account: "finance_admin",
        mitre_technique: "T1059.001",
        mitre_tactic: "Execution",
        evidence_raw: "Sysmon Event ID 1: powershell.exe -enc JABzACA...",
        status: "Investigating"
      };
      const a3: Alert = {
        alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
        timestamp: new Date().toISOString(),
        rule_id: "RULE-TSK-01",
        rule_name: "Scheduled Task Persistence",
        severity: "Critical",
        risk_score: 70,
        source_host: "FIN-LAPTOP04",
        source_ip: "192.168.1.142",
        target_account: "SYSTEM",
        mitre_technique: "T1053.005",
        mitre_tactic: "Persistence",
        evidence_raw: "SchTasks /create persistence payload on FIN-LAPTOP04",
        status: "Investigating"
      };
      generatedAlerts.push(a3, a2, a1);
    }

    // Try backend call first
    try {
      const res = await fetch('/api/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario })
      });
      if (res.ok) {
        const text = await res.text();
        if (!text.trim().startsWith('<')) {
          await fetchData();
          setSimulationMessage(`Scenario [${scenario}] executed. Incident updated without duplicates.`);
          setTimeout(() => setSimulating(false), 1500);
          return;
        }
      }
    } catch {
      // Offline fallback
    }

    // INCIDENT DEDUPLICATION LOGIC ON CLIENT:
    setAlerts(prev => [...generatedAlerts, ...prev]);

    setIncidents(prevIncidents => {
      const existingOpenInc = prevIncidents.find(i => i.affected_asset === targetHost && i.status !== 'Closed');

      if (existingOpenInc) {
        // UPDATE EXISTING INCIDENT (DEDUPLICATION)!
        const updatedAlertIds = [...existingOpenInc.associated_alert_ids];
        const updatedMitre = [...existingOpenInc.mitre_mappings];

        generatedAlerts.forEach(a => {
          if (!updatedAlertIds.includes(a.alert_id)) updatedAlertIds.push(a.alert_id);
          if (!updatedMitre.includes(a.mitre_technique)) updatedMitre.push(a.mitre_technique);
        });

        const maxSev = generatedAlerts.some(a => a.severity === 'Critical') ? 'Critical' :
          existingOpenInc.severity === 'Critical' ? 'Critical' :
          generatedAlerts.some(a => a.severity === 'High') ? 'High' : existingOpenInc.severity;

        const isExt = generatedAlerts.some(a => a.source_ip === '185.220.101.5' || a.source_ip === '198.51.100.42');
        const calc = computeRiskScore(maxSev as any, targetHost, updatedAlertIds.length, isExt);

        const updatedIncident: Incident = {
          ...existingOpenInc,
          severity: maxSev as any,
          risk_score: calc.score,
          risk_breakdown: calc.breakdown,
          associated_alert_ids: updatedAlertIds,
          mitre_mappings: updatedMitre,
          notes: `${existingOpenInc.notes} | Updated with scenario [${scenario}] (${generatedAlerts.length} new log entries).`,
          updated_at: new Date().toISOString()
        };

        setSelectedIncidentId(updatedIncident.incident_id);
        return prevIncidents.map(i => i.incident_id === updatedIncident.incident_id ? updatedIncident : i);
      } else {
        // CREATE SINGLE NEW INCIDENT IF NONE ACTIVE
        const isExt = generatedAlerts.some(a => a.source_ip === '185.220.101.5' || a.source_ip === '198.51.100.42');
        const maxSev = generatedAlerts.some(a => a.severity === 'Critical') ? 'Critical' :
          generatedAlerts.some(a => a.severity === 'High') ? 'High' : 'Medium';

        const calc = computeRiskScore(maxSev as any, targetHost, generatedAlerts.length, isExt);

        const newInc: Incident = {
          incident_id: `INC-${Math.floor(2000 + Math.random() * 9000)}`,
          title: `Active Threat Campaign on ${targetHost}`,
          severity: maxSev as any,
          status: 'New',
          risk_score: calc.score,
          risk_breakdown: calc.breakdown,
          affected_asset: targetHost,
          associated_alert_ids: generatedAlerts.map(a => a.alert_id),
          mitre_mappings: Array.from(new Set(generatedAlerts.map(a => a.mitre_technique))),
          assigned_analyst: 'Unassigned',
          notes: `Triggered scenario [${scenario}]: ${generatedAlerts.length} correlated telemetry events.`,
          response_action_taken: 'Pending Analyst Triage',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };

        setSelectedIncidentId(newInc.incident_id);
        return [newInc, ...prevIncidents];
      }
    });

    setSimulationMessage(`Scenario [${scenario}] executed. Telemetry correlated into active host incident.`);
    setTimeout(() => setSimulating(false), 1500);
  };

  // Endpoint Isolation / Release Handler
  const handleToggleEndpointIsolation = async (hostId: string, currentStatus: string) => {
    const isIsolating = currentStatus !== 'Isolated';
    const actionUrl = isIsolating ? '/api/response/isolate' : '/api/response/release-isolation';

    try {
      await fetch(actionUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host_id: hostId, analyst_id: analystNameInput || 'Analyst_1' })
      });
    } catch {
      // Fallback
    }

    const newStatus = isIsolating ? 'Isolated' : 'Online';
    setEndpoints(prev => prev.map(e => (e.hostname === hostId || e.host_id === hostId) ? { ...e, status: newStatus } : e));

    const newAudit: AuditLog = {
      audit_id: `AUD-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      analyst_id: analystNameInput || 'Analyst_1',
      action_type: isIsolating ? 'ENDPOINT_ISOLATION' : 'ENDPOINT_RELEASE',
      target: hostId,
      details: isIsolating
        ? `Applied network isolation rule to ${hostId}. Non-SOC network traffic blocked.`
        : `Removed network isolation for ${hostId}. Normal connectivity restored.`
    };

    setAuditLogs(prev => [newAudit, ...prev]);
    if (supabase && isSupabaseConfigured) {
      supabase.from('audit_logs').insert([newAudit]).then(() => {}, () => {});
    }
  };

  // Incident Lifecycle Assignment & Status Handlers
  const handleAssignAnalyst = (incidentId: string, analystName: string) => {
    setIncidents(prev => prev.map(inc => {
      if (inc.incident_id === incidentId) {
        const newStatus = inc.status === 'New' ? 'Investigating' : inc.status;
        const updated = {
          ...inc,
          assigned_analyst: analystName,
          status: newStatus as any,
          updated_at: new Date().toISOString()
        };

        const audit: AuditLog = {
          audit_id: `AUD-${Math.floor(1000 + Math.random() * 9000)}`,
          timestamp: new Date().toISOString(),
          analyst_id: analystName,
          action_type: 'INCIDENT_ASSIGNMENT',
          target: incidentId,
          details: `Assigned incident ${incidentId} to ${analystName}. Status changed to ${newStatus}.`
        };
        setAuditLogs(aPrev => [audit, ...aPrev]);

        return updated;
      }
      return inc;
    }));
  };

  const handleUpdateIncidentStatus = (
    incidentId: string,
    newStatus: 'New' | 'Investigating' | 'Contained' | 'Resolved' | 'Closed',
    responseAction?: string
  ) => {
    setIncidents(prev => prev.map(inc => {
      if (inc.incident_id === incidentId) {
        const actionText = responseAction || inc.response_action_taken;
        const updated = {
          ...inc,
          status: newStatus,
          response_action_taken: actionText,
          notes: customNoteInput ? `${inc.notes}\n[${new Date().toLocaleTimeString()}] ${analystNameInput}: ${customNoteInput}` : inc.notes,
          updated_at: new Date().toISOString()
        };

        const audit: AuditLog = {
          audit_id: `AUD-${Math.floor(1000 + Math.random() * 9000)}`,
          timestamp: new Date().toISOString(),
          analyst_id: analystNameInput || inc.assigned_analyst || 'Analyst_1',
          action_type: `STATUS_CHANGE_${newStatus.toUpperCase()}`,
          target: incidentId,
          details: `Changed incident status to [${newStatus}]. Action: ${actionText}`
        };
        setAuditLogs(aPrev => [audit, ...aPrev]);
        setCustomNoteInput('');

        return updated;
      }
      return inc;
    }));
  };

  const decodeBase64Evidence = (evidence: string) => {
    try {
      const match = evidence.match(/-enc\s+([A-Za-z0-9+/=]+)/);
      if (match && match[1]) {
        const decoded = atob(match[1]);
        return `Decoded Command: ${decoded}`;
      }
      return 'No base64 encoded payload pattern found.';
    } catch {
      return 'Failed to decode base64 string.';
    }
  };

  const selectedIncident = incidents.find(i => i.incident_id === selectedIncidentId) || incidents[0] || DEFAULT_INCIDENTS[0];
  const onlineEndpointsCount = endpoints.filter(e => e.status === 'Online').length;
  const criticalIncidentsCount = incidents.filter(i => i.severity === 'Critical' && i.status !== 'Closed').length;

  return (
    <div className="min-h-screen bg-[#090D16] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Header */}
      <header className="h-14 border-b border-slate-800/80 bg-[#0B101D] px-6 flex items-center justify-between sticky top-0 z-50">
        <div className="flex items-center gap-3">
          <div className="w-7 h-7 rounded bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Shield className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold tracking-tight text-white font-mono">SOC-X</span>
              <span className="text-xs bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-mono px-2 py-0.2 rounded">Academic SOC Simulator</span>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="hidden xl:flex items-center gap-1 bg-[#070A12] p-1 rounded border border-slate-800/80 text-xs font-mono">
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

        {/* Actions & Status */}
        <div className="flex items-center gap-3 text-xs font-mono">
          <button
            onClick={handleResetDemo}
            className="flex items-center gap-1.5 px-2.5 py-1 bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 rounded transition-colors"
            title="Reset demo state to baseline clean start"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Demo</span>
          </button>

          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 rounded">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>SIEM Active</span>
          </div>

          <div className="flex items-center gap-2 pl-3 border-l border-slate-800 text-slate-300">
            <span className="text-cyan-400">#A1</span>
            <input
              type="text"
              value={analystNameInput}
              onChange={(e) => setAnalystNameInput(e.target.value)}
              className="bg-[#070A12] border border-slate-800 rounded px-2 py-0.5 text-xs text-cyan-300 w-24 focus:outline-none focus:border-cyan-500"
              placeholder="Analyst Name"
            />
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
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono">
              <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-4">
                <div className="text-xs text-slate-400 uppercase tracking-wider">Critical Incidents</div>
                <div className="mt-2 flex items-baseline justify-between">
                  <span className="text-2xl font-bold text-white tabular-nums">{criticalIncidentsCount}</span>
                  <span className="text-xs text-red-400 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> Action Req.</span>
                </div>
              </div>

              <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-4">
                <div className="text-xs text-slate-400 uppercase tracking-wider">High Severity Alerts</div>
                <div className="mt-2 flex items-baseline justify-between">
                  <span className="text-2xl font-bold text-white tabular-nums">{alerts.filter(a => a.severity === 'High').length}</span>
                  <span className="text-xs text-amber-400">Past 24h</span>
                </div>
              </div>

              <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-4">
                <div className="text-xs text-slate-400 uppercase tracking-wider">Monitored Endpoints</div>
                <div className="mt-2 flex items-baseline justify-between">
                  <span className="text-2xl font-bold text-white tabular-nums">{endpoints.length}</span>
                  <span className="text-xs text-emerald-400">{onlineEndpointsCount} / {endpoints.length} Online</span>
                </div>
              </div>

              <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-4">
                <div className="text-xs text-slate-400 uppercase tracking-wider">Telemetry Ingestion</div>
                <div className="mt-2 flex items-baseline justify-between">
                  <span className="text-2xl font-bold text-white tabular-nums">{alerts.length}</span>
                  <span className="text-xs text-emerald-400">Active Logs</span>
                </div>
              </div>
            </div>

            {/* Attack Simulation Lab Strip */}
            <div className="bg-[#0B101D] border border-cyan-500/30 rounded-lg p-4 flex flex-col lg:flex-row items-center justify-between gap-4 font-mono">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
                  <Zap className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider">Attack Simulation & Verification Lab</h3>
                  <p className="text-xs text-slate-400 font-sans">Trigger simulated adversary scenarios to evaluate correlation rules and active incident aggregation.</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <button
                  disabled={simulating}
                  onClick={() => triggerSimulation('brute-force')}
                  className="px-3 py-1.5 bg-[#070A12] hover:bg-slate-800 text-xs text-cyan-300 rounded border border-slate-800 transition-colors"
                >
                  Brute Force (T1110)
                </button>
                <button
                  disabled={simulating}
                  onClick={() => triggerSimulation('powershell')}
                  className="px-3 py-1.5 bg-[#070A12] hover:bg-slate-800 text-xs text-cyan-300 rounded border border-slate-800 transition-colors"
                >
                  PowerShell (T1059.001)
                </button>
                <button
                  disabled={simulating}
                  onClick={() => triggerSimulation('correlated')}
                  className="px-3.5 py-1.5 bg-cyan-500 hover:bg-cyan-400 text-xs text-slate-950 font-bold rounded transition-colors"
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

            {/* MITRE ATT&CK Summary & Alerts Chart Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* MITRE ATT&CK Matrix Summary */}
              <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 font-mono">
                <h3 className="text-xs font-bold uppercase tracking-wider text-white mb-4 flex items-center gap-2">
                  <Grid className="w-4 h-4 text-cyan-400" /> MITRE ATT&CK Coverage & Triggered Techniques
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
                  {[
                    { tactic: 'Credential Access', tech: 'T1110 (Brute Force)', count: alerts.filter(a => a.mitre_technique === 'T1110').length, color: 'border-amber-500/30 text-amber-300 bg-amber-500/10' },
                    { tactic: 'Execution', tech: 'T1059.001 (PowerShell)', count: alerts.filter(a => a.mitre_technique === 'T1059.001').length, color: 'border-indigo-500/30 text-indigo-300 bg-indigo-500/10' },
                    { tactic: 'Persistence', tech: 'T1053.005 (SchTasks)', count: alerts.filter(a => a.mitre_technique === 'T1053.005').length, color: 'border-purple-500/30 text-purple-300 bg-purple-500/10' },
                    { tactic: 'Persistence', tech: 'T1098 (Account Creation)', count: alerts.filter(a => a.mitre_technique === 'T1098').length, color: 'border-blue-500/30 text-blue-300 bg-blue-500/10' },
                    { tactic: 'Defense Evasion', tech: 'T1027 (Obfuscation)', count: alerts.filter(a => a.evidence_raw.includes('-enc')).length, color: 'border-cyan-500/30 text-cyan-300 bg-cyan-500/10' },
                    { tactic: 'Command & Control', tech: 'T1071 (Application Layer)', count: alerts.filter(a => a.source_ip === '198.51.100.42').length, color: 'border-red-500/30 text-red-300 bg-red-500/10' }
                  ].map((m, idx) => (
                    <div key={idx} className={`p-2.5 rounded border ${m.color} space-y-1`}>
                      <div className="text-[10px] uppercase text-slate-400">{m.tactic}</div>
                      <div className="font-bold">{m.tech}</div>
                      <div className="text-[10px] text-right font-bold">{m.count} event(s)</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Alerts Over Time Chart Visual */}
              <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 font-mono">
                <h3 className="text-xs font-bold uppercase tracking-wider text-white mb-4 flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-cyan-400" /> Ingested Telemetry Severity Distribution
                </h3>
                <div className="space-y-3 pt-2">
                  {[
                    { label: 'Critical Severity', count: alerts.filter(a => a.severity === 'Critical').length, color: 'bg-red-500', text: 'text-red-400' },
                    { label: 'High Severity', count: alerts.filter(a => a.severity === 'High').length, color: 'bg-amber-500', text: 'text-amber-400' },
                    { label: 'Medium Severity', count: alerts.filter(a => a.severity === 'Medium').length, color: 'bg-blue-500', text: 'text-blue-400' },
                    { label: 'Low Severity', count: alerts.filter(a => a.severity === 'Low').length, color: 'bg-slate-500', text: 'text-slate-400' }
                  ].map(bar => {
                    const pct = alerts.length ? Math.min(100, Math.round((bar.count / alerts.length) * 100)) : 0;
                    return (
                      <div key={bar.label} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className={bar.text}>{bar.label}</span>
                          <span className="text-slate-400">{bar.count} logs ({pct}%)</span>
                        </div>
                        <div className="w-full h-2 bg-[#070A12] rounded overflow-hidden">
                          <div className={`h-full ${bar.color} transition-all duration-500`} style={{ width: `${Math.max(4, pct)}%` }}></div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left 2 Cols: Active Incidents */}
              <div className="lg:col-span-2 space-y-6 font-mono">
                <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5">
                  <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800/80">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
                      <Shield className="w-4 h-4 text-cyan-400" /> Active Correlated Incidents
                    </h3>
                    <button onClick={() => setActiveTab('incidents')} className="text-xs text-cyan-400 hover:underline">View All ({incidents.length})</button>
                  </div>
                  <div className="space-y-3">
                    {incidents.slice(0, 3).map(inc => (
                      <div key={inc.incident_id} className="bg-[#070A12] border border-slate-800/80 rounded p-4 hover:border-slate-700 transition-colors">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              inc.severity === 'Critical' ? 'bg-red-500/15 text-red-400 border border-red-500/30' :
                              inc.severity === 'High' ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30' : 'bg-blue-500/15 text-blue-400'
                            }`}>
                              {inc.severity}
                            </span>
                            <span className="text-xs text-slate-400">{inc.incident_id}</span>
                            <span className="text-xs text-cyan-400 font-semibold">{inc.affected_asset}</span>
                            <span className="text-[10px] px-2 py-0.5 bg-slate-800 text-amber-300 rounded">{inc.status}</span>
                          </div>
                          <span className="text-xs text-slate-400">Risk Score: <strong className="text-cyan-400">{inc.risk_score}/100</strong></span>
                        </div>
                        <h4 className="text-sm font-semibold text-white mt-2 font-sans">{inc.title}</h4>
                        <p className="text-xs text-slate-400 mt-1 line-clamp-1 font-sans">{inc.notes}</p>
                        <div className="mt-3 flex items-center justify-between pt-3 border-t border-slate-900 text-xs">
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
                    <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
                      <Server className="w-4 h-4 text-cyan-400" /> Monitored Endpoint Fleet
                    </h3>
                    <button onClick={() => setActiveTab('endpoints')} className="text-xs text-cyan-400 hover:underline">Manage Fleet</button>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                    {endpoints.map(ep => (
                      <div key={ep.host_id} className="bg-[#070A12] border border-slate-800/80 rounded p-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-white">{ep.hostname}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] ${
                            ep.status === 'Isolated' ? 'bg-red-500/15 text-red-400 border border-red-500/30' : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                          }`}>
                            {ep.status}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">{ep.ip_address}</p>
                        <div className="mt-2 pt-2 border-t border-slate-900 flex items-center justify-between text-[10px]">
                          <span className="text-slate-400">Wazuh v{ep.wazuh_agent_version}</span>
                          <button
                            onClick={() => handleToggleEndpointIsolation(ep.hostname, ep.status)}
                            className={`px-2 py-0.5 rounded ${ep.status === 'Isolated' ? 'text-emerald-400 hover:underline' : 'text-red-400 hover:underline'}`}
                          >
                            {ep.status === 'Isolated' ? 'Release' : 'Isolate'}
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Right Col: Live Telemetry Stream with IP Threat Intel Triggers */}
              <div className="space-y-6 font-mono">
                <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 flex flex-col h-full">
                  <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800/80">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
                      <Radio className="w-4 h-4 text-cyan-400 animate-pulse" /> Live Telemetry Feed
                    </h3>
                    <span className="text-xs text-slate-400">{alerts.length} events</span>
                  </div>

                  <div className="space-y-2.5 overflow-y-auto max-h-[500px] pr-1">
                    {alerts.map(alert => (
                      <div
                        key={alert.alert_id}
                        className="bg-[#070A12] border border-slate-800/80 rounded p-3 hover:border-cyan-500/40 transition-colors group"
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
                        <h4 className="text-xs font-semibold text-white mt-1.5 cursor-pointer" onClick={() => setSelectedAlertForModal(alert)}>
                          {alert.rule_name}
                        </h4>
                        <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                          <span className="text-cyan-400">{alert.source_host}</span>
                          <button
                            onClick={() => handleLookupThreatIntel(alert.source_ip)}
                            className="text-amber-300 hover:underline flex items-center gap-1 text-[10px] bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/20"
                          >
                            <Globe className="w-3 h-3" />
                            <span>IP Intel ({alert.source_ip})</span>
                          </button>
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
          <div className="space-y-6 font-mono">
            <div className="flex flex-col md:flex-row items-center justify-between gap-4 bg-[#0B101D] border border-slate-800/80 p-4 rounded-lg">
              <div>
                <h2 className="text-base font-bold text-white">Alerts & Sysmon Telemetry Ingestion</h2>
                <p className="text-xs text-slate-400 font-sans">Real-time log ingestion from Windows Event Logs, Sysmon, and Wazuh security rules.</p>
              </div>
              <div className="flex items-center gap-3 w-full md:w-auto">
                <div className="relative flex-1 md:w-64">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-3" />
                  <input
                    type="text"
                    placeholder="Search host, rule, MITRE..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full bg-[#070A12] border border-slate-800 rounded px-3 py-2 text-xs text-white pl-9 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="bg-[#070A12] border border-slate-800 rounded px-3 py-2 text-xs text-white"
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
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#070A12] text-slate-400 uppercase tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="p-3">Alert ID</th>
                      <th className="p-3">Timestamp</th>
                      <th className="p-3">Rule Name / ID</th>
                      <th className="p-3">Severity</th>
                      <th className="p-3">Source Host</th>
                      <th className="p-3">Source IP</th>
                      <th className="p-3">MITRE</th>
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
                          <td className="p-3 text-slate-300">{alert.source_host}</td>
                          <td className="p-3">
                            <button
                              onClick={() => handleLookupThreatIntel(alert.source_ip)}
                              className="text-amber-300 hover:underline font-semibold"
                            >
                              {alert.source_ip}
                            </button>
                          </td>
                          <td className="p-3 text-indigo-300">{alert.mitre_technique}</td>
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
          <div className="space-y-6 font-mono">
            <div className="bg-[#0B101D] border border-slate-800/80 p-4 rounded-lg flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white">Incident Correlation & Lifecycle Management</h2>
                <p className="text-xs text-slate-400 font-sans">Multi-alert correlation engine with incident lifecycle controls (Assign, Escalate, Contain, Resolve, Close).</p>
              </div>
              <span className="text-xs bg-[#070A12] px-3 py-1.5 rounded border border-slate-800 text-slate-300">
                Total Incidents: <strong className="text-white">{incidents.length}</strong>
              </span>
            </div>

            <div className="space-y-4">
              {incidents.map(inc => (
                <div key={inc.incident_id} className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5">
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
                        <span className="text-xs px-2 py-0.5 bg-slate-800 text-amber-300 rounded font-bold">{inc.status}</span>
                      </div>
                      <h3 className="text-base font-bold text-white font-sans">{inc.title}</h3>
                      <p className="text-xs text-slate-400 font-sans">{inc.notes}</p>
                    </div>

                    <div className="flex items-center gap-4 shrink-0">
                      <div className="text-right">
                        <div className="text-xs text-slate-400">Dynamic Risk Score</div>
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

                  {/* Lifecycle Controls Bar */}
                  <div className="mt-4 pt-4 border-t border-slate-800/80 flex flex-wrap items-center justify-between text-xs text-slate-400 gap-3">
                    <div className="flex items-center gap-2">
                      <span>Assigned:</span>
                      <select
                        value={inc.assigned_analyst}
                        onChange={(e) => handleAssignAnalyst(inc.incident_id, e.target.value)}
                        className="bg-[#070A12] border border-slate-800 rounded px-2 py-1 text-xs text-cyan-300"
                      >
                        <option value="Unassigned">Unassigned</option>
                        <option value="Analyst_1">Analyst_1</option>
                        <option value="Lead_SecOps">Lead_SecOps</option>
                        <option value="Tier2_Forensics">Tier2_Forensics</option>
                      </select>
                    </div>

                    <div className="flex items-center gap-1.5">
                      <button
                        onClick={() => handleUpdateIncidentStatus(inc.incident_id, 'Investigating')}
                        className={`px-2.5 py-1 rounded border ${inc.status === 'Investigating' ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 font-bold' : 'bg-[#070A12] border-slate-800 text-slate-400 hover:text-white'}`}
                      >
                        Investigate
                      </button>
                      <button
                        onClick={() => handleUpdateIncidentStatus(inc.incident_id, 'Contained', 'Host network isolated and process terminated.')}
                        className={`px-2.5 py-1 rounded border ${inc.status === 'Contained' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40 font-bold' : 'bg-[#070A12] border-slate-800 text-slate-400 hover:text-white'}`}
                      >
                        Contain
                      </button>
                      <button
                        onClick={() => handleUpdateIncidentStatus(inc.incident_id, 'Resolved', 'Account disabled, malware removed, scheduled task deleted.')}
                        className={`px-2.5 py-1 rounded border ${inc.status === 'Resolved' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40 font-bold' : 'bg-[#070A12] border-slate-800 text-slate-400 hover:text-white'}`}
                      >
                        Resolve
                      </button>
                      <button
                        onClick={() => handleUpdateIncidentStatus(inc.incident_id, 'Closed', 'Investigation closed after post-incident audit.')}
                        className={`px-2.5 py-1 rounded border ${inc.status === 'Closed' ? 'bg-slate-700 text-slate-200 border-slate-600 font-bold' : 'bg-[#070A12] border-slate-800 text-slate-400 hover:text-white'}`}
                      >
                        Close
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* -------------------- INVESTIGATION WORKSPACE VIEW -------------------- */}
        {activeTab === 'investigation' && (
          <div className="space-y-6 font-mono">
            <div className="bg-[#0B101D] border border-slate-800/80 p-4 rounded-lg flex flex-col md:flex-row items-center justify-between gap-4">
              <div>
                <h2 className="text-base font-bold text-white">Investigation Workspace</h2>
                <p className="text-xs text-slate-400 font-sans">Chronological attack chain analysis, dynamic risk calculation breakdown, and active containment.</p>
              </div>
              <div className="flex items-center gap-2">
                <label className="text-xs text-slate-400">Incident:</label>
                <select
                  value={selectedIncidentId}
                  onChange={(e) => setSelectedIncidentId(e.target.value)}
                  className="bg-[#070A12] border border-slate-800 rounded px-3 py-1.5 text-xs text-white"
                >
                  {incidents.map(i => (
                    <option key={i.incident_id} value={i.incident_id}>{i.incident_id} - {i.affected_asset} ({i.severity})</option>
                  ))}
                </select>
              </div>
            </div>

            {selectedIncident && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Left 2 Cols: Incident Details & Timeline */}
                <div className="lg:col-span-2 space-y-6">
                  <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xs bg-cyan-500/10 text-cyan-400 px-2 py-0.5 rounded border border-cyan-500/20">{selectedIncident.incident_id}</span>
                        <span className="text-xs text-slate-400">Host: <strong className="text-white">{selectedIncident.affected_asset}</strong></span>
                        <span className="text-xs text-amber-300 font-bold bg-slate-800 px-2 py-0.5 rounded">{selectedIncident.status}</span>
                      </div>
                      <div className="text-right">
                        <span className="text-xs text-slate-400">Risk Score: </span>
                        <span className="text-sm font-bold text-cyan-400">{selectedIncident.risk_score}/100</span>
                      </div>
                    </div>

                    <h3 className="text-base font-bold text-white font-sans">{selectedIncident.title}</h3>
                    <p className="text-xs text-slate-300 bg-[#070A12] p-3 rounded border border-slate-800 font-sans">{selectedIncident.notes}</p>

                    {/* Dynamic Risk Score Calculation Formula Breakdown */}
                    {selectedIncident.risk_breakdown && (
                      <div className="bg-[#070A12] p-3 rounded border border-slate-800 space-y-2 text-xs">
                        <div className="flex items-center justify-between text-cyan-400 font-bold border-b border-slate-800 pb-1.5">
                          <span>Risk Score Formula Calculation</span>
                          <span>Score: {selectedIncident.risk_score}/100</span>
                        </div>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] pt-1">
                          <div>
                            <span className="text-slate-500 block">Severity (40%)</span>
                            <span className="text-white font-bold">{selectedIncident.risk_breakdown.severity_factor} pts</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block">Asset Criticality (30%)</span>
                            <span className="text-white font-bold">{selectedIncident.risk_breakdown.asset_criticality} pts</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block">Confidence (15%)</span>
                            <span className="text-white font-bold">{selectedIncident.risk_breakdown.confidence_score} pts</span>
                          </div>
                          <div>
                            <span className="text-slate-500 block">Threat Intel (15%)</span>
                            <span className="text-white font-bold">{selectedIncident.risk_breakdown.threat_intel_score} pts</span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Timeline Analysis */}
                    <div className="pt-4 border-t border-slate-800/80">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-4 flex items-center justify-between">
                        <span className="flex items-center gap-2"><Clock className="w-4 h-4 text-cyan-400" /> Chronological Attack Chain Timeline</span>
                        <span className="text-[10px] text-slate-500">Sorted T0 → T-Latest</span>
                      </h4>

                      <div className="space-y-3">
                        {alerts
                          .filter(a => selectedIncident.associated_alert_ids.includes(a.alert_id) || a.source_host === selectedIncident.affected_asset)
                          .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
                          .map((alert, idx) => (
                            <div key={alert.alert_id} className="relative pl-6 pb-4 border-l border-cyan-500/30 last:border-0 last:pb-0">
                              <div className="absolute -left-1.5 top-0 w-3 h-3 rounded-full bg-cyan-500 border-2 border-[#090D16]"></div>
                              <div className="bg-[#070A12] border border-slate-800 rounded p-3 space-y-1.5">
                                <div className="flex items-center justify-between text-xs">
                                  <div className="flex items-center gap-2">
                                    <span className="text-[10px] bg-slate-800 text-cyan-300 px-1.5 py-0.5 rounded font-bold">Step T{idx + 1}</span>
                                    <span className="text-cyan-400 font-bold">{alert.rule_name}</span>
                                  </div>
                                  <span className="text-slate-500">{new Date(alert.timestamp).toLocaleTimeString()}</span>
                                </div>
                                <p className="text-xs text-slate-300 font-sans">{alert.evidence_raw}</p>
                                <div className="flex items-center justify-between text-[10px] pt-1">
                                  <div className="flex gap-2">
                                    <span className="bg-indigo-500/20 text-indigo-300 px-1.5 py-0.5 rounded">{alert.mitre_technique}</span>
                                    <span className="bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded">{alert.mitre_tactic}</span>
                                  </div>
                                  <button
                                    onClick={() => handleLookupThreatIntel(alert.source_ip)}
                                    className="text-amber-300 hover:underline"
                                  >
                                    IP: {alert.source_ip}
                                  </button>
                                </div>
                              </div>
                            </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Right Col: Response Playbooks & Notes */}
                <div className="space-y-6">
                  {/* Status Lifecycle Control */}
                  <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
                      <Sliders className="w-4 h-4 text-cyan-400" /> Lifecycle Status Transition
                    </h3>

                    <div className="grid grid-cols-2 gap-2 text-xs">
                      {(['New', 'Investigating', 'Contained', 'Resolved', 'Closed'] as const).map((st) => (
                        <button
                          key={st}
                          onClick={() => handleUpdateIncidentStatus(selectedIncident.incident_id, st)}
                          className={`py-1.5 px-2 rounded border transition-colors ${
                            selectedIncident.status === st
                              ? 'bg-cyan-500 text-slate-950 font-bold border-cyan-400'
                              : 'bg-[#070A12] text-slate-400 hover:text-white border-slate-800'
                          }`}
                        >
                          Set {st}
                        </button>
                      ))}
                    </div>

                    <div className="pt-2 space-y-2">
                      <label className="text-xs text-slate-400 block">Add Analyst Mitigation Note:</label>
                      <textarea
                        value={customNoteInput}
                        onChange={(e) => setCustomNoteInput(e.target.value)}
                        placeholder="Type findings or containment steps..."
                        className="w-full bg-[#070A12] border border-slate-800 rounded p-2 text-xs text-white focus:outline-none focus:border-cyan-500 h-16 resize-none font-sans"
                      />
                      <button
                        onClick={() => handleUpdateIncidentStatus(selectedIncident.incident_id, selectedIncident.status, customNoteInput || selectedIncident.response_action_taken)}
                        className="w-full py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-bold rounded transition-colors"
                      >
                        Save Note to Incident Record
                      </button>
                    </div>
                  </div>

                  {/* Active Response Playbooks */}
                  <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 space-y-4">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-2">
                      <Zap className="w-4 h-4 text-amber-400" /> Active Response Playbooks
                    </h3>

                    {(() => {
                      const ep = endpoints.find(e => e.hostname === selectedIncident.affected_asset);
                      const isIsolated = ep?.status === 'Isolated';

                      return (
                        <div className="space-y-3">
                          <div className="bg-[#070A12] p-3.5 rounded border border-slate-800 space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-bold text-white">Endpoint Network Control</span>
                              <span className={`text-[10px] ${isIsolated ? 'text-red-400 font-bold' : 'text-emerald-400'}`}>
                                {isIsolated ? 'ISOLATED' : 'ONLINE'}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 font-sans">Apply or release firewall containment for {selectedIncident.affected_asset}.</p>
                            <button
                              onClick={() => handleToggleEndpointIsolation(selectedIncident.affected_asset, ep?.status || 'Online')}
                              className={`w-full py-2 text-xs font-bold rounded transition-colors flex items-center justify-center gap-1.5 ${
                                isIsolated ? 'bg-emerald-600 hover:bg-emerald-500 text-white' : 'bg-red-600 hover:bg-red-500 text-white'
                              }`}
                            >
                              {isIsolated ? <Unlock className="w-3.5 h-3.5" /> : <Lock className="w-3.5 h-3.5" />}
                              <span>{isIsolated ? 'Release Network Isolation' : 'Isolate Host Network Now'}</span>
                            </button>
                          </div>
                        </div>
                      );
                    })()}
                  </div>

                  {/* Dynamic Audit Trail */}
                  <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center justify-between">
                      <span className="flex items-center gap-2"><FileText className="w-4 h-4 text-cyan-400" /> Dynamic Audit Trail</span>
                      <span className="text-[10px] text-slate-500">{auditLogs.length} actions logged</span>
                    </h3>

                    {auditLogs.length === 0 ? (
                      <p className="text-xs text-slate-500 py-3 text-center italic font-sans">Audit trail is currently clean. Performed actions will be recorded here in real-time.</p>
                    ) : (
                      <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
                        {auditLogs.map(audit => (
                          <div key={audit.audit_id} className="bg-[#070A12] p-2.5 rounded border border-slate-800 text-[11px] space-y-0.5">
                            <div className="flex items-center justify-between text-slate-500">
                              <span className="text-cyan-400 font-bold">{audit.analyst_id}</span>
                              <span>{new Date(audit.timestamp).toLocaleTimeString()}</span>
                            </div>
                            <p className="text-slate-300 font-sans">{audit.details}</p>
                          </div>
                        ))}
                      </div>
                    )}
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
                <p className="text-xs text-slate-400 font-sans">Manage Wazuh security agents, network isolation states, and heartbeat status.</p>
              </div>
              <span className="text-xs bg-[#070A12] px-3 py-1.5 rounded border border-slate-800 text-emerald-400">
                {onlineEndpointsCount} / {endpoints.length} Online Agents
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              {endpoints.map(ep => (
                <div key={ep.host_id} className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-bold text-white">{ep.hostname}</span>
                    <span className={`px-2.5 py-0.5 rounded text-xs font-bold ${
                      ep.status === 'Isolated' ? 'bg-red-500/15 text-red-400 border border-red-500/30' : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                    }`}>
                      {ep.status}
                    </span>
                  </div>

                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between text-slate-400">
                      <span>Standard IP:</span>
                      <span className="text-white font-bold">{ep.ip_address}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Asset Criticality:</span>
                      <span className="text-amber-300">{ep.criticality}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>OS:</span>
                      <span className="text-white truncate max-w-[170px]">{ep.os}</span>
                    </div>
                    <div className="flex justify-between text-slate-400">
                      <span>Wazuh Agent:</span>
                      <span className="text-cyan-400">v{ep.wazuh_agent_version}</span>
                    </div>
                  </div>

                  <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                    <span className="text-[10px] text-slate-500">Heartbeat: Active</span>
                    <button
                      onClick={() => handleToggleEndpointIsolation(ep.hostname, ep.status)}
                      className={`px-3 py-1.5 rounded text-xs font-bold transition-colors flex items-center gap-1 ${
                        ep.status === 'Isolated' ? 'bg-emerald-600/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-600/30' : 'bg-red-600/20 text-red-400 border border-red-500/30 hover:bg-red-600/30'
                      }`}
                    >
                      {ep.status === 'Isolated' ? <Unlock className="w-3.5 h-3.5" /> : <Lock className="w-3.5 h-3.5" />}
                      <span>{ep.status === 'Isolated' ? 'Release' : 'Isolate'}</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* -------------------- THREAT SIMULATION LAB VIEW -------------------- */}
        {activeTab === 'simulator' && (
          <div className="space-y-6 font-mono">
            <div className="bg-[#0B101D] border border-slate-800/80 p-4 rounded-lg flex justify-between items-center">
              <div>
                <h2 className="text-base font-bold text-white">Threat Simulation & Evaluation Lab</h2>
                <p className="text-xs text-slate-400 font-sans">Execute simulated attack vectors. Duplicate alerts for the same host are automatically appended to the active host incident.</p>
              </div>
              <button
                onClick={handleResetDemo}
                className="px-3 py-1.5 bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 text-xs rounded transition-colors flex items-center gap-1.5"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>Reset Demo Environment</span>
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {[
                {
                  id: 'brute-force',
                  title: 'Scenario 1: Brute Force Attack',
                  mitre: 'T1110 (Credential Access)',
                  source: 'Windows Event ID 4625',
                  desc: 'Triggers authentication failure alerts from remote IP 185.220.101.5 targeting service accounts on WIN-EP01.'
                },
                {
                  id: 'powershell',
                  title: 'Scenario 2: Suspicious Encoded PowerShell',
                  mitre: 'T1059.001 (Execution)',
                  source: 'Sysmon Event ID 1',
                  desc: 'Executes base64 encoded powershell payload on WIN-EP01 attempting reflective DLL loading.'
                },
                {
                  id: 'account-creation',
                  title: 'Scenario 3: Unauthorized Account Creation',
                  mitre: 'T1098 (Persistence)',
                  source: 'Windows Event ID 4720',
                  desc: 'Creates local administrator account test_admin via net user command on WIN-EP01.'
                },
                {
                  id: 'persistence',
                  title: 'Scenario 4: Scheduled Task Persistence',
                  mitre: 'T1053.005 (Persistence)',
                  source: 'Sysmon Event ID 1 / Event 4698',
                  desc: 'Registers malicious scheduled task executing payload on startup.'
                },
                {
                  id: 'correlated',
                  title: 'Scenario 5: Multi-Stage Campaign (FIN-LAPTOP04)',
                  mitre: 'T1110 -> T1059.001 -> T1053.005',
                  source: 'Correlation Engine',
                  desc: 'Executes full attack chain on FIN-LAPTOP04 (192.168.1.142) with remote C2 IP 198.51.100.42.'
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
                <h2 className="text-base font-bold text-white">Incident Reporting & Audit Export</h2>
                <p className="text-xs text-slate-400 font-sans">Generate comprehensive incident reports containing timeline evidence, response actions, and analyst notes.</p>
              </div>
            </div>

            <div className="bg-[#0B101D] border border-slate-800/80 rounded-lg p-6 space-y-6">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800/80 pb-4 gap-4">
                <div>
                  <h3 className="text-base font-bold text-white">{selectedIncident.title} ({selectedIncident.incident_id})</h3>
                  <p className="text-xs text-slate-400 mt-1">Asset: <strong className="text-cyan-400">{selectedIncident.affected_asset}</strong> | Status: <strong className="text-amber-300">{selectedIncident.status}</strong></p>
                </div>
                <button
                  onClick={() => {
                    const mdContent = `# SOC-X INCIDENT AUDIT REPORT
Incident ID: ${selectedIncident.incident_id}
Title: ${selectedIncident.title}
Severity: ${selectedIncident.severity}
Risk Score: ${selectedIncident.risk_score}/100
Affected Asset: ${selectedIncident.affected_asset}
Status: ${selectedIncident.status}
Assigned Analyst: ${selectedIncident.assigned_analyst || 'Analyst_1'}
MITRE ATT&CK Mappings: ${selectedIncident.mitre_mappings.join(', ')}
Report Timestamp: ${new Date().toISOString()}

## Executive Summary & Analyst Notes
${selectedIncident.notes}

## Response & Containment Actions Taken
${selectedIncident.response_action_taken || 'No containment action taken.'}

## Correlated Evidence Logs
${alerts
  .filter(a => selectedIncident.associated_alert_ids.includes(a.alert_id))
  .map(a => `- [${a.timestamp}] ${a.rule_name} (${a.mitre_technique}) from ${a.source_ip}: ${a.evidence_raw}`)
  .join('\n')}

## Audit Trail
${auditLogs.map(au => `- [${au.timestamp}] ${au.analyst_id}: ${au.details}`).join('\n')}
`;
                    const blob = new Blob([mdContent], { type: 'text/markdown' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `${selectedIncident.incident_id}_Report.md`;
                    a.click();
                  }}
                  className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs rounded transition-colors flex items-center gap-2 self-start sm:self-auto"
                >
                  <Download className="w-4 h-4" />
                  <span>Download Markdown Report</span>
                </button>
              </div>

              <div className="bg-[#070A12] p-6 rounded border border-slate-800 text-xs space-y-4 text-slate-300">
                <div className="text-cyan-400 font-bold text-sm"># SOC-X INCIDENT AUDIT REPORT: {selectedIncident.incident_id}</div>
                <div><strong>Title:</strong> {selectedIncident.title}</div>
                <div><strong>Severity:</strong> {selectedIncident.severity} | <strong>Risk Score:</strong> {selectedIncident.risk_score}/100</div>
                <div><strong>Affected Asset:</strong> {selectedIncident.affected_asset} | <strong>Status:</strong> {selectedIncident.status}</div>
                <div><strong>Assigned Analyst:</strong> {selectedIncident.assigned_analyst}</div>
                <div><strong>MITRE Mappings:</strong> {selectedIncident.mitre_mappings.join(', ')}</div>
                
                <div className="pt-2 border-t border-slate-900">
                  <div className="text-white font-bold mb-1">## Analyst Findings & Notes</div>
                  <p className="text-slate-400 font-sans">{selectedIncident.notes}</p>
                </div>

                <div className="pt-2 border-t border-slate-900">
                  <div className="text-white font-bold mb-1">## Response & Mitigation Actions Taken</div>
                  <p className="text-slate-400 font-sans">{selectedIncident.response_action_taken || 'Awaiting analyst containment.'}</p>
                </div>

                <div className="pt-2 border-t border-slate-900">
                  <div className="text-white font-bold mb-1">## Associated Evidence Artifacts</div>
                  <div className="space-y-1 text-slate-400 font-mono text-[11px]">
                    {alerts
                      .filter(a => selectedIncident.associated_alert_ids.includes(a.alert_id))
                      .map(a => (
                        <div key={a.alert_id} className="bg-[#090D16] p-2 rounded border border-slate-800">
                          <span className="text-cyan-300">[{a.alert_id}] {a.rule_name}</span> - {a.evidence_raw}
                        </div>
                      ))}
                  </div>
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
                  <span className="text-slate-500">Source Host:</span>
                  <div className="text-cyan-400">{selectedAlertForModal.source_host}</div>
                </div>
                <div>
                  <span className="text-slate-500">Source IP (Threat Intel):</span>
                  <button
                    onClick={() => { setSelectedAlertForModal(null); handleLookupThreatIntel(selectedAlertForModal.source_ip); }}
                    className="text-amber-300 hover:underline block font-bold"
                  >
                    {selectedAlertForModal.source_ip}
                  </button>
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

      {/* Threat Intelligence Inspector Modal */}
      {showIntelModal && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0B101D] border border-slate-800 rounded-lg max-w-lg w-full p-6 space-y-4 shadow-2xl font-mono">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-amber-400" />
                <h3 className="text-sm font-bold text-white">Threat Intelligence IP Inspector</h3>
              </div>
              <button onClick={() => setShowIntelModal(false)} className="text-slate-400 hover:text-white">✕</button>
            </div>

            {intelLoading ? (
              <div className="py-8 flex flex-col items-center justify-center gap-2 text-xs text-slate-400">
                <RefreshCw className="w-5 h-5 animate-spin text-amber-400" />
                <span>Querying threat intelligence feeds for {threatIntelIp}...</span>
              </div>
            ) : threatIntelData ? (
              <div className="space-y-4 text-xs">
                <div className="flex items-center justify-between bg-[#070A12] p-3 rounded border border-slate-800">
                  <div>
                    <span className="text-slate-500 block text-[10px]">Target IP Address</span>
                    <span className="text-sm font-bold text-white">{threatIntelData.ip}</span>
                  </div>
                  <span className={`px-2.5 py-1 rounded font-bold text-xs ${
                    threatIntelData.is_known_threat ? 'bg-red-500/15 text-red-400 border border-red-500/30' : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                  }`}>
                    {threatIntelData.is_known_threat ? `MALICIOUS (${threatIntelData.threat_score}/100)` : 'CLEAN / INTERNAL'}
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="bg-[#070A12] p-2.5 rounded border border-slate-800">
                    <span className="text-slate-500 block text-[10px]">Threat Actor / Network</span>
                    <span className="text-cyan-300 font-semibold">{threatIntelData.actor}</span>
                  </div>
                  <div className="bg-[#070A12] p-2.5 rounded border border-slate-800">
                    <span className="text-slate-500 block text-[10px]">Category</span>
                    <span className="text-white font-semibold">{threatIntelData.category}</span>
                  </div>
                  <div className="bg-[#070A12] p-2.5 rounded border border-slate-800">
                    <span className="text-slate-500 block text-[10px]">Country / ISP</span>
                    <span className="text-white">{threatIntelData.country} ({threatIntelData.isp})</span>
                  </div>
                  <div className="bg-[#070A12] p-2.5 rounded border border-slate-800">
                    <span className="text-slate-500 block text-[10px]">Confidence Level</span>
                    <span className="text-amber-300 font-semibold">{threatIntelData.confidence}</span>
                  </div>
                </div>

                <div className="bg-[#070A12] p-3 rounded border border-slate-800 space-y-1">
                  <span className="text-slate-500 text-[10px] block">Threat Intelligence Brief:</span>
                  <p className="text-slate-300 font-sans">{threatIntelData.details}</p>
                </div>
              </div>
            ) : null}

            <div className="pt-3 border-t border-slate-800/80 flex justify-end">
              <button
                onClick={() => setShowIntelModal(false)}
                className="px-4 py-2 bg-[#070A12] hover:bg-slate-800 text-white rounded text-xs transition-colors"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
