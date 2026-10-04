import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Initialize Supabase client if configured
const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.VITE_SUPABASE_ANON_KEY;
const supabase = (supabaseUrl && supabaseKey && supabaseUrl !== 'https://placeholder.supabase.co')
  ? createClient(supabaseUrl, supabaseKey)
  : null;

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

// Standardized Asset IP Mapping across the entire platform
const ASSET_IPS: Record<string, string> = {
  'WIN-EP01': '192.168.1.105',
  'DC-SRV01': '192.168.1.10',
  'FIN-LAPTOP04': '192.168.1.142'
};

const ASSET_CRITICALITY_SCORES: Record<string, number> = {
  'DC-SRV01': 95,
  'FIN-LAPTOP04': 80,
  'WIN-EP01': 60
};

// Default Baseline Endpoints (All ONLINE by default)
const getInitialEndpoints = (): EndpointAsset[] => [
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

// Default Initial Baseline Alerts
const getInitialAlerts = (): Alert[] => [
  {
    alert_id: "ALT-1001",
    timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
    rule_id: "RULE-BF-01",
    rule_name: "Multiple Failed Logins (Brute Force)",
    severity: "High",
    risk_score: 40,
    source_host: "WIN-EP01",
    source_ip: "185.220.101.5", // Standardized external attacker IP
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

const calculateRiskScore = (
  severity: 'Low' | 'Medium' | 'High' | 'Critical',
  host: string,
  alertCount: number,
  isExternalThreat: boolean
) => {
  const sevMap = { Low: 25, Medium: 45, High: 75, Critical: 95 };
  const sevFactor = sevMap[severity] || 45;
  const assetFactor = ASSET_CRITICALITY_SCORES[host] || 60;
  const confidenceScore = Math.min(95, 70 + (alertCount * 8));
  const threatIntelScore = isExternalThreat ? 90 : 35;

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

const getInitialIncidents = (): Incident[] => {
  const calc = calculateRiskScore('High', 'WIN-EP01', 2, true);
  return [
    {
      incident_id: "INC-2001",
      title: "Suspicious Brute Force & PowerShell Execution on WIN-EP01",
      severity: "High",
      status: "Investigating",
      risk_score: calc.score,
      risk_breakdown: calc.breakdown,
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
};

let alerts: Alert[] = getInitialAlerts();
let incidents: Incident[] = getInitialIncidents();
let endpoints: EndpointAsset[] = getInitialEndpoints();
let auditLogs: AuditLog[] = []; // Starts COMPLETELY EMPTY as requested

async function startServer() {
  const app = express();
  app.use(express.json());

  // Attempt initial Supabase load if available
  if (supabase) {
    try {
      const { data: sbAlerts } = await supabase.from('alerts').select('*');
      if (sbAlerts && sbAlerts.length > 0) alerts = sbAlerts;

      const { data: sbIncidents } = await supabase.from('incidents').select('*');
      if (sbIncidents && sbIncidents.length > 0) incidents = sbIncidents;

      const { data: sbEndpoints } = await supabase.from('endpoints').select('*');
      if (sbEndpoints && sbEndpoints.length > 0) endpoints = sbEndpoints;

      const { data: sbAudits } = await supabase.from('audit_logs').select('*');
      if (sbAudits && sbAudits.length > 0) auditLogs = sbAudits;
    } catch (e) {
      console.log('Operating with local in-memory SOC store.');
    }
  }

  // API Routes
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      supabase_connected: !!supabase,
      timestamp: new Date().toISOString()
    });
  });

  app.get('/api/data', (req, res) => {
    res.json({
      alerts,
      incidents,
      endpoints,
      auditLogs,
      supabaseConfigured: !!supabase
    });
  });

  // Reset Demo API to clear all dynamic state before student presentation
  app.post('/api/reset', async (req, res) => {
    alerts = getInitialAlerts();
    incidents = getInitialIncidents();
    endpoints = getInitialEndpoints();
    auditLogs = [];

    res.json({ success: true, message: 'SOC-X Demo environment reset to initial clean state.' });
  });

  // Threat Intel IP Lookup API
  app.get('/api/threat-intel/:ip', (req, res) => {
    const { ip } = req.params;
    
    if (ip === '185.220.101.5') {
      return res.json({
        ip,
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
    }

    if (ip === '198.51.100.42') {
      return res.json({
        ip,
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
    }

    if (ip.startsWith('192.168.')) {
      return res.json({
        ip,
        is_known_threat: false,
        threat_score: 5,
        confidence: 'High (99%)',
        actor: 'Internal Corporate Network',
        category: 'Local Subnet Endpoint',
        country: 'LAN',
        isp: 'Internal DHCP Gateway',
        last_seen: 'Current Session',
        details: 'Private RFC1918 address space. No external threat reputation alerts.'
      });
    }

    return res.json({
      ip,
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
  });

  // Incident Lifecycle Management APIs
  app.post('/api/incidents/:id/assign', async (req, res) => {
    const { id } = req.params;
    const { analyst_id } = req.body;
    const incident = incidents.find(i => i.incident_id === id);
    if (!incident) return res.status(404).json({ error: 'Incident not found' });

    incident.assigned_analyst = analyst_id || 'Analyst_1';
    if (incident.status === 'New') incident.status = 'Investigating';
    incident.updated_at = new Date().toISOString();

    const audit: AuditLog = {
      audit_id: `AUD-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      analyst_id: analyst_id || 'Analyst_1',
      action_type: 'INCIDENT_ASSIGNMENT',
      target: id,
      details: `Assigned incident ${id} to ${incident.assigned_analyst}. Status changed to ${incident.status}.`
    };
    auditLogs.unshift(audit);

    res.json({ success: true, incident, audit });
  });

  app.post('/api/incidents/:id/status', async (req, res) => {
    const { id } = req.params;
    const { status, notes, analyst_id, response_action } = req.body;
    const incident = incidents.find(i => i.incident_id === id);
    if (!incident) return res.status(404).json({ error: 'Incident not found' });

    if (status) incident.status = status;
    if (notes) incident.notes = notes;
    if (response_action) incident.response_action_taken = response_action;
    incident.updated_at = new Date().toISOString();

    const audit: AuditLog = {
      audit_id: `AUD-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      analyst_id: analyst_id || incident.assigned_analyst || 'Analyst_1',
      action_type: `STATUS_UPDATE_${status}`,
      target: id,
      details: `Updated status of ${id} to [${status}]. Response note: ${notes || response_action || 'N/A'}`
    };
    auditLogs.unshift(audit);

    res.json({ success: true, incident, audit });
  });

  // Endpoint Isolation / Release APIs
  app.post('/api/response/isolate', async (req, res) => {
    const { host_id, analyst_id } = req.body;
    const endpoint = endpoints.find(e => e.host_id === host_id || e.hostname === host_id);
    if (!endpoint) return res.status(404).json({ error: 'Endpoint not found' });

    endpoint.status = 'Isolated';
    endpoint.last_heartbeat = new Date().toISOString();

    const audit: AuditLog = {
      audit_id: `AUD-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      analyst_id: analyst_id || 'Analyst_1',
      action_type: 'ENDPOINT_ISOLATION',
      target: endpoint.hostname,
      details: `Network isolation rule applied to ${endpoint.hostname} (${endpoint.ip_address}). Non-SOC traffic blocked.`
    };
    auditLogs.unshift(audit);

    res.json({ success: true, endpoint, message: `Host ${endpoint.hostname} has been isolated.` });
  });

  app.post('/api/response/release-isolation', async (req, res) => {
    const { host_id, analyst_id } = req.body;
    const endpoint = endpoints.find(e => e.host_id === host_id || e.hostname === host_id);
    if (!endpoint) return res.status(404).json({ error: 'Endpoint not found' });

    endpoint.status = 'Online';
    endpoint.last_heartbeat = new Date().toISOString();

    const audit: AuditLog = {
      audit_id: `AUD-${Math.floor(1000 + Math.random() * 9000)}`,
      timestamp: new Date().toISOString(),
      analyst_id: analyst_id || 'Analyst_1',
      action_type: 'ENDPOINT_RELEASE',
      target: endpoint.hostname,
      details: `Network isolation removed for ${endpoint.hostname} (${endpoint.ip_address}). Normal network connectivity restored.`
    };
    auditLogs.unshift(audit);

    res.json({ success: true, endpoint, message: `Host ${endpoint.hostname} network isolation released.` });
  });

  // Threat Simulation API with Incident Deduplication Logic
  app.post('/api/simulate', async (req, res) => {
    try {
      const { scenario } = req.body;
      let newAlerts: Alert[] = [];
      let targetHost = "WIN-EP01";

      if (scenario === 'brute-force') {
        targetHost = "WIN-EP01";
        const a: Alert = {
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
        };
        alerts.unshift(a);
        newAlerts.push(a);
      } else if (scenario === 'powershell') {
        targetHost = "WIN-EP01";
        const a: Alert = {
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
        };
        alerts.unshift(a);
        newAlerts.push(a);
      } else if (scenario === 'account-creation') {
        targetHost = "WIN-EP01";
        const a: Alert = {
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
        };
        alerts.unshift(a);
        newAlerts.push(a);
      } else if (scenario === 'persistence') {
        targetHost = "WIN-EP01";
        const a: Alert = {
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
        };
        alerts.unshift(a);
        newAlerts.push(a);
      } else if (scenario === 'correlated') {
        targetHost = "FIN-LAPTOP04";
        const now = new Date();
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
        alerts.unshift(a3, a2, a1);
        newAlerts.push(a1, a2, a3);
      }

      // INCIDENT DEDUPLICATION LOGIC:
      // Search for an open incident on the target host (not closed)
      let activeInc = incidents.find(i => i.affected_asset === targetHost && i.status !== 'Closed');

      if (activeInc) {
        // Update existing incident instead of creating a duplicate!
        newAlerts.forEach(a => {
          if (!activeInc!.associated_alert_ids.includes(a.alert_id)) {
            activeInc!.associated_alert_ids.push(a.alert_id);
          }
          if (!activeInc!.mitre_mappings.includes(a.mitre_technique)) {
            activeInc!.mitre_mappings.push(a.mitre_technique);
          }
        });

        const maxSeverity = newAlerts.some(a => a.severity === 'Critical') ? 'Critical' :
          activeInc.severity === 'Critical' ? 'Critical' :
          newAlerts.some(a => a.severity === 'High') ? 'High' : activeInc.severity;

        const isExt = newAlerts.some(a => a.source_ip === '185.220.101.5' || a.source_ip === '198.51.100.42');
        const calc = calculateRiskScore(maxSeverity as any, targetHost, activeInc.associated_alert_ids.length, isExt);

        activeInc.severity = maxSeverity as any;
        activeInc.risk_score = calc.score;
        activeInc.risk_breakdown = calc.breakdown;
        activeInc.notes = `Updated with ${newAlerts.length} new telemetry event(s) from scenario [${scenario}]. Total correlated alerts: ${activeInc.associated_alert_ids.length}.`;
        activeInc.updated_at = new Date().toISOString();
      } else {
        // Create new single incident if none active
        const isExt = newAlerts.some(a => a.source_ip === '185.220.101.5' || a.source_ip === '198.51.100.42');
        const maxSev = newAlerts.some(a => a.severity === 'Critical') ? 'Critical' :
          newAlerts.some(a => a.severity === 'High') ? 'High' : 'Medium';

        const calc = calculateRiskScore(maxSev as any, targetHost, newAlerts.length, isExt);

        activeInc = {
          incident_id: `INC-${Math.floor(2000 + Math.random() * 9000)}`,
          title: `Active Threat Campaign on ${targetHost}`,
          severity: maxSev as any,
          status: 'New',
          risk_score: calc.score,
          risk_breakdown: calc.breakdown,
          affected_asset: targetHost,
          associated_alert_ids: newAlerts.map(a => a.alert_id),
          mitre_mappings: Array.from(new Set(newAlerts.map(a => a.mitre_technique))),
          assigned_analyst: 'Unassigned',
          notes: `Triggered scenario [${scenario}]: ${newAlerts.length} initial correlated telemetry logs.`,
          response_action_taken: 'Pending Analyst Investigation',
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        };
        incidents.unshift(activeInc);
      }

      res.json({ success: true, scenario, incident: activeInc, newAlerts });
    } catch (err: any) {
      console.error('Simulation error:', err);
      res.status(500).json({ success: false, error: err.message || 'Simulation execution failed' });
    }
  });

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`SOC-X Academic Server running on port ${port}`);
  });
}

startServer();
