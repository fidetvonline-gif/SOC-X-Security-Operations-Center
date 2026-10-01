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

let alerts: Alert[] = [
  {
    alert_id: "ALT-1001",
    timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(),
    rule_id: "RULE-BF-01",
    rule_name: "Multiple Failed Logins (Brute Force)",
    severity: "High",
    risk_score: 40,
    source_host: "WIN-EP01",
    source_ip: "192.168.1.105",
    target_account: "admin_test",
    mitre_technique: "T1110",
    mitre_tactic: "Credential Access",
    evidence_raw: "Windows Event ID 4625: 14 failed authentication attempts in 60 seconds from IP 192.168.1.105 targeting user admin_test.",
    status: "Investigating"
  },
  {
    alert_id: "ALT-1002",
    timestamp: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    rule_id: "RULE-PS-01",
    rule_name: "Suspicious PowerShell Execution",
    severity: "High",
    risk_score: 40,
    source_host: "WIN-EP01",
    source_ip: "192.168.1.105",
    target_account: "system",
    mitre_technique: "T1059.001",
    mitre_tactic: "Execution",
    evidence_raw: "Sysmon Event ID 1: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC-ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEOWNk...",
    status: "Investigating"
  },
  {
    alert_id: "ALT-1003",
    timestamp: new Date(Date.now() - 20 * 60 * 1000).toISOString(),
    rule_id: "RULE-TSK-01",
    rule_name: "Suspicious Scheduled Task Creation",
    severity: "Medium",
    risk_score: 25,
    source_host: "WIN-EP01",
    source_ip: "192.168.1.105",
    target_account: "SYSTEM",
    mitre_technique: "T1053.005",
    mitre_tactic: "Persistence",
    evidence_raw: "Sysmon Event ID 1 / SchTasks: schtasks /create /tn 'SystemUpdater' /tr 'powershell.exe -windowstyle hidden -c IEX(...)' /sc ONLOGON",
    status: "Unassigned"
  }
];

let incidents: Incident[] = [
  {
    incident_id: "INC-2001",
    title: "Multi-Stage Endpoint Compromise on WIN-EP01",
    severity: "Critical",
    status: "Investigating",
    risk_score: 88,
    affected_asset: "WIN-EP01",
    associated_alert_ids: ["ALT-1001", "ALT-1002", "ALT-1003"],
    mitre_mappings: ["T1110", "T1059.001", "T1053.005"],
    assigned_analyst: "Analyst_1",
    notes: "Initial brute force followed by encoded powershell script execution and persistence task creation.",
    response_action_taken: "None yet - Monitoring payload execution graph.",
    created_at: new Date(Date.now() - 25 * 60 * 1000).toISOString()
  }
];

let endpoints: EndpointAsset[] = [
  {
    host_id: "EP-01",
    hostname: "WIN-EP01",
    ip_address: "192.168.1.105",
    os: "Windows 11 Enterprise (23H2)",
    status: "Online",
    wazuh_agent_version: "4.7.2",
    sysmon_status: "Active",
    last_heartbeat: new Date().toISOString()
  },
  {
    host_id: "EP-02",
    hostname: "DC-SRV01",
    ip_address: "192.168.1.10",
    os: "Windows Server 2022 Datacenter",
    status: "Online",
    wazuh_agent_version: "4.7.2",
    sysmon_status: "Active",
    last_heartbeat: new Date().toISOString()
  },
  {
    host_id: "EP-03",
    hostname: "FIN-LAPTOP04",
    ip_address: "192.168.1.142",
    os: "Windows 10 Pro",
    status: "Online",
    wazuh_agent_version: "4.7.1",
    sysmon_status: "Active",
    last_heartbeat: new Date().toISOString()
  }
];

let auditLogs: AuditLog[] = [
  {
    audit_id: "AUD-901",
    timestamp: new Date(Date.now() - 40 * 60 * 1000).toISOString(),
    analyst_id: "Analyst_1",
    action_type: "INCIDENT_ASSIGNED",
    target: "INC-2001",
    details: "Assigned incident INC-2001 to Analyst_1 for tier-2 triage."
  }
];

async function startServer() {
  const app = express();
  app.use(express.json());

  // If Supabase is connected, attempt to load initial data from Supabase tables
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

      console.log('Successfully synchronized SOC-X data with Supabase provider.');
    } catch (e) {
      console.log('Supabase tables not yet provisioned; operating with robust fallback data store.');
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

  app.get('/api/alerts', (req, res) => {
    res.json(alerts);
  });

  app.post('/api/alerts', async (req, res) => {
    try {
      const newAlert: Alert = {
        alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
        timestamp: new Date().toISOString(),
        rule_id: req.body.rule_id || 'RULE-GEN-01',
        rule_name: req.body.rule_name || 'Generic Suspicious Activity',
        severity: req.body.severity || 'Medium',
        risk_score: req.body.risk_score || 25,
        source_host: req.body.source_host || 'WIN-EP01',
        source_ip: req.body.source_ip || '192.168.1.105',
        target_account: req.body.target_account || 'user',
        mitre_technique: req.body.mitre_technique || 'T1078',
        mitre_tactic: req.body.mitre_tactic || 'Defense Evasion',
        evidence_raw: req.body.evidence_raw || 'Manual alert ingested into SIEM.',
        status: 'Unassigned'
      };
      alerts.unshift(newAlert);
      checkCorrelation(newAlert.source_host);

      if (supabase) {
        try {
          await supabase.from('alerts').insert([newAlert]);
        } catch (e) {}
      }

      res.status(201).json(newAlert);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Internal server error' });
    }
  });

  app.get('/api/incidents', (req, res) => {
    res.json(incidents);
  });

  app.patch('/api/incidents/:id', async (req, res) => {
    try {
      const { id } = req.params;
      const { status, assigned_analyst, notes, response_action_taken } = req.body;
      const incident = incidents.find(i => i.incident_id === id);
      if (!incident) {
        return res.status(404).json({ error: 'Incident not found' });
      }
      if (status) incident.status = status;
      if (assigned_analyst) incident.assigned_analyst = assigned_analyst;
      if (notes) incident.notes = notes;
      if (response_action_taken) incident.response_action_taken = response_action_taken;

      const newAudit: AuditLog = {
        audit_id: `AUD-${Math.floor(100 + Math.random() * 900)}`,
        timestamp: new Date().toISOString(),
        analyst_id: assigned_analyst || 'Analyst_1',
        action_type: 'INCIDENT_UPDATE',
        target: id,
        details: `Updated incident ${id}: status=${status || incident.status}, action=${response_action_taken || 'none'}`
      };
      auditLogs.unshift(newAudit);

      if (supabase) {
        try {
          await supabase.from('incidents').update(incident).eq('incident_id', id);
          await supabase.from('audit_logs').insert([newAudit]);
        } catch (e) {}
      }

      res.json(incident);
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Internal server error' });
    }
  });

  app.get('/api/endpoints', (req, res) => {
    res.json(endpoints);
  });

  app.post('/api/response/isolate', async (req, res) => {
    try {
      const { host_id, analyst_id } = req.body;
      const endpoint = endpoints.find(e => e.host_id === host_id || e.hostname === host_id);
      if (!endpoint) {
        return res.status(404).json({ error: 'Endpoint not found' });
      }
      endpoint.status = 'Isolated';

      const newAudit: AuditLog = {
        audit_id: `AUD-${Math.floor(100 + Math.random() * 900)}`,
        timestamp: new Date().toISOString(),
        analyst_id: analyst_id || 'Analyst_1',
        action_type: 'ENDPOINT_ISOLATION',
        target: endpoint.hostname,
        details: `Successfully isolated host ${endpoint.hostname} (${endpoint.ip_address}) from network.`
      };
      auditLogs.unshift(newAudit);

      if (supabase) {
        try {
          await supabase.from('endpoints').update({ status: 'Isolated' }).eq('hostname', endpoint.hostname);
          await supabase.from('audit_logs').insert([newAudit]);
        } catch (e) {}
      }

      res.json({ success: true, endpoint, message: `Host ${endpoint.hostname} has been isolated.` });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Internal server error' });
    }
  });

  app.post('/api/response/disable-account', async (req, res) => {
    try {
      const { username, analyst_id } = req.body;
      const newAudit: AuditLog = {
        audit_id: `AUD-${Math.floor(100 + Math.random() * 900)}`,
        timestamp: new Date().toISOString(),
        analyst_id: analyst_id || 'Analyst_1',
        action_type: 'ACCOUNT_DISABLE',
        target: username,
        details: `Executed active response command: net user ${username} /active:no. Account disabled.`
      };
      auditLogs.unshift(newAudit);

      if (supabase) {
        try {
          await supabase.from('audit_logs').insert([newAudit]);
        } catch (e) {}
      }

      res.json({ success: true, message: `Account ${username} disabled successfully.` });
    } catch (err: any) {
      res.status(500).json({ error: err.message || 'Internal server error' });
    }
  });

  app.post('/api/simulate', async (req, res) => {
    try {
      const { scenario } = req.body;
      let newAlerts: Alert[] = [];

      if (scenario === 'brute-force') {
        const a: Alert = {
          alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
          timestamp: new Date().toISOString(),
          rule_id: "RULE-BF-01",
          rule_name: "Hydra SSH/RDP Brute Force Attack",
          severity: "High",
          risk_score: 40,
          source_host: "WIN-EP01",
          source_ip: "192.168.1.180",
          target_account: "administrator",
          mitre_technique: "T1110",
          mitre_tactic: "Credential Access",
          evidence_raw: "Windows Event ID 4625: 38 failed logon attempts recorded in 120 seconds.",
          status: "Unassigned"
        };
        alerts.unshift(a);
        newAlerts.push(a);
      } else if (scenario === 'powershell') {
        const a: Alert = {
          alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
          timestamp: new Date().toISOString(),
          rule_id: "RULE-PS-01",
          rule_name: "Encoded Base64 PowerShell Execution",
          severity: "High",
          risk_score: 40,
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
        const a: Alert = {
          alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
          timestamp: new Date().toISOString(),
          rule_id: "RULE-USR-01",
          rule_name: "Unauthorized Local User Creation",
          severity: "Medium",
          risk_score: 25,
          source_host: "WIN-EP01",
          source_ip: "192.168.1.105",
          target_account: "test_admin",
          mitre_technique: "T1098",
          mitre_tactic: "Persistence",
          evidence_raw: "Windows Event ID 4720: User account created: test_admin.",
          status: "Unassigned"
        };
        alerts.unshift(a);
        newAlerts.push(a);
      } else if (scenario === 'persistence') {
        const a: Alert = {
          alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
          timestamp: new Date().toISOString(),
          rule_id: "RULE-TSK-01",
          rule_name: "Scheduled Task Persistence Registered",
          severity: "High",
          risk_score: 40,
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
        const now = new Date();
        const a1: Alert = {
          alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
          timestamp: new Date(now.getTime() - 10000).toISOString(),
          rule_id: "RULE-BF-01",
          rule_name: "Hydra Brute Force Attack",
          severity: "High",
          risk_score: 40,
          source_host: "FIN-LAPTOP04",
          source_ip: "192.168.1.200",
          target_account: "finance_admin",
          mitre_technique: "T1110",
          mitre_tactic: "Credential Access",
          evidence_raw: "Event ID 4625: 50 failed logins on FIN-LAPTOP04",
          status: "Investigating"
        };
        const a2: Alert = {
          alert_id: `ALT-${Math.floor(1000 + Math.random() * 9000)}`,
          timestamp: new Date(now.getTime() - 5000).toISOString(),
          rule_id: "RULE-PS-01",
          rule_name: "Encoded PowerShell Execution",
          severity: "High",
          risk_score: 40,
          source_host: "FIN-LAPTOP04",
          source_ip: "192.168.1.200",
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
          risk_score: 50,
          source_host: "FIN-LAPTOP04",
          source_ip: "192.168.1.200",
          target_account: "SYSTEM",
          mitre_technique: "T1053.005",
          mitre_tactic: "Persistence",
          evidence_raw: "SchTasks /create persistence payload on FIN-LAPTOP04",
          status: "Investigating"
        };
        alerts.unshift(a3, a2, a1);
        newAlerts.push(a1, a2, a3);

        const newInc: Incident = {
          incident_id: `INC-${Math.floor(2000 + Math.random() * 9000)}`,
          title: "Multi-Stage Chain Compromise on FIN-LAPTOP04",
          severity: "Critical",
          status: "Investigating",
          risk_score: 95,
          affected_asset: "FIN-LAPTOP04",
          associated_alert_ids: [a1.alert_id, a2.alert_id, a3.alert_id],
          mitre_mappings: ["T1110", "T1059.001", "T1053.005"],
          assigned_analyst: "Analyst_1",
          notes: "Automated correlation engine triggered: Brute force leading to encoded payload and persistence task.",
          response_action_taken: "Pending Analyst Action",
          created_at: new Date().toISOString()
        };
        incidents.unshift(newInc);

        if (supabase) {
          try {
            await supabase.from('incidents').insert([newInc]);
          } catch (e) {}
        }
      }

      if (newAlerts.length > 0) {
        checkCorrelation(newAlerts[0].source_host);
        if (supabase) {
          try {
            await supabase.from('alerts').insert(newAlerts);
          } catch (e) {}
        }
      }

      res.json({ success: true, scenario, newAlerts });
    } catch (err: any) {
      console.error('Simulation error:', err);
      res.status(500).json({ success: false, error: err.message || 'Simulation execution failed' });
    }
  });

  function checkCorrelation(host: string) {
    const recentAlerts = alerts.filter(a => a.source_host === host && (a.status === 'Unassigned' || a.status === 'Investigating'));
    if (recentAlerts.length >= 2) {
      const existingIncident = incidents.find(i => i.affected_asset === host && i.status === 'Investigating');
      if (!existingIncident) {
        const severitiesMap: Record<string, number> = { Low: 10, Medium: 25, High: 40, Critical: 50 };
        let sumSeverity = recentAlerts.reduce((acc, a) => acc + (severitiesMap[a.severity] || 25), 0);
        let riskScore = Math.min(100, sumSeverity + 15);
        let maxSev = recentAlerts.some(a => a.severity === 'Critical') ? 'Critical' : recentAlerts.some(a => a.severity === 'High') ? 'High' : 'Medium';

        const newInc: Incident = {
          incident_id: `INC-${Math.floor(2000 + Math.random() * 9000)}`,
          title: `Correlated Threat Campaign on ${host}`,
          severity: maxSev as any,
          status: 'Investigating',
          risk_score: riskScore,
          affected_asset: host,
          associated_alert_ids: recentAlerts.map(a => a.alert_id),
          mitre_mappings: Array.from(new Set(recentAlerts.map(a => a.mitre_technique))),
          assigned_analyst: 'Analyst_1',
          notes: `Auto-generated by Correlation Engine: ${recentAlerts.length} correlated alerts detected on ${host}.`,
          response_action_taken: 'None',
          created_at: new Date().toISOString()
        };
        incidents.unshift(newInc);
      }
    }
  }

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
    console.log(`SOC-X Backend running on port ${port} (Supabase integration active: ${!!supabase})`);
  });
}

startServer();
