/**
 * CloudVPC Studio - VPC Flow Logs & Threat Analytics Dashboard
 * Visualizes 10,000+ network flow logs, bandwidth metrics, and security threat detection.
 */

window.VPCAnalytics = {
  activeTierFilter: '',
  activeActionFilter: '',
  searchQuery: '',

  init() {
    this.bindEvents();
    this.loadLogs();
  },

  bindEvents() {
    const searchInput = document.getElementById('log-search-input');
    const tierFilter = document.getElementById('log-tier-filter');
    const actionFilter = document.getElementById('log-action-filter');
    const regenBtn = document.getElementById('regen-logs-btn');

    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value;
        this.loadLogs();
      });
    }

    if (tierFilter) {
      tierFilter.addEventListener('change', (e) => {
        this.activeTierFilter = e.target.value;
        this.loadLogs();
      });
    }

    if (actionFilter) {
      actionFilter.addEventListener('change', (e) => {
        this.activeActionFilter = e.target.value;
        this.loadLogs();
      });
    }

    if (regenBtn) {
      regenBtn.addEventListener('click', () => this.regenerateDataset());
    }
  },

  render() {
    const summary = AppState.analyticsSummary;
    if (!summary) return;

    this.renderThreats(summary.security_threats || []);
    this.renderTierBars(summary.tier_summary || []);
    this.renderTopSources(summary.top_sources || []);
  },

  renderThreats(threats) {
    const container = document.getElementById('threat-feed-container');
    if (!container) return;

    if (threats.length === 0) {
      container.innerHTML = `<div style="color:var(--text-muted); font-size:0.85rem;">No security threats detected in dataset.</div>`;
      return;
    }

    let html = '';
    threats.forEach(t => {
      html += `
        <div class="threat-item">
          <div class="threat-item-left">
            <div class="threat-title">🚨 ${t.threat_name}</div>
            <div class="threat-sub">
              Targeted Ports: [${t.targeted_ports.join(', ')}] | Attackers: ${t.attacker_ips.join(', ')}
            </div>
            <div style="font-size:0.75rem; color:#10b981; margin-top:0.2rem;">
              Status: ${t.status} (Total Incidents: ${t.incident_count})
            </div>
          </div>
          <span class="threat-severity">${t.severity}</span>
        </div>
      `;
    });
    container.innerHTML = html;
  },

  renderTierBars(tiers) {
    const container = document.getElementById('tier-breakdown-container');
    if (!container) return;

    let html = '';
    const maxBytes = Math.max(...tiers.map(t => t.total_bytes), 1);

    tiers.forEach(tier => {
      const pct = Math.round((tier.total_bytes / maxBytes) * 100);
      const tierColor = tier.tier === 'Public' ? '#38bdf8' : (tier.tier === 'Application' ? '#10b981' : '#f59e0b');

      html += `
        <div style="margin-bottom: 1.25rem;">
          <div style="display:flex; justify-content:space-between; font-size:0.85rem; margin-bottom:0.35rem;">
            <span style="font-weight:600; color:${tierColor};">${tier.tier} Subnets</span>
            <span style="font-family:var(--font-mono); color:var(--text-secondary);">
              ${(tier.total_bytes / 1024 / 1024).toFixed(2)} MB (${tier.records} packets)
            </span>
          </div>
          <div style="height:8px; background:var(--bg-tertiary); border-radius:4px; overflow:hidden;">
            <div style="height:100%; width:${pct}%; background:${tierColor}; border-radius:4px;"></div>
          </div>
          <div style="display:flex; justify-content:space-between; font-size:0.75rem; color:var(--text-muted); margin-top:0.25rem;">
            <span>Accepted: ${tier.accepted}</span>
            <span>Rejected: <strong style="color:#f87171;">${tier.rejected} (${tier.reject_ratio}%)</strong></span>
          </div>
        </div>
      `;
    });
    container.innerHTML = html;
  },

  renderTopSources(sources) {
    const container = document.getElementById('top-sources-container');
    if (!container) return;

    let html = `
      <table class="mini-table" style="font-size:0.8rem;">
        <thead>
          <tr><th>Source IP Address</th><th>Volume</th><th>Threat Status</th></tr>
        </thead>
        <tbody>
    `;

    sources.forEach(s => {
      const volumeMB = (s.total_bytes / 1024 / 1024).toFixed(2);
      html += `
        <tr>
          <td style="font-family:var(--font-mono);">${s.ip}</td>
          <td>${volumeMB} MB</td>
          <td>
            ${s.is_threat ? 
              `<span style="color:#ef4444; font-weight:700;">MALICIOUS SCANNER</span>` : 
              `<span style="color:#10b981;">CLEAN INGRESS</span>`
            }
          </td>
        </tr>
      `;
    });

    html += `</tbody></table>`;
    container.innerHTML = html;
  },

  async loadLogs() {
    const tableBody = document.getElementById('flow-logs-tbody');
    if (!tableBody) return;

    tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:2rem; color:var(--text-muted);">Loading live VPC Flow Logs dataset...</td></tr>`;

    try {
      const params = new URLSearchParams();
      if (this.activeTierFilter) params.append('tier', this.activeTierFilter);
      if (this.activeActionFilter) params.append('action', this.activeActionFilter);
      if (this.searchQuery) params.append('search', this.searchQuery);
      params.append('limit', '100');

      const res = await fetch(`/api/flow-logs?${params.toString()}`);
      const data = await res.json();
      
      this.renderLogsTable(data.records || []);
    } catch (err) {
      console.error("Failed to fetch logs:", err);
      tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:#ef4444;">Error loading flow logs.</td></tr>`;
    }
  },

  renderLogsTable(records) {
    const tableBody = document.getElementById('flow-logs-tbody');
    if (!tableBody) return;

    if (records.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:2rem; color:var(--text-muted);">No records match the current filter criteria.</td></tr>`;
      return;
    }

    let html = '';
    records.forEach(r => {
      const isAccept = r.action === 'ACCEPT';
      const actionBadge = isAccept ? 
        `<span class="badge-action-accept">ACCEPT</span>` : 
        `<span class="badge-action-reject">REJECT</span>`;

      html += `
        <tr>
          <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted);">${r.timestamp_iso}</td>
          <td style="font-family:var(--font-mono);">${r.src_addr}:${r.src_port}</td>
          <td style="font-family:var(--font-mono);">${r.dst_addr}:${r.dst_port}</td>
          <td><span style="font-family:var(--font-mono);">${r.protocol_name}</span></td>
          <td>${(r.bytes / 1024).toFixed(1)} KB</td>
          <td>${actionBadge}</td>
          <td style="font-size:0.75rem; color:var(--text-secondary);">${r.scenario || 'Normal Traffic'}</td>
        </tr>
      `;
    });

    tableBody.innerHTML = html;
  },

  async regenerateDataset() {
    showToast("Regenerating 5,000 synthetic VPC flow logs...", "info");
    try {
      const res = await fetch('/api/generate-logs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ records: 6000 })
      });
      const data = await res.json();
      AppState.analyticsSummary = data.summary;
      this.render();
      this.loadLogs();
      updateQuickMetrics(data.summary);
      showToast("VPC Flow Logs Dataset Regenerated!", "success");
    } catch (err) {
      showToast("Failed to regenerate logs: " + err.message, "error");
    }
  }
};
