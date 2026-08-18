/**
 * CloudVPC Studio - Packet Tracer & Firewall Simulator
 * Simulates network packet paths across Route Tables, NACLs, and Security Groups.
 */

window.VPCSimulator = {
  init() {
    this.bindEvents();
    this.loadPresetScenario('legit_https');
  },

  bindEvents() {
    const runBtn = document.getElementById('run-simulation-btn');
    const presetSelect = document.getElementById('sim-preset-scenario');

    if (runBtn) {
      runBtn.addEventListener('click', () => this.executeSimulation());
    }

    if (presetSelect) {
      presetSelect.addEventListener('change', (e) => this.loadPresetScenario(e.target.value));
    }
  },

  loadPresetScenario(scenarioKey) {
    const srcSelect = document.getElementById('sim-source');
    const dstSelect = document.getElementById('sim-destination');
    const portInput = document.getElementById('sim-port');
    const protoSelect = document.getElementById('sim-protocol');
    const srcIpInput = document.getElementById('sim-source-ip');

    const presets = {
      legit_https: {
        source: 'internet',
        sourceIp: '203.0.113.15',
        dest: 'alb',
        port: 443,
        proto: 'TCP'
      },
      direct_db_attack: {
        source: 'malicious_ip',
        sourceIp: '185.220.101.5',
        dest: 'database',
        port: 5432,
        proto: 'TCP'
      },
      app_to_db: {
        source: 'app_node',
        sourceIp: '10.0.10.45',
        dest: 'database',
        port: 5432,
        proto: 'TCP'
      },
      ssh_attack: {
        source: 'malicious_ip',
        sourceIp: '45.155.205.233',
        dest: 'app_node',
        port: 22,
        proto: 'TCP'
      },
      bastion_ssh: {
        source: 'bastion',
        sourceIp: '10.0.1.200',
        dest: 'app_node',
        port: 22,
        proto: 'TCP'
      },
      app_egress_nat: {
        source: 'app_node',
        sourceIp: '10.0.10.45',
        dest: 'external_api',
        port: 443,
        proto: 'TCP'
      }
    };

    const config = presets[scenarioKey];
    if (config) {
      if (srcSelect) srcSelect.value = config.source;
      if (srcIpInput) srcIpInput.value = config.sourceIp;
      if (dstSelect) dstSelect.value = config.dest;
      if (portInput) portInput.value = config.port;
      if (protoSelect) protoSelect.value = config.proto;
      this.executeSimulation();
    }
  },

  async executeSimulation() {
    const srcSelect = document.getElementById('sim-source');
    const dstSelect = document.getElementById('sim-destination');
    const portInput = document.getElementById('sim-port');
    const protoSelect = document.getElementById('sim-protocol');
    const srcIpInput = document.getElementById('sim-source-ip');
    const outputContainer = document.getElementById('sim-results-container');

    if (!srcSelect || !dstSelect || !portInput) return;

    const payload = {
      source: srcSelect.value,
      source_ip: srcIpInput ? srcIpInput.value : '203.0.113.15',
      destination: dstSelect.value,
      port: parseInt(portInput.value, 10),
      protocol: protoSelect ? protoSelect.value : 'TCP'
    };

    if (outputContainer) {
      outputContainer.innerHTML = `
        <div style="text-align:center; padding: 3rem;">
          <div class="status-indicator" style="display:inline-block; margin-bottom:1rem;"></div>
          <div>Simulating Packet Inspection & Hop Routing...</div>
        </div>
      `;
    }

    try {
      const res = await fetch('/api/simulate-packet', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      this.renderSimulationResults(data);
    } catch (err) {
      console.error("Simulation error:", err);
      if (outputContainer) {
        outputContainer.innerHTML = `<div class="sim-verdict-banner drop">Simulation Failed: ${err.message}</div>`;
      }
    }
  },

  renderSimulationResults(data) {
    const container = document.getElementById('sim-results-container');
    if (!container) return;

    const isAllowed = data.verdict === 'ALLOW';

    let html = `
      <div class="sim-verdict-banner ${isAllowed ? 'allow' : 'drop'}">
        <div class="verdict-title">
          ${isAllowed ? `
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
            <span>PACKET ALLOWED (STATUS 200 OK)</span>
          ` : `
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>
            <span>PACKET DROPPED / BLOCKED (FIREWALL REJECT)</span>
          `}
        </div>
        <div style="font-size: 0.85rem; font-weight: 600;">Hops Evaluated: ${data.hop_count}</div>
      </div>
    `;

    if (data.drop_reason) {
      html += `
        <div style="background: rgba(239, 68, 68, 0.08); border-left: 4px solid #ef4444; padding: 1rem; border-radius: 4px; margin-bottom: 1.5rem;">
          <div style="font-weight: 700; color: #f87171; font-size: 0.85rem;">REJECTION RATIONALE</div>
          <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.25rem;">${data.drop_reason}</div>
        </div>
      `;
    }

    html += `
      <div style="font-family: var(--font-heading); font-size: 1rem; font-weight: 700; margin-bottom: 1rem;">
        Packet Traversal Trace & Rule Evaluations:
      </div>
      <div class="hops-timeline">
    `;

    data.hops.forEach(hop => {
      const isDrop = hop.action === 'DROP';
      const isAllow = hop.action === 'ALLOW' || hop.action === 'SUCCESS';
      const badgeClass = isDrop ? 'drop' : (isAllow ? 'allow' : 'forward');

      html += `
        <div class="hop-item">
          <div class="hop-dot ${badgeClass}"></div>
          <div class="hop-header">
            <div class="hop-node-name">Hop ${hop.hop_number}: ${hop.node}</div>
            <span class="hop-badge ${badgeClass}">${hop.action}</span>
          </div>
          <div class="hop-detail">${hop.detail}</div>
          ${hop.rule_matched ? `<div class="hop-rule">Rule Matched: ${hop.rule_matched}</div>` : ''}
        </div>
      `;
    });

    html += `</div>`;
    container.innerHTML = html;
  }
};
