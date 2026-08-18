/**
 * CloudVPC Studio - CIDR Subnetting Calculator & IP Visualizer
 * Calculates subnet splits, usable IP address ranges, and AWS/Azure reserved IPs.
 */

window.VPCCalculator = {
  init() {
    this.bindEvents();
    this.calculate();
  },

  bindEvents() {
    const calcBtn = document.getElementById('calc-run-btn');
    const vpcCidrInput = document.getElementById('calc-vpc-cidr');
    const maskSelect = document.getElementById('calc-subnet-mask');
    const azSelect = document.getElementById('calc-num-azs');

    if (calcBtn) {
      calcBtn.addEventListener('click', () => this.calculate());
    }
    if (maskSelect) {
      maskSelect.addEventListener('change', () => this.calculate());
    }
    if (azSelect) {
      azSelect.addEventListener('change', () => this.calculate());
    }
  },

  async calculate() {
    const vpcCidr = document.getElementById('calc-vpc-cidr').value || '10.0.0.0/16';
    const mask = document.getElementById('calc-subnet-mask').value || '24';
    const numAzs = document.getElementById('calc-num-azs').value || '2';
    const container = document.getElementById('cidr-results-container');

    if (container) {
      container.innerHTML = `<div style="text-align:center; padding:2rem; color:var(--text-muted);">Calculating IP Allocation Matrix...</div>`;
    }

    try {
      const res = await fetch('/api/cidr-calculate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vpc_cidr: vpcCidr,
          subnet_mask: parseInt(mask, 10),
          num_azs: parseInt(numAzs, 10)
        })
      });
      const data = await res.json();
      this.renderResults(data);
    } catch (err) {
      console.error("CIDR calculation error:", err);
    }
  },

  renderResults(data) {
    const container = document.getElementById('cidr-results-container');
    if (!container) return;

    if (data.error) {
      container.innerHTML = `<div class="sim-verdict-banner drop">CIDR Calculation Error: ${data.error}</div>`;
      return;
    }

    let html = `
      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap:1rem; margin-bottom:1.5rem;">
        <div class="card" style="margin-bottom:0; padding:1rem;">
          <div style="font-size:0.75rem; color:var(--text-muted); text-transform:uppercase;">VPC Total Address Space</div>
          <div style="font-size:1.4rem; font-weight:800; color:#818cf8; font-family:var(--font-heading);">${data.total_vpc_ips.toLocaleString()} IPs</div>
          <div style="font-size:0.75rem; color:var(--text-secondary); font-family:var(--font-mono);">${data.base_cidr}</div>
        </div>
        <div class="card" style="margin-bottom:0; padding:1rem;">
          <div style="font-size:0.75rem; color:var(--text-muted); text-transform:uppercase;">Subnet Size Allocation</div>
          <div style="font-size:1.4rem; font-weight:800; color:#38bdf8; font-family:var(--font-heading);">${data.subnet_prefix}</div>
          <div style="font-size:0.75rem; color:var(--text-secondary);">Max ${data.total_available_subnets} Subnets Possible</div>
        </div>
        <div class="card" style="margin-bottom:0; padding:1rem;">
          <div style="font-size:0.75rem; color:var(--text-muted); text-transform:uppercase;">Subnets Configured</div>
          <div style="font-size:1.4rem; font-weight:800; color:#10b981; font-family:var(--font-heading);">${data.allocated_subnets.length} Active</div>
          <div style="font-size:0.75rem; color:var(--text-secondary);">${data.remaining_unallocated_subnets} Unallocated Slices</div>
        </div>
      </div>

      <div style="font-family:var(--font-heading); font-size:1.1rem; font-weight:700; margin-bottom:1rem;">
        Subnet Allocation & Cloud Reserved IP Breakdown
      </div>
      <div class="cidr-matrix">
    `;

    data.allocated_subnets.forEach(sub => {
      const tierClass = sub.tier.includes('Public') ? 'public' : (sub.tier.includes('App') ? 'app' : 'db');
      const tierColor = tierClass === 'public' ? '#38bdf8' : (tierClass === 'app' ? '#10b981' : '#f59e0b');

      html += `
        <div class="subnet-box ${tierClass}">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
            <span style="font-weight:700; font-size:0.9rem; color:${tierColor};">${sub.tier}</span>
            <span style="font-size:0.7rem; font-weight:600; padding:0.15rem 0.4rem; border-radius:4px; background:var(--bg-tertiary);">${sub.az}</span>
          </div>
          <div style="font-family:var(--font-mono); font-size:1rem; font-weight:700; color:var(--text-primary); margin-bottom:0.75rem;">
            ${sub.cidr}
          </div>
          
          <div style="font-size:0.75rem; color:var(--text-secondary); display:flex; flex-direction:column; gap:0.25rem;">
            <div><strong>Usable Hosts:</strong> <span style="color:#10b981; font-weight:700;">${sub.usable_ips} IPs</span> (${sub.total_ips} total)</div>
            <div><strong>Usable Range:</strong> <span style="font-family:var(--font-mono); font-size:0.7rem;">${sub.first_usable_ip} - ${sub.last_usable_ip}</span></div>
          </div>

          <div style="margin-top:0.75rem; padding-top:0.5rem; border-top:1px solid var(--border-color); font-size:0.7rem;">
            <div style="color:var(--text-muted); font-weight:600; margin-bottom:0.2rem;">AWS 5 Reserved IPs:</div>
            <div style="font-family:var(--font-mono); color:#94a3b8; line-height:1.4;">
              • ${sub.reserved_breakdown.network} (Network)<br/>
              • ${sub.reserved_breakdown.router} (VPC Router)<br/>
              • ${sub.reserved_breakdown.dns} (Amazon DNS)<br/>
              • ${sub.reserved_breakdown.future_aws} (Reserved Future)<br/>
              • ${sub.reserved_breakdown.broadcast} (Broadcast)
            </div>
          </div>
        </div>
      `;
    });

    html += `</div>`;
    container.innerHTML = html;
  }
};
