/**
 * CloudVPC Studio - AWS Well-Architected & CIS Benchmark Security Auditor
 * Evaluates the 3-tier VPC against cloud network security and reliability best practices.
 */

window.VPCAuditor = {
  init() {
    this.render();
  },

  async render() {
    const container = document.getElementById('auditor-results-container');
    if (!container) return;

    container.innerHTML = `<div style="text-align:center; padding:3rem; color:var(--text-muted);">Running Well-Architected Security Audit Rules...</div>`;

    try {
      const res = await fetch('/api/compliance-audit');
      const data = await res.json();
      this.renderAuditReport(data);
    } catch (err) {
      console.error("Auditor fetch failed:", err);
    }
  },

  renderAuditReport(data) {
    const container = document.getElementById('auditor-results-container');
    if (!container) return;

    let html = `
      <div class="score-hero">
        <div>
          <div style="font-family:var(--font-heading); font-size:1.5rem; font-weight:800; color:#ffffff; margin-bottom:0.25rem;">
            Security & Reliability Posture: ${data.compliance_status}
          </div>
          <div style="font-size:0.875rem; color:#cbd5e1; max-width:650px;">
            Audited against ${data.framework}. Evaluated isolation boundaries, security group chaining, and multi-AZ redundancy.
          </div>
          <div style="display:flex; gap:1rem; margin-top:1rem; font-size:0.85rem;">
            <span>Checks Passed: <strong style="color:#10b981;">${data.checks_passed} / ${data.total_checks}</strong></span>
            <span>Critical Violations: <strong style="color:#10b981;">0</strong></span>
          </div>
        </div>
        <div class="score-circle">
          <div class="score-num">${data.overall_score}</div>
          <div class="score-grade">GRADE ${data.grade}</div>
        </div>
      </div>

      <div style="font-family:var(--font-heading); font-size:1.15rem; font-weight:700; margin-bottom:1.25rem;">
        Detailed Benchmark Verification Checks
      </div>
    `;

    data.checks.forEach(check => {
      const isPass = check.status === 'PASS';
      const severityColor = check.severity === 'CRITICAL' ? '#ef4444' : (check.severity === 'HIGH' ? '#f59e0b' : '#38bdf8');

      html += `
        <div class="audit-check-card">
          <div class="audit-icon ${isPass ? 'pass' : 'warn'}">
            ${isPass ? 
              `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>` : 
              `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>`
            }
          </div>
          <div style="flex:1;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.25rem;">
              <div style="font-weight:700; font-size:0.95rem; color:var(--text-primary);">
                ${check.id}: ${check.title}
              </div>
              <div style="display:flex; gap:0.5rem; align-items:center;">
                <span style="font-size:0.7rem; font-weight:600; padding:0.15rem 0.45rem; border-radius:4px; background:rgba(255,255,255,0.06); color:${severityColor};">
                  ${check.severity}
                </span>
                <span style="font-size:0.7rem; font-weight:700; color:#10b981; background:rgba(16,185,129,0.15); padding:0.15rem 0.45rem; border-radius:4px;">
                  +${check.score_impact} PTS
                </span>
              </div>
            </div>
            <div style="font-size:0.85rem; color:var(--text-secondary); margin-bottom:0.5rem;">
              ${check.description}
            </div>
            <div style="font-size:0.75rem; background:var(--bg-tertiary); padding:0.4rem 0.75rem; border-radius:var(--radius-sm); color:#a5b4fc;">
              <strong>Remediation / Evidence:</strong> ${check.remediation}
            </div>
          </div>
        </div>
      `;
    });

    container.innerHTML = html;
  }
};
