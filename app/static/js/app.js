/**
 * CloudVPC Studio - Main Application Controller
 * Handles tab navigation, theme toggling, global state, and lifecycle events.
 */

const AppState = {
  activeTab: 'topology',
  theme: 'dark',
  topologyData: null,
  analyticsSummary: null,
  flowLogs: [],
  selectedNode: null
};

document.addEventListener('DOMContentLoaded', async () => {
  console.log("Initializing CloudVPC Studio...");
  initNavigation();
  initThemeToggle();
  
  // Load Initial API Data
  await loadTopologyData();
  await loadAnalyticsData();
  
  // Initialize Sub-modules
  if (window.VPCVisualizer) window.VPCVisualizer.init();
  if (window.VPCSimulator) window.VPCSimulator.init();
  if (window.VPCAnalytics) window.VPCAnalytics.init();
  if (window.VPCCalculator) window.VPCCalculator.init();
  if (window.VPCAuditor) window.VPCAuditor.init();
  if (window.VPCIacGenerator) window.VPCIacGenerator.init();

  showToast("CloudVPC Studio Loaded Successfully", "success");
});

function initNavigation() {
  const tabs = document.querySelectorAll('.nav-tab');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.getAttribute('data-tab');
      switchTab(target);
    });
  });
}

function switchTab(tabId) {
  AppState.activeTab = tabId;
  
  // Update Tab buttons
  document.querySelectorAll('.nav-tab').forEach(t => {
    t.classList.toggle('active', t.getAttribute('data-tab') === tabId);
  });
  
  // Update Panes
  document.querySelectorAll('.tab-pane').forEach(p => {
    p.classList.toggle('active', p.id === `tab-${tabId}`);
  });

  // Trigger sub-module refreshes if needed
  if (tabId === 'topology' && window.VPCVisualizer) {
    window.VPCVisualizer.render();
  } else if (tabId === 'analytics' && window.VPCAnalytics) {
    window.VPCAnalytics.render();
  } else if (tabId === 'auditor' && window.VPCAuditor) {
    window.VPCAuditor.render();
  }
}

function initThemeToggle() {
  const themeBtn = document.getElementById('theme-toggle-btn');
  if (!themeBtn) return;

  themeBtn.addEventListener('click', () => {
    if (AppState.theme === 'dark') {
      AppState.theme = 'light';
      document.body.classList.add('light-theme');
      themeBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`;
    } else {
      AppState.theme = 'dark';
      document.body.classList.remove('light-theme');
      themeBtn.innerHTML = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`;
    }
  });
}

async function loadTopologyData() {
  try {
    const res = await fetch('/api/topology');
    AppState.topologyData = await res.json();
  } catch (err) {
    console.error("Failed to load topology:", err);
  }
}

async function loadAnalyticsData() {
  try {
    const res = await fetch('/api/analytics-summary');
    AppState.analyticsSummary = await res.json();
    updateQuickMetrics(AppState.analyticsSummary);
  } catch (err) {
    console.error("Failed to load analytics summary:", err);
  }
}

function updateQuickMetrics(summary) {
  if (!summary || !summary.dataset_metadata) return;
  const meta = summary.dataset_metadata;
  
  const m1 = document.getElementById('metric-total-traffic');
  const m2 = document.getElementById('metric-reject-ratio');
  const m3 = document.getElementById('metric-threats');
  
  if (m1) m1.innerText = meta.total_bytes_formatted || '48.6 MB';
  if (m2) m2.innerText = `${meta.rejection_ratio_percent}%`;
  if (m3 && summary.security_threats) {
    m3.innerText = summary.security_threats.length;
  }
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  
  let iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>`;
  if (type === 'success') {
    iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`;
  } else if (type === 'error') {
    iconSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
  }

  toast.innerHTML = `${iconSvg}<span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}
