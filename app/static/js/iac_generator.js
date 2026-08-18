/**
 * CloudVPC Studio - Multi-Cloud Infrastructure as Code (IaC) Exporter
 * Generates and downloads production Terraform, CloudFormation, Pulumi, and Bicep scripts.
 */

window.VPCIacGenerator = {
  currentType: 'terraform',
  currentFiles: {},
  activeFile: '',

  init() {
    this.bindEvents();
    this.loadIaC('terraform');
  },

  bindEvents() {
    const tfBtn = document.getElementById('iac-btn-tf');
    const cfnBtn = document.getElementById('iac-btn-cfn');
    const pulumiBtn = document.getElementById('iac-btn-pulumi');
    const bicepBtn = document.getElementById('iac-btn-bicep');
    const copyBtn = document.getElementById('iac-copy-btn');
    const downloadBtn = document.getElementById('iac-download-btn');

    if (tfBtn) tfBtn.addEventListener('click', () => this.switchIaCType('terraform'));
    if (cfnBtn) cfnBtn.addEventListener('click', () => this.switchIaCType('cloudformation'));
    if (pulumiBtn) pulumiBtn.addEventListener('click', () => this.switchIaCType('pulumi'));
    if (bicepBtn) bicepBtn.addEventListener('click', () => this.switchIaCType('bicep'));

    if (copyBtn) copyBtn.addEventListener('click', () => this.copyCurrentCode());
    if (downloadBtn) downloadBtn.addEventListener('click', () => this.downloadCurrentFile());
  },

  async switchIaCType(type) {
    this.currentType = type;
    
    document.querySelectorAll('.iac-type-btn').forEach(btn => {
      btn.classList.toggle('active', btn.getAttribute('data-type') === type);
    });

    await this.loadIaC(type);
  },

  async loadIaC(type) {
    try {
      const res = await fetch(`/api/export-iac?type=${type}`);
      const data = await res.json();
      this.currentFiles = data.files || {};
      this.renderFileList();
    } catch (err) {
      console.error("Failed to load IaC:", err);
    }
  },

  renderFileList() {
    const listContainer = document.getElementById('iac-files-list');
    if (!listContainer) return;

    const fileNames = Object.keys(this.currentFiles);
    if (fileNames.length === 0) {
      listContainer.innerHTML = `<div style="color:var(--text-muted); font-size:0.8rem;">No files available</div>`;
      return;
    }

    this.activeFile = fileNames[0];

    let html = '';
    fileNames.forEach(fn => {
      const isActive = fn === this.activeFile;
      html += `
        <button class="iac-file-btn ${isActive ? 'active' : ''}" onclick="VPCIacGenerator.selectFile('${fn}')">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"></path><polyline points="13 2 13 9 20 9"></polyline></svg>
          <span>${fn}</span>
        </button>
      `;
    });

    listContainer.innerHTML = html;
    this.renderActiveCode();
  },

  selectFile(fileName) {
    this.activeFile = fileName;
    document.querySelectorAll('.iac-file-btn').forEach(btn => {
      btn.classList.toggle('active', btn.innerText.includes(fileName));
    });
    this.renderActiveCode();
  },

  renderActiveCode() {
    const codePre = document.getElementById('iac-code-content');
    const headerTitle = document.getElementById('iac-current-filename');

    if (headerTitle) headerTitle.innerText = this.activeFile;
    if (codePre) {
      codePre.innerText = this.currentFiles[this.activeFile] || '# No content';
    }
  },

  copyCurrentCode() {
    const code = this.currentFiles[this.activeFile];
    if (!code) return;

    navigator.clipboard.writeText(code).then(() => {
      showToast(`Copied ${this.activeFile} to clipboard!`, 'success');
    }).catch(err => {
      showToast('Failed to copy code: ' + err.message, 'error');
    });
  },

  downloadCurrentFile() {
    const code = this.currentFiles[this.activeFile];
    if (!code) return;

    const blob = new Blob([code], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = this.activeFile;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    showToast(`Downloaded ${this.activeFile}`, 'success');
  }
};
