/**
 * CloudVPC Studio - Interactive Topology Visualizer
 * Renders an interactive SVG canvas representing the Multi-AZ 3-Tier VPC
 * with component inspection, route table mappings, and security boundaries.
 */

window.VPCVisualizer = {
  svg: null,
  zoomLevel: 1.0,
  panX: 0,
  panY: 0,
  activeFilter: 'all',

  init() {
    this.svg = document.getElementById('vpc-topology-svg');
    this.initControls();
    this.render();
  },

  initControls() {
    const zoomInBtn = document.getElementById('zoom-in-btn');
    const zoomOutBtn = document.getElementById('zoom-out-btn');
    const zoomResetBtn = document.getElementById('zoom-reset-btn');
    const filterSelect = document.getElementById('tier-filter-select');

    if (zoomInBtn) {
      zoomInBtn.addEventListener('click', () => {
        this.zoomLevel = Math.min(this.zoomLevel + 0.15, 2.0);
        this.updateTransform();
      });
    }

    if (zoomOutBtn) {
      zoomOutBtn.addEventListener('click', () => {
        this.zoomLevel = Math.max(this.zoomLevel - 0.15, 0.6);
        this.updateTransform();
      });
    }

    if (zoomResetBtn) {
      zoomResetBtn.addEventListener('click', () => {
        this.zoomLevel = 1.0;
        this.panX = 0;
        this.panY = 0;
        this.updateTransform();
      });
    }

    if (filterSelect) {
      filterSelect.addEventListener('change', (e) => {
        this.activeFilter = e.target.value;
        this.render();
      });
    }
  },

  updateTransform() {
    const mainGroup = document.getElementById('svg-main-group');
    if (mainGroup) {
      mainGroup.setAttribute('transform', `translate(${this.panX}, ${this.panY}) scale(${this.zoomLevel})`);
    }
  },

  render() {
    if (!this.svg) return;

    const data = AppState.topologyData;
    if (!data) return;

    this.svg.innerHTML = `
      <defs>
        <!-- Gradients -->
        <linearGradient id="igwGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#38bdf8" />
          <stop offset="100%" stop-color="#2563eb" />
        </linearGradient>
        <linearGradient id="natGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#38bdf8" />
          <stop offset="100%" stop-color="#0284c7" />
        </linearGradient>
        <linearGradient id="appGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#34d399" />
          <stop offset="100%" stop-color="#059669" />
        </linearGradient>
        <linearGradient id="dbGrad" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#fbbf24" />
          <stop offset="100%" stop-color="#d97706" />
        </linearGradient>

        <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
          <feGaussianBlur stdDeviation="4" result="blur" />
          <feComposite in="SourceGraphic" in2="blur" operator="over" />
        </filter>
      </defs>

      <g id="svg-main-group" transform="translate(${this.panX}, ${this.panY}) scale(${this.zoomLevel})">
        <!-- VPC Outer Container -->
        <rect x="50" y="70" width="1020" height="520" class="svg-vpc-box" />
        
        <!-- VPC Header Label -->
        <g transform="translate(70, 100)">
          <rect x="0" y="-18" width="280" height="28" rx="6" fill="#1e1b4b" stroke="#6366f1" stroke-width="1.2"/>
          <text x="12" y="1" fill="#c7d2fe" font-size="12" font-weight="700" font-family="'JetBrains Mono', monospace">VPC: 10.0.0.0/16 (us-east-1)</text>
        </g>

        <!-- Internet Gateway (IGW) at Edge -->
        <g id="node-igw" class="svg-node-interactive" transform="translate(510, 20)" style="cursor:pointer;" onclick="VPCVisualizer.selectNode('igw')">
          <rect x="-60" y="0" width="120" height="42" rx="8" fill="url(#igwGrad)" filter="url(#glow)"/>
          <text x="0" y="24" fill="#ffffff" font-size="12" font-weight="800" text-anchor="middle" font-family="Inter">🌐 IGW (igw-01)</text>
        </g>

        <!-- Link from Internet to IGW -->
        <path d="M 510 62 L 510 130" stroke="#38bdf8" stroke-width="2.5" stroke-dasharray="4,4" class="svg-link" />

        <!-- S3 VPC Gateway Endpoint -->
        <g id="node-vpce" class="svg-node-interactive" transform="translate(930, 20)" style="cursor:pointer;" onclick="VPCVisualizer.selectNode('s3_endpoint')">
          <rect x="-65" y="0" width="130" height="42" rx="8" fill="#4338ca" stroke="#818cf8" stroke-width="1.5"/>
          <text x="0" y="24" fill="#ffffff" font-size="11" font-weight="700" text-anchor="middle">⚡ S3 VPC Endpoint</text>
        </g>

        <!-- ==================================================== -->
        <!-- AVAILABILITY ZONE 1 (us-east-1a) -->
        <!-- ==================================================== -->
        <rect x="70" y="120" width="470" height="450" class="svg-az-box" />
        <text x="90" y="145" fill="#94a3b8" font-size="12" font-weight="700" font-family="'JetBrains Mono', monospace">AVAILABILITY ZONE: us-east-1a</text>

        <!-- Public Subnet AZ1 -->
        <g class="tier-public" style="opacity: ${this.activeFilter === 'all' || this.activeFilter === 'public' ? 1 : 0.2}">
          <rect x="90" y="160" width="430" height="115" class="svg-subnet-public svg-subnet-node" onclick="VPCVisualizer.selectSubnet('subnet-01a_pub_01')" />
          <text x="105" y="182" fill="#38bdf8" font-size="11" font-weight="700" font-family="'JetBrains Mono', monospace">Public Subnet 1a (10.0.1.0/24)</text>

          <!-- ALB Node -->
          <g transform="translate(110, 195)" class="svg-node-interactive" onclick="event.stopPropagation(); VPCVisualizer.selectNode('alb_1a')">
            <rect x="0" y="0" width="180" height="65" class="svg-node-box" />
            <text x="15" y="24" fill="#38bdf8" font-size="12" font-weight="700">⚖️ ALB Ingress</text>
            <text x="15" y="42" fill="#94a3b8" font-size="10" font-family="JetBrains Mono">IP: 10.0.1.15 :443</text>
            <text x="15" y="55" fill="#64748b" font-size="9">SG: sg-01_alb</text>
          </g>

          <!-- NAT Gateway 1a Node -->
          <g transform="translate(310, 195)" class="svg-node-interactive" onclick="event.stopPropagation(); VPCVisualizer.selectNode('nat_1a')">
            <rect x="0" y="0" width="190" height="65" class="svg-node-box" />
            <text x="15" y="24" fill="#38bdf8" font-size="12" font-weight="700">🛡️ NAT Gateway 1a</text>
            <text x="15" y="42" fill="#94a3b8" font-size="10" font-family="JetBrains Mono">EIP: 54.210.10.22</text>
            <text x="15" y="55" fill="#64748b" font-size="9">Private: 10.0.1.50</text>
          </g>
        </g>

        <!-- App Private Subnet AZ1 -->
        <g class="tier-app" style="opacity: ${this.activeFilter === 'all' || this.activeFilter === 'app' ? 1 : 0.2}">
          <rect x="90" y="295" width="430" height="115" class="svg-subnet-app svg-subnet-node" onclick="VPCVisualizer.selectSubnet('subnet-10a_app_01')" />
          <text x="105" y="317" fill="#10b981" font-size="11" font-weight="700" font-family="'JetBrains Mono', monospace">App Private Subnet 1a (10.0.10.0/24)</text>

          <!-- App EC2/Container Node -->
          <g transform="translate(110, 330)" class="svg-node-interactive" onclick="event.stopPropagation(); VPCVisualizer.selectNode('app_1a')">
            <rect x="0" y="0" width="390" height="65" class="svg-node-box" />
            <text x="15" y="24" fill="#10b981" font-size="12" font-weight="700">⚙️ Web / API App Node 1 (EC2 / EKS)</text>
            <text x="15" y="42" fill="#94a3b8" font-size="10" font-family="JetBrains Mono">Private IP: 10.0.10.45 :8080</text>
            <text x="15" y="55" fill="#64748b" font-size="9">Route: 0.0.0.0/0 -> nat-01a | SG: sg-02_app</text>
          </g>
        </g>

        <!-- Database Isolated Subnet AZ1 -->
        <g class="tier-db" style="opacity: ${this.activeFilter === 'all' || this.activeFilter === 'db' ? 1 : 0.2}">
          <rect x="90" y="430" width="430" height="120" class="svg-subnet-db svg-subnet-node" onclick="VPCVisualizer.selectSubnet('subnet-100a_db_01')" />
          <text x="105" y="452" fill="#f59e0b" font-size="11" font-weight="700" font-family="'JetBrains Mono', monospace">Database Isolated Subnet 1a (10.0.100.0/24)</text>

          <!-- RDS PostgreSQL Primary -->
          <g transform="translate(110, 465)" class="svg-node-interactive" onclick="event.stopPropagation(); VPCVisualizer.selectNode('rds_primary')">
            <rect x="0" y="0" width="390" height="70" class="svg-node-box" />
            <text x="15" y="24" fill="#f59e0b" font-size="12" font-weight="700">🗄️ RDS Aurora PostgreSQL (Primary Master)</text>
            <text x="15" y="42" fill="#94a3b8" font-size="10" font-family="JetBrains Mono">Private IP: 10.0.100.12 :5432</text>
            <text x="15" y="58" fill="#ef4444" font-size="9" font-weight="700">🔒 ISOLATED: Ingress ONLY from sg-02_app</text>
          </g>
        </g>

        <!-- ==================================================== -->
        <!-- AVAILABILITY ZONE 2 (us-east-1b) -->
        <!-- ==================================================== -->
        <rect x="560" y="120" width="490" height="450" class="svg-az-box" />
        <text x="580" y="145" fill="#94a3b8" font-size="12" font-weight="700" font-family="'JetBrains Mono', monospace">AVAILABILITY ZONE: us-east-1b</text>

        <!-- Public Subnet AZ2 -->
        <g class="tier-public" style="opacity: ${this.activeFilter === 'all' || this.activeFilter === 'public' ? 1 : 0.2}">
          <rect x="580" y="160" width="450" height="115" class="svg-subnet-public svg-subnet-node" onclick="VPCVisualizer.selectSubnet('subnet-01b_pub_02')" />
          <text x="595" y="182" fill="#38bdf8" font-size="11" font-weight="700" font-family="'JetBrains Mono', monospace">Public Subnet 1b (10.0.2.0/24)</text>

          <!-- ALB Secondary -->
          <g transform="translate(600, 195)" class="svg-node-interactive" onclick="event.stopPropagation(); VPCVisualizer.selectNode('alb_1b')">
            <rect x="0" y="0" width="190" height="65" class="svg-node-box" />
            <text x="15" y="24" fill="#38bdf8" font-size="12" font-weight="700">⚖️ ALB Standby</text>
            <text x="15" y="42" fill="#94a3b8" font-size="10" font-family="JetBrains Mono">IP: 10.0.2.18 :443</text>
            <text x="15" y="55" fill="#64748b" font-size="9">SG: sg-01_alb</text>
          </g>

          <!-- NAT Gateway 1b -->
          <g transform="translate(810, 195)" class="svg-node-interactive" onclick="event.stopPropagation(); VPCVisualizer.selectNode('nat_1b')">
            <rect x="0" y="0" width="200" height="65" class="svg-node-box" />
            <text x="15" y="24" fill="#38bdf8" font-size="12" font-weight="700">🛡️ NAT Gateway 1b</text>
            <text x="15" y="42" fill="#94a3b8" font-size="10" font-family="JetBrains Mono">EIP: 54.210.20.44</text>
            <text x="15" y="55" fill="#64748b" font-size="9">Private: 10.0.2.50</text>
          </g>
        </g>

        <!-- App Private Subnet AZ2 -->
        <g class="tier-app" style="opacity: ${this.activeFilter === 'all' || this.activeFilter === 'app' ? 1 : 0.2}">
          <rect x="580" y="295" width="450" height="115" class="svg-subnet-app svg-subnet-node" onclick="VPCVisualizer.selectSubnet('subnet-20b_app_02')" />
          <text x="595" y="317" fill="#10b981" font-size="11" font-weight="700" font-family="'JetBrains Mono', monospace">App Private Subnet 1b (10.0.20.0/24)</text>

          <!-- App Node 2 -->
          <g transform="translate(600, 330)" class="svg-node-interactive" onclick="event.stopPropagation(); VPCVisualizer.selectNode('app_1b')">
            <rect x="0" y="0" width="410" height="65" class="svg-node-box" />
            <text x="15" y="24" fill="#10b981" font-size="12" font-weight="700">⚙️ Web / API App Node 2 (EC2 / EKS)</text>
            <text x="15" y="42" fill="#94a3b8" font-size="10" font-family="JetBrains Mono">Private IP: 10.0.20.78 :8080</text>
            <text x="15" y="55" fill="#64748b" font-size="9">Route: 0.0.0.0/0 -> nat-02b | SG: sg-02_app</text>
          </g>
        </g>

        <!-- Database Isolated Subnet AZ2 -->
        <g class="tier-db" style="opacity: ${this.activeFilter === 'all' || this.activeFilter === 'db' ? 1 : 0.2}">
          <rect x="580" y="430" width="450" height="120" class="svg-subnet-db svg-subnet-node" onclick="VPCVisualizer.selectSubnet('subnet-200b_db_02')" />
          <text x="595" y="452" fill="#f59e0b" font-size="11" font-weight="700" font-family="'JetBrains Mono', monospace">Database Isolated Subnet 1b (10.0.200.0/24)</text>

          <!-- RDS PostgreSQL Replica -->
          <g transform="translate(600, 465)" class="svg-node-interactive" onclick="event.stopPropagation(); VPCVisualizer.selectNode('rds_standby')">
            <rect x="0" y="0" width="410" height="70" class="svg-node-box" />
            <text x="15" y="24" fill="#f59e0b" font-size="12" font-weight="700">🗄️ RDS Aurora Standby (Sync Replication)</text>
            <text x="15" y="42" fill="#94a3b8" font-size="10" font-family="JetBrains Mono">Private IP: 10.0.200.14 :5432</text>
            <text x="15" y="58" fill="#ef4444" font-size="9" font-weight="700">🔒 ISOLATED: Ingress ONLY from sg-02_app</text>
          </g>
        </g>

        <!-- Replication Link between DB Master & Replica -->
        <path d="M 500 500 L 600 500" stroke="#f59e0b" stroke-width="2" stroke-dasharray="3,3" />

      </g>
    `;

    // Populate Inspector with default node
    this.selectNode('alb_1a');
  },

  selectNode(nodeKey) {
    const inspector = document.getElementById('inspector-content');
    if (!inspector) return;

    const nodeDetails = {
      igw: {
        title: "Internet Gateway (IGW)",
        type: "Edge Routing Gateway",
        id: "igw-09a8b7c6d5e4f3a21",
        tier: "Edge Gateway",
        description: "Horizontally scaled, redundant, and highly available VPC component that allows communication between instances in your VPC and the internet.",
        routes: [
          { dest: "0.0.0.0/0", target: "Attached to vpc-0a8b9c1d2e3f4001" }
        ],
        security: "Stateless translation between public and private IPv4 space."
      },
      alb_1a: {
        title: "Application Load Balancer (Primary)",
        type: "Layer-7 Reverse Proxy",
        id: "arn:aws:elasticloadbalancing:alb/prod-alb",
        tier: "Public Subnet (10.0.1.0/24)",
        ip: "10.0.1.15 (Public DNS reachable)",
        securityGroup: "sg-01_alb",
        sgRules: [
          { type: "Ingress", port: "443 (HTTPS)", source: "0.0.0.0/0", desc: "Allow public HTTPS" },
          { type: "Ingress", port: "80 (HTTP)", source: "0.0.0.0/0", desc: "Redirect to HTTPS" },
          { type: "Egress", port: "8080", dest: "sg-02_app", desc: "Forward to App Nodes" }
        ],
        nacl: "nacl-public (Rule 100/110: Allow 80, 443 Inbound)"
      },
      alb_1b: {
        title: "Application Load Balancer (Secondary)",
        type: "Layer-7 Reverse Proxy",
        id: "arn:aws:elasticloadbalancing:alb/prod-alb-standby",
        tier: "Public Subnet (10.0.2.0/24)",
        ip: "10.0.2.18",
        securityGroup: "sg-01_alb",
        sgRules: [
          { type: "Ingress", port: "443 (HTTPS)", source: "0.0.0.0/0", desc: "Allow public HTTPS" },
          { type: "Egress", port: "8080", dest: "sg-02_app", desc: "Forward to App Nodes" }
        ]
      },
      nat_1a: {
        title: "NAT Gateway (AZ-1a)",
        type: "Managed NAT Service",
        id: "nat-01a2b3c4d5e6f7001",
        tier: "Public Subnet (10.0.1.0/24)",
        elasticIp: "54.210.10.22",
        privateIp: "10.0.1.50",
        description: "Enables instances in private app subnet 10.0.10.0/24 to connect to the internet for package/OS updates without allowing inbound traffic.",
        routeTarget: "Default gateway for rtb-app-az1"
      },
      nat_1b: {
        title: "NAT Gateway (AZ-1b)",
        type: "Managed NAT Service",
        id: "nat-02a2b3c4d5e6f7002",
        tier: "Public Subnet (10.0.2.0/24)",
        elasticIp: "54.210.20.44",
        privateIp: "10.0.2.50",
        description: "Multi-AZ redundancy ensuring AZ-1b private instances have zero cross-AZ dependency for outbound egress.",
        routeTarget: "Default gateway for rtb-app-az2"
      },
      app_1a: {
        title: "Web / Application Compute Node 1",
        type: "EC2 / EKS Worker Node",
        id: "i-0a8174f1b2c3d4001",
        tier: "Private Application Subnet (10.0.10.0/24)",
        ip: "10.0.10.45",
        securityGroup: "sg-02_app",
        sgRules: [
          { type: "Ingress", port: "8080", source: "sg-01_alb", desc: "Allow from ALB only" },
          { type: "Ingress", port: "22 (SSH)", source: "sg-01_bastion", desc: "Admin SSH only" },
          { type: "Egress", port: "5432", dest: "sg-03_db", desc: "PostgreSQL queries to DB" },
          { type: "Egress", port: "443", dest: "0.0.0.0/0", desc: "Outbound HTTPS via NAT" }
        ],
        routes: [
          { dest: "10.0.0.0/16", target: "local" },
          { dest: "0.0.0.0/0", target: "nat-01a2b3c4d5e6f7001" },
          { dest: "pl-63a5400a (S3)", target: "vpce-0123456789abcdef0" }
        ]
      },
      rds_primary: {
        title: "RDS Aurora PostgreSQL (Primary)",
        type: "Managed Multi-AZ Database",
        id: "db-cluster-aurora-pg-01",
        tier: "Isolated Database Subnet (10.0.100.0/24)",
        ip: "10.0.100.12 :5432",
        securityGroup: "sg-03_db",
        sgRules: [
          { type: "Ingress", port: "5432", source: "sg-02_app", desc: "Strictly allow queries ONLY from App SG" },
          { type: "Egress", port: "None", dest: "None", desc: "Local stateful response only" }
        ],
        routeTable: "rtb-db-isolated (Local VPC 10.0.0.0/16 ONLY, NO route to 0.0.0.0/0)"
      },
      rds_standby: {
        title: "RDS Aurora PostgreSQL (Standby)",
        type: "Managed Multi-AZ Synchronous Replica",
        id: "db-cluster-aurora-pg-02",
        tier: "Isolated Database Subnet (10.0.200.0/24)",
        ip: "10.0.200.14 :5432",
        securityGroup: "sg-03_db",
        routeTable: "rtb-db-isolated"
      },
      s3_endpoint: {
        title: "AWS S3 VPC Gateway Endpoint",
        type: "VPC Gateway Endpoint",
        id: "vpce-0123456789abcdef0",
        tier: "VPC Gateway",
        description: "Direct AWS backbone route for Amazon S3 object storage without traversing NAT Gateways or the public internet.",
        prefixList: "pl-63a5400a (com.amazonaws.us-east-1.s3)"
      }
    };

    const node = nodeDetails[nodeKey] || nodeDetails['alb_1a'];

    let html = `
      <div class="property-group">
        <div class="prop-label">Selected Component</div>
        <div class="prop-val" style="color: #818cf8;">${node.title}</div>
      </div>
      <div class="property-group">
        <div class="prop-label">Tier / Network Location</div>
        <div class="prop-val">${node.tier}</div>
      </div>
      <div class="property-group">
        <div class="prop-label">Resource ID</div>
        <div class="prop-val" style="font-size: 0.75rem;">${node.id || 'N/A'}</div>
      </div>
    `;

    if (node.ip) {
      html += `
        <div class="property-group">
          <div class="prop-label">Private IP / Port</div>
          <div class="prop-val" style="color: #38bdf8;">${node.ip}</div>
        </div>
      `;
    }

    if (node.securityGroup) {
      html += `
        <div class="property-group">
          <div class="prop-label">Associated Security Group</div>
          <div class="prop-val" style="color: #10b981;">${node.securityGroup}</div>
        </div>
      `;
    }

    if (node.sgRules) {
      html += `
        <div class="property-group">
          <div class="prop-label">Security Group Rules</div>
          <table class="mini-table">
            <thead>
              <tr><th>Dir</th><th>Port</th><th>Source/Dest</th></tr>
            </thead>
            <tbody>
              ${node.sgRules.map(r => `
                <tr>
                  <td style="color:${r.type==='Ingress'?'#38bdf8':'#f59e0b'}">${r.type}</td>
                  <td>${r.port}</td>
                  <td>${r.source || r.dest}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    }

    if (node.routes) {
      html += `
        <div class="property-group">
          <div class="prop-label">Active Route Table Entries</div>
          <table class="mini-table">
            <thead>
              <tr><th>Destination</th><th>Target</th></tr>
            </thead>
            <tbody>
              ${node.routes.map(r => `
                <tr>
                  <td>${r.dest}</td>
                  <td style="color:#a5b4fc">${r.target}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    }

    inspector.innerHTML = html;
  },

  selectSubnet(subnetId) {
    const data = AppState.topologyData;
    if (!data || !data.subnets) return;
    const sub = data.subnets.find(s => s.id === subnetId);
    if (!sub) return;

    const inspector = document.getElementById('inspector-content');
    if (!inspector) return;

    let html = `
      <div class="property-group">
        <div class="prop-label">Subnet Name</div>
        <div class="prop-val" style="color:#818cf8;">${sub.name}</div>
      </div>
      <div class="property-group">
        <div class="prop-label">Subnet ID & Tier</div>
        <div class="prop-val">${sub.id} (${sub.tier})</div>
      </div>
      <div class="property-group">
        <div class="prop-label">CIDR Block</div>
        <div class="prop-val" style="color:#38bdf8;">${sub.cidr_block}</div>
      </div>
      <div class="property-group">
        <div class="prop-label">Availability Zone</div>
        <div class="prop-val">${sub.availability_zone}</div>
      </div>
      <div class="property-group">
        <div class="prop-label">Total / Usable IPs</div>
        <div class="prop-val">${sub.total_ips} Total / ${sub.usable_ips} Usable</div>
      </div>
      <div class="property-group">
        <div class="prop-label">Associated Route Table</div>
        <div class="prop-val" style="font-size:0.75rem;">${sub.route_table_id}</div>
      </div>
      <div class="property-group">
        <div class="prop-label">Network ACL (NACL)</div>
        <div class="prop-val" style="font-size:0.75rem;">${sub.nacl_id}</div>
      </div>
    `;

    inspector.innerHTML = html;
  }
};
