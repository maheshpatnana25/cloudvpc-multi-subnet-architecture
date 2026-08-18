# 🌐 CloudVPC Studio: Virtual Private Cloud (VPC) Multi-Subnet Architecture Design & Security Suite

[![Python](https://img.shields.io/badge/Python-3.14+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Terraform](https://img.shields.io/badge/Terraform-1.5+-7B42BC?style=for-the-badge&logo=terraform&logoColor=white)](https://terraform.io)
[![AWS](https://img.shields.io/badge/AWS-VPC%20Multi--AZ-FF9900?style=for-the-badge&logo=amazon-aws&logoColor=white)](https://aws.amazon.com)
[![Compliance](https://img.shields.io/badge/CIS%20AWS%20Benchmark-Grade%20A+-10B981?style=for-the-badge)](https://www.cisecurity.org/)

An interactive, production-grade cloud computing project designed for **Virtual Private Cloud (VPC) Multi-Subnet Architecture Design**. This project implements a secure, highly available **3-Tier VPC Architecture** spanning multiple Availability Zones (`us-east-1a` and `us-east-1b`), isolating public web tiers from private compute and sensitive database tiers using Route Tables, Internet Gateways, NAT Gateways, Network ACLs, and Security Groups.

---

## 🚀 Key Features & Innovations

1. **Interactive Multi-AZ VPC Topology Visualizer**:
   - Interactive SVG canvas rendering 3 security tiers across Availability Zones (`us-east-1a`, `us-east-1b`).
   - Live **Component Inspector** showing route table mappings, NACLs, stateful security groups, ENIs, and CIDRs on click.
   - Tier filtering (Public Ingress, App Private, Database Isolated).

2. **Real-Time Packet Tracer & Firewall Simulator**:
   - Trace live packet flows across Internet Gateways, Route Tables, Stateless NACLs, and Stateful Security Groups.
   - Test attack scenarios (e.g. external attacker attempting direct DB access on port 5432, SSH brute force, legitimate HTTPS traffic, private outbound updates via NAT).
   - Real-time animated hop-by-hop evaluation with instant `ALLOWED` or `DROPPED` verdicts and rule matches.

3. **VPC Flow Logs Dataset & Threat Intelligence Engine**:
   - Includes **12,000+ realistic VPC Flow Log records** (`vpc_flow_logs_dataset.csv` and JSON).
   - Real-time threat detection identifying port scanning probes, unauthorized database queries, and brute-force attacks.
   - Live searchable flow log stream with action, tier, and text filtering.

4. **Interactive CIDR Subnetting Calculator**:
   - Dynamic IP allocation calculator for any base CIDR (`10.0.0.0/16`, `172.16.0.0/16`, `192.168.0.0/16`) and subnet mask (`/24`, `/25`, `/26`, `/27`, `/28`).
   - Visual breakdown of **AWS 5 Reserved IPs** per subnet (`.0` network, `.1` router, `.2` DNS, `.3` future, `.255` broadcast).

5. **AWS Well-Architected & CIS Benchmark Compliance Auditor**:
   - Automated 12-point audit scoring the VPC design against CIS AWS Foundations Benchmark v1.5 and AWS Well-Architected Security/Reliability pillars.
   - Real-time score (A+ 100/100) with detailed evidence and remediation guidance.

6. **Multi-Cloud Infrastructure as Code (IaC) Exporter**:
   - Production-ready **Terraform HCL** modular files (`main.tf`, `subnets.tf`, `routes.tf`, `security_groups.tf`, `nacls.tf`, `flow_logs.tf`, `variables.tf`, `outputs.tf`).
   - **AWS CloudFormation** YAML template.
   - **Pulumi (Python)** and **Azure Bicep / VNet** scripts.
   - One-click copy to clipboard and file download.

7. **Embedded Viva Preparation & Architecture Guide**:
   - Complete technical breakdown and interview Q&A explaining stateful vs stateless firewalls, NAT gateways, and CIDR planning.

---

## 📁 Repository Structure

```
├── app/
│   ├── server.py                  # High-performance threaded Python REST API server
│   └── static/
│       ├── index.html             # Single Page Application UI
│       ├── css/
│       │   └── styles.css         # Modern, responsive design system & theme tokens
│       └── js/
│           ├── app.js             # Main SPA orchestrator & state manager
│           ├── visualizer.js      # Interactive VPC topology SVG canvas
│           ├── simulator.js       # Packet tracer firewall simulation engine
│           ├── analytics.js       # Flow logs charts & threat intelligence feed
│           ├── calculator.js      # CIDR subnetting & IP allocation visualizer
│           ├── auditor.js         # CIS Benchmark & Well-Architected auditor
│           └── iac_generator.js   # Multi-cloud IaC generator
├── data/
│   ├── vpc_flow_logs_dataset.csv  # 12,000+ realistic VPC Flow Log records
│   ├── vpc_flow_logs_dataset.json # JSON structured flow log records
│   ├── flow_logs_analytics_summary.json # Aggregated analytics & threat intelligence
│   └── security_rules.json        # Formal VPC topology & security rules definition
├── terraform/
│   ├── main.tf                    # VPC core, IGW, NAT Gateways, S3 Endpoint
│   ├── subnets.tf                 # Public, App, and Isolated DB subnets (Multi-AZ)
│   ├── routes.tf                  # Public, Private, and Isolated Route Tables
│   ├── security_groups.tf         # 3-tier stateful security groups (ALB -> App -> DB)
│   ├── nacls.tf                   # Stateless Network ACLs
│   ├── flow_logs.tf               # CloudWatch VPC Flow Logs configuration
│   ├── variables.tf               # Parameterized variables
│   └── outputs.tf                 # Exported VPC, Subnet, and Security Group IDs
├── cloudformation/
│   └── vpc-multi-subnet.yaml      # AWS CloudFormation production template
├── scripts/
│   ├── generate_flow_logs.py      # Dataset generator with attack scenarios
│   └── analyze_vpc_flow_logs.py   # Pandas data science & security reporting script
├── docs/
│   ├── ARCHITECTURE.md            # Detailed network architecture specification
│   └── PRESENTATION_GUIDE.md      # Step-by-step presentation & viva guide
├── run_app.bat                    # Windows 1-click launcher
├── run_app.py                     # Python application launcher
└── README.md                      # Comprehensive documentation
```

---

## ⚡ Quick Start

### Option 1: 1-Click Launch (Windows)
Double-click `run_app.bat` to launch the application and automatically open it in your browser.

### Option 2: Python Command Line
```bash
# Start server and auto-open browser at http://localhost:8000
python run_app.py
```

### Option 3: Run Flow Log Data Science Analytics Script
```bash
python scripts/analyze_vpc_flow_logs.py
```

---

## 🛡️ 3-Tier Security Architecture Summary

```
[Public Internet]
       │ (HTTPS 443 / HTTP 80)
       ▼
+──────────────────────────────────────────────────────────+
│ Public Tier (10.0.1.0/24 & 10.0.2.0/24)                  │
│ • Application Load Balancers (ALB)                       │
│ • NAT Gateways (Multi-AZ)                                │
│ • Bastion Host (Admin SSH restricted to Corporate IP)    │
+──────────────────────────────────────────────────────────+
       │ (Internal Port 8080)
       ▼
+──────────────────────────────────────────────────────────+
│ Private Application Tier (10.0.10.0/24 & 10.0.20.0/24)   │
│ • Web & Compute Nodes (EC2 / ECS / EKS)                  │
│ • Outbound Updates -> NAT Gateways (0.0.0.0/0)           │
│ • S3 API -> S3 VPC Gateway Endpoint (Private Backbone)  │
+──────────────────────────────────────────────────────────+
       │ (PostgreSQL Port 5432 - Strict SG Chaining)
       ▼
+──────────────────────────────────────────────────────────+
│ Isolated Database Tier (10.0.100.0/24 & 10.0.200.0/24)  │
│ • RDS Aurora PostgreSQL Multi-AZ Cluster                 │
│ • NO default route to IGW or NAT (Local VPC 10.0.0.0/16) │
│ • Ingress strictly permitted ONLY from App Tier SG       │
+──────────────────────────────────────────────────────────+
```

---

## 📜 License
This project is open source and available under the MIT License.
