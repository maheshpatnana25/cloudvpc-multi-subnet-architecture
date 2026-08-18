# Project Presentation & Viva Defense Guide
## Virtual Private Cloud (VPC) Multi-Subnet Architecture Design

This guide provides the presentation script, demo walkthrough sequence, and answers to technical viva questions for presenting this cloud computing project.

---

## 1. Project Introduction (1 Minute Elevator Pitch)
> "Good morning / afternoon. Our project is **CloudVPC Studio: Multi-Subnet Architecture Design, Simulation & Security Suite**.
> In enterprise cloud computing, putting web servers, microservices, and databases in a flat network exposes sensitive data to cyber attacks. 
> To solve this, we designed an automated, production-grade 3-Tier Multi-Subnet VPC architecture across 2 Availability Zones (`us-east-1a` and `us-east-1b`).
> We built a real-time network simulator, packet tracer, threat intelligence engine with 12,000+ VPC flow logs, CIDR calculator, Well-Architected compliance auditor, and multi-cloud IaC generator (Terraform, CloudFormation, Pulumi, Bicep)."

---

## 2. Recommended Live Demonstration Workflow (3-5 Minutes)

### Step 1: Network Topology Visualizer (`Tab 1`)
- Show the **VPC boundary** (`10.0.0.0/16`) spanning `us-east-1a` and `us-east-1b`.
- Highlight the **3 distinct tiers**: Public Ingress (`10.0.1.0/24`), App Private (`10.0.10.0/24`), and Database Isolated (`10.0.100.0/24`).
- Click on any component (e.g., `RDS Aurora PostgreSQL Master` or `ALB`) to show the **Live Component Inspector** with real-time route tables, NACLs, and Security Groups.

### Step 2: Packet Tracer & Firewall Simulator (`Tab 2`)
- Select Scenario 1: **Legitimate User -> Web App (HTTPS 443)** -> Click **Run Packet Simulation**.
  - Show how the packet enters IGW -> passes Public NACL -> passes ALB SG -> succeeds (Status 200 OK).
- Select Scenario 2: **Attacker -> Direct Database Port 5432**.
  - Show the immediate firewall drop at the isolated route table & database security group (verdict: **DROPPED**).
- Select Scenario 3: **App Node -> RDS PostgreSQL (Port 5432)** -> Show allowed stateful internal query.

### Step 3: VPC Flow Logs & Threat Intelligence Dashboard (`Tab 3`)
- Point out the **12,000+ realistic VPC Flow Log dataset** generated across all three tiers.
- Show the **Automated Threat Intelligence Feed** detecting port scans and unauthorized database probes.
- Demonstrate real-time search & filtering (e.g. filter by `REJECT` or tier `Database`).

### Step 4: CIDR Subnetting Calculator (`Tab 4`)
- Change subnet prefix to `/24` or `/25` and demonstrate the **AWS 5 Reserved IPs breakdown** (`.0` network, `.1` router, `.2` DNS, `.3` future, `.255` broadcast).

### Step 5: Compliance Auditor & Multi-Cloud IaC Exporter (`Tabs 5 & 6`)
- Show the **A+ 100/100 Well-Architected compliance score**.
- Switch to IaC Exporter and showcase production-ready **Terraform HCL modular files** and **AWS CloudFormation YAML**.

---

## 3. High-Frequency Viva Questions & Answers

### Q1: What is the difference between a Public Subnet, a Private Subnet, and an Isolated Subnet?
- **Public Subnet**: Has a direct route (`0.0.0.0/0`) targeting an **Internet Gateway (IGW)**. Resources can have public IPv4 addresses and communicate directly with the internet.
- **Private Subnet**: Has a default route (`0.0.0.0/0`) targeting a **NAT Gateway** located in a public subnet. Resources have private IPs only; they can initiate outbound internet requests (e.g. downloading patches) but cannot receive unsolicited inbound internet connections.
- **Isolated Subnet**: Has **NO default route** to an IGW or NAT Gateway (local VPC route `10.0.0.0/16` only). No traffic can enter or leave the subnet except from explicitly authorized internal VPC resources.

### Q2: What is the difference between Security Groups and Network ACLs (NACLs)?
| Feature | Security Group (SG) | Network ACL (NACL) |
| :--- | :--- | :--- |
| **Level** | Applied at Instance / ENI level | Applied at Subnet boundary |
| **State** | **Stateful** (Return traffic is automatically permitted regardless of rules) | **Stateless** (Return traffic must be explicitly allowed via ephemeral ports) |
| **Rules** | Allow rules only | Allow AND Deny rules |
| **Evaluation** | All rules evaluated simultaneously | Evaluated in numerical order (100-32766) until first match |

### Q3: Why does AWS reserve 5 IP addresses in every subnet?
In a `/24` CIDR (256 IP addresses), exactly 251 addresses are usable:
1. `10.0.x.0`: Network address.
2. `10.0.x.1`: Reserved by AWS for VPC Router.
3. `10.0.x.2`: Reserved by AWS for DNS server (`AmazonProvidedDNS`).
4. `10.0.x.3`: Reserved by AWS for future use.
5. `10.0.x.255`: Network broadcast address (AWS does not support broadcast, but reserves the address).

### Q4: Why use an S3 VPC Gateway Endpoint instead of routing S3 traffic through the NAT Gateway?
1. **Cost Optimization**: VPC Gateway Endpoints for S3/DynamoDB are completely free and eliminate AWS NAT Gateway data processing fees ($0.045/GB).
2. **Performance & Security**: Traffic stays entirely within the private AWS network backbone and never traverses the public internet.

### Q5: What are VPC Flow Logs and how do they detect cyber threats?
VPC Flow Logs capture IP traffic going to and from network interfaces in the VPC. Fields include `srcaddr`, `dstaddr`, `srcport`, `dstport`, `protocol`, `packets`, `bytes`, and `action` (`ACCEPT`/`REJECT`). By analyzing flow logs, security teams can detect:
- **Port scanning**: Rapid sequential connection attempts across diverse ports.
- **Brute force attacks**: Repeated `REJECT` actions on port 22 (SSH) or 3389 (RDP).
- **Data exfiltration**: Anomalous surges in outbound byte volume.
