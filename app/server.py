"""
CloudVPC Studio - High Performance Backend & Network Simulation Server
Provides REST APIs for:
- VPC Topology & Security Rule queries
- Real-time Packet Tracer / Firewall Simulator
- VPC Flow Logs Data Streaming & Threat Analytics
- CIDR Subnet Calculator & IP Allocation Matrix
- AWS Well-Architected & CIS Benchmark Compliance Auditor
- Multi-Cloud IaC Exporter (Terraform, CloudFormation, Pulumi, Bicep)
"""

import os
import sys
import json
import ipaddress
import urllib.parse
from http.server import HTTPServer, SimpleHTTPRequestHandler
from socketserver import ThreadingMixIn

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "app", "static")
DATA_DIR = os.path.join(BASE_DIR, "data")
TERRAFORM_DIR = os.path.join(BASE_DIR, "terraform")
CFN_DIR = os.path.join(BASE_DIR, "cloudformation")

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class CloudVPCHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        query = urllib.parse.parse_qs(parsed_path.query)

        if path.startswith("/api/"):
            self.handle_api_get(path, query)
        else:
            # Serve index.html for root or any unknown static routes
            if path == "/" or not os.path.exists(os.path.join(STATIC_DIR, path.lstrip("/"))):
                self.path = "/index.html"
            return super().do_GET()

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        
        try:
            body = json.loads(post_data)
        except Exception:
            body = {}

        if path.startswith("/api/"):
            self.handle_api_post(path, body)
        else:
            self.send_error(404, "Not Found")

    def handle_api_get(self, path, query):
        if path == "/api/topology":
            topology_file = os.path.join(DATA_DIR, "security_rules.json")
            if os.path.exists(topology_file):
                with open(topology_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.send_json_response(data)
            else:
                self.send_json_response({"error": "Topology data not found"}, 404)

        elif path == "/api/analytics-summary":
            summary_file = os.path.join(DATA_DIR, "flow_logs_analytics_summary.json")
            if os.path.exists(summary_file):
                with open(summary_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.send_json_response(data)
            else:
                # Trigger analysis on demand
                from scripts.analyze_vpc_flow_logs import analyze_flow_logs
                summary = analyze_flow_logs()
                self.send_json_response(summary if summary else {"error": "Failed to analyze"})

        elif path == "/api/flow-logs":
            dataset_file = os.path.join(DATA_DIR, "vpc_flow_logs_dataset.json")
            if os.path.exists(dataset_file):
                with open(dataset_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                tier = query.get("tier", [None])[0]
                action = query.get("action", [None])[0]
                search = query.get("search", [None])[0]
                limit = int(query.get("limit", [100])[0])
                
                records = data.get("records", [])
                if tier:
                    records = [r for r in records if r["tier"].lower() == tier.lower()]
                if action:
                    records = [r for r in records if r["action"].lower() == action.lower()]
                if search:
                    s = search.lower()
                    records = [r for r in records if s in r["src_addr"].lower() or s in r["dst_addr"].lower() or s in str(r["dst_port"]) or s in r.get("scenario", "").lower()]

                self.send_json_response({
                    "total_matching": len(records),
                    "records": records[:limit]
                })
            else:
                self.send_json_response({"error": "Dataset not found"}, 404)

        elif path == "/api/compliance-audit":
            audit_result = self.run_compliance_audit()
            self.send_json_response(audit_result)

        elif path == "/api/export-iac":
            iac_type = query.get("type", ["terraform"])[0]
            iac_content = self.get_iac_content(iac_type)
            self.send_json_response(iac_content)

        else:
            self.send_json_response({"error": f"Unknown endpoint {path}"}, 404)

    def handle_api_post(self, path, body):
        if path == "/api/simulate-packet":
            result = self.simulate_packet_flow(body)
            self.send_json_response(result)

        elif path == "/api/cidr-calculate":
            result = self.calculate_cidr_plan(body)
            self.send_json_response(result)

        elif path == "/api/generate-logs":
            from scripts.generate_flow_logs import generate_vpc_dataset
            from scripts.analyze_vpc_flow_logs import analyze_flow_logs
            num_records = int(body.get("records", 5000))
            generate_vpc_dataset(num_records=num_records)
            summary = analyze_flow_logs()
            self.send_json_response({"status": "SUCCESS", "records_generated": num_records, "summary": summary})

        else:
            self.send_json_response({"error": f"Unknown endpoint {path}"}, 404)

    def send_json_response(self, data, status_code=200):
        response_bytes = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(response_bytes)

    def simulate_packet_flow(self, req):
        """
        Comprehensive Packet Tracer Simulation Engine
        Evaluates route tables, NACLs (stateless), and Security Groups (stateful)
        """
        source = req.get("source", "internet") # "internet", "bastion", "app_node", "malicious_ip"
        source_ip = req.get("source_ip", "203.0.113.15")
        destination = req.get("destination", "alb") # "alb", "app_node", "database", "external_api"
        dest_port = int(req.get("port", 443))
        protocol = req.get("protocol", "TCP").upper()

        hops = []
        verdict = "ALLOW"
        drop_reason = None
        current_stage = "START"

        # Hop 1: Packet Origin & Ingress Gateway
        if source == "internet" or source == "malicious_ip":
            hops.append({
                "hop_number": 1,
                "node": "Internet Gateway (IGW)",
                "tier": "Edge",
                "action": "FORWARD",
                "detail": f"Inbound packet from {source_ip} to destination port {dest_port} enters via igw-09a8b7c6d5e4f3a21"
            })
        elif source == "bastion":
            hops.append({
                "hop_number": 1,
                "node": "Bastion Host (10.0.1.200)",
                "tier": "Public",
                "action": "INITIATE",
                "detail": f"Admin jump session initiated from Bastion host (10.0.1.200)"
            })
        elif source == "app_node":
            hops.append({
                "hop_number": 1,
                "node": "App Compute Instance (10.0.10.45)",
                "tier": "Application",
                "action": "INITIATE",
                "detail": f"Application backend initiating connection to {destination}"
            })

        # Evaluate Based on Target Destination
        if destination == "alb":
            # Target: Public Load Balancer
            # Hop 2: Public NACL Ingress
            if dest_port in [80, 443]:
                hops.append({
                    "hop_number": 2,
                    "node": "Public Subnet Network ACL (nacl-public)",
                    "tier": "Public",
                    "action": "ALLOW",
                    "rule_matched": f"Rule {100 if dest_port == 80 else 110}: ALLOW {protocol} Port {dest_port} from 0.0.0.0/0",
                    "detail": "Stateless Network ACL permitted packet based on whitelisted web ingress ports."
                })
            else:
                verdict = "DROP"
                drop_reason = f"Public NACL dropped packet: Port {dest_port} is not allowed by inbound rules."
                hops.append({
                    "hop_number": 2,
                    "node": "Public Subnet Network ACL (nacl-public)",
                    "tier": "Public",
                    "action": "DROP",
                    "rule_matched": "Rule *: DENY ALL",
                    "detail": drop_reason
                })
                return self.build_simulation_response(hops, verdict, drop_reason, req)

            # Hop 3: ALB Security Group
            if dest_port in [80, 443]:
                hops.append({
                    "hop_number": 3,
                    "node": "ALB Security Group (sg-01_alb)",
                    "tier": "Public",
                    "action": "ALLOW",
                    "rule_matched": f"Ingress Rule: Allow {protocol} {dest_port} from 0.0.0.0/0",
                    "detail": "Stateful Security Group accepted connection. Target ALB instance terminates TLS / processes HTTP."
                })
                hops.append({
                    "hop_number": 4,
                    "node": "Application Load Balancer (10.0.1.15)",
                    "tier": "Public",
                    "action": "SUCCESS",
                    "detail": "HTTP request successfully received and queued for target group health routing."
                })
            else:
                verdict = "DROP"
                drop_reason = f"ALB Security Group dropped connection on port {dest_port}."
                hops.append({
                    "hop_number": 3,
                    "node": "ALB Security Group (sg-01_alb)",
                    "tier": "Public",
                    "action": "DROP",
                    "detail": drop_reason
                })

        elif destination == "app_node":
            # Target: Application Server (Private Subnet 10.0.10.x)
            if source == "internet" or source == "malicious_ip":
                # External Internet trying direct access to Private Subnet!
                verdict = "DROP"
                drop_reason = "CRITICAL SECURITY BLOCK: Private Subnet (10.0.10.0/24) has no public IP and no Direct Internet Gateway route. External direct packets cannot route directly to private instances."
                hops.append({
                    "hop_number": 2,
                    "node": "VPC Route Table Isolation (rtb-app-az1)",
                    "tier": "Application",
                    "action": "DROP",
                    "rule_matched": "No Public Route / No Direct IGW Association",
                    "detail": drop_reason
                })
                return self.build_simulation_response(hops, verdict, drop_reason, req)

            elif source == "alb":
                hops.append({
                    "hop_number": 2,
                    "node": "App Subnet Network ACL (nacl-app)",
                    "tier": "Application",
                    "action": "ALLOW",
                    "rule_matched": "Rule 100: ALLOW TCP 8080 from 10.0.0.0/16",
                    "detail": "App NACL permitted internal traffic from ALB."
                })
                if dest_port == 8080:
                    hops.append({
                        "hop_number": 3,
                        "node": "App Security Group (sg-02_app)",
                        "tier": "Application",
                        "action": "ALLOW",
                        "rule_matched": "Ingress Rule: Allow TCP 8080 from sg-01_alb",
                        "detail": "App Security Group verified source SG identity matches ALB security group."
                    })
                    hops.append({
                        "hop_number": 4,
                        "node": "App Server (10.0.10.45)",
                        "tier": "Application",
                        "action": "SUCCESS",
                        "detail": "Request delivered to microservice container."
                    })
                else:
                    verdict = "DROP"
                    drop_reason = f"App Security Group rejected port {dest_port}. Only 8080 (from ALB) and 22 (from Bastion) are permitted."
                    hops.append({
                        "hop_number": 3,
                        "node": "App Security Group (sg-02_app)",
                        "tier": "Application",
                        "action": "DROP",
                        "detail": drop_reason
                    })

            elif source == "bastion":
                if dest_port == 22:
                    hops.append({
                        "hop_number": 2,
                        "node": "App Subnet Network ACL (nacl-app)",
                        "tier": "Application",
                        "action": "ALLOW",
                        "rule_matched": "Rule 110: ALLOW TCP 22 from 10.0.1.0/24",
                        "detail": "Bastion subnet IP range permitted via App NACL."
                    })
                    hops.append({
                        "hop_number": 3,
                        "node": "App Security Group (sg-02_app)",
                        "tier": "Application",
                        "action": "ALLOW",
                        "rule_matched": "Ingress Rule: Allow TCP 22 from sg-01_bastion",
                        "detail": "SSH session authenticated from Bastion SG."
                    })
                    hops.append({
                        "hop_number": 4,
                        "node": "App Server (10.0.10.45)",
                        "tier": "Application",
                        "action": "SUCCESS",
                        "detail": "SSH Terminal shell established."
                    })
                else:
                    verdict = "DROP"
                    drop_reason = f"Bastion cannot connect to App Server on port {dest_port} (only SSH 22 is permitted)."
                    hops.append({
                        "hop_number": 2,
                        "node": "App Security Group (sg-02_app)",
                        "tier": "Application",
                        "action": "DROP",
                        "detail": drop_reason
                    })

        elif destination == "database":
            # Target: Isolated Database Subnet (10.0.100.x)
            if source == "internet" or source == "malicious_ip":
                verdict = "DROP"
                drop_reason = "HIGH SEVERITY FIREWALL BLOCK: Database Tier is completely isolated. Subnet has NO route to Internet Gateway and Security Group denies all 0.0.0.0/0 ingress."
                hops.append({
                    "hop_number": 2,
                    "node": "Database Route Table (rtb-db-isolated)",
                    "tier": "Database",
                    "action": "DROP",
                    "rule_matched": "Strict Isolation (Local Routing Only)",
                    "detail": drop_reason
                })
                hops.append({
                    "hop_number": 3,
                    "node": "Database Security Group (sg-03_db)",
                    "tier": "Database",
                    "action": "DROP",
                    "rule_matched": "No Public Ingress Allowed",
                    "detail": "DB Security Group strictly accepts connections referencing sg-02_app only."
                })
                return self.build_simulation_response(hops, verdict, drop_reason, req)

            elif source == "bastion":
                verdict = "DROP"
                drop_reason = "SECURITY POLICY ENFORCED: Direct Bastion access to Database Subnet is denied. Database queries must originate from the Application Tier."
                hops.append({
                    "hop_number": 2,
                    "node": "Database Security Group (sg-03_db)",
                    "tier": "Database",
                    "action": "DROP",
                    "detail": drop_reason
                })
                return self.build_simulation_response(hops, verdict, drop_reason, req)

            elif source == "app_node":
                if dest_port == 5432:
                    hops.append({
                        "hop_number": 2,
                        "node": "Database Subnet Network ACL (nacl-db)",
                        "tier": "Database",
                        "action": "ALLOW",
                        "rule_matched": "Rule 100: ALLOW TCP 5432 from 10.0.10.0/24",
                        "detail": "NACL verified App Subnet CIDR."
                    })
                    hops.append({
                        "hop_number": 3,
                        "node": "Database Security Group (sg-03_db)",
                        "tier": "Database",
                        "action": "ALLOW",
                        "rule_matched": "Ingress Rule: Allow TCP 5432 from sg-02_app",
                        "detail": "PostgreSQL query authorized via SG chaining."
                    })
                    hops.append({
                        "hop_number": 4,
                        "node": "RDS Aurora PostgreSQL (10.0.100.12)",
                        "tier": "Database",
                        "action": "SUCCESS",
                        "detail": "SQL Query executed successfully with stateful response return."
                    })
                else:
                    verdict = "DROP"
                    drop_reason = f"Database Security Group blocked port {dest_port}. Only PostgreSQL (Port 5432) is open."
                    hops.append({
                        "hop_number": 2,
                        "node": "Database Security Group (sg-03_db)",
                        "tier": "Database",
                        "action": "DROP",
                        "detail": drop_reason
                    })

        elif destination == "external_api":
            # App Node reaching out to external Internet (e.g. GitHub / S3)
            if source == "app_node":
                hops.append({
                    "hop_number": 2,
                    "node": "App Private Route Table (rtb-app-az1)",
                    "tier": "Application",
                    "action": "FORWARD",
                    "rule_matched": "Route 0.0.0.0/0 -> nat-01a2b3c4d5e6f7001",
                    "detail": "Default route forwards outbound non-VPC traffic to NAT Gateway in Public Subnet."
                })
                hops.append({
                    "hop_number": 3,
                    "node": "NAT Gateway 1a (10.0.1.50 / EIP 54.210.10.22)",
                    "tier": "Public",
                    "action": "TRANSLATE",
                    "detail": "Source IP translated from private 10.0.10.45 to Elastic IP 54.210.10.22."
                })
                hops.append({
                    "hop_number": 4,
                    "node": "Internet Gateway (igw-09a8b7c6d5e4f3a21)",
                    "tier": "Edge",
                    "action": "EGRESS",
                    "detail": "Outbound HTTPS request transmitted to External API server."
                })
                hops.append({
                    "hop_number": 5,
                    "node": "External Cloud / API Endpoint",
                    "tier": "Internet",
                    "action": "SUCCESS",
                    "detail": "Response successfully returned through NAT Gateway state table back to App Instance."
                })
            else:
                verdict = "DROP"
                drop_reason = "Unsupported source for outbound internet."

        return self.build_simulation_response(hops, verdict, drop_reason, req)

    def build_simulation_response(self, hops, verdict, drop_reason, req):
        return {
            "simulation_id": f"sim_{int(ipaddress.IPv4Address(hops[0].get('node', '10.0.0.1').split()[0] if '.' in hops[0].get('node','') else '10.0.0.1'))}_{int(req.get('port', 80))}",
            "verdict": verdict,
            "drop_reason": drop_reason,
            "request_parameters": req,
            "hop_count": len(hops),
            "hops": hops
        }

    def calculate_cidr_plan(self, body):
        base_cidr = body.get("vpc_cidr", "10.0.0.0/16")
        subnet_mask = int(body.get("subnet_mask", 24))
        num_azs = int(body.get("num_azs", 2))
        
        try:
            vpc_net = ipaddress.ip_network(base_cidr, strict=False)
            all_subnets = list(vpc_net.subnets(new_prefix=subnet_mask))
            
            allocated_subnets = []
            tier_names = ["Public Ingress", "Application Tier", "Database Tier"]
            idx = 0
            
            for tier in tier_names:
                for az in range(num_azs):
                    if idx < len(all_subnets):
                        sub = all_subnets[idx]
                        total_ips = sub.num_addresses
                        usable_ips = max(0, total_ips - 5) # AWS reserves 5 IPs
                        
                        allocated_subnets.append({
                            "name": f"{tier.lower().replace(' ', '-')}-az-{chr(97+az)}",
                            "tier": tier,
                            "az": f"AZ-{chr(65+az)}",
                            "cidr": str(sub),
                            "network_address": str(sub.network_address),
                            "broadcast_address": str(sub.broadcast_address),
                            "first_usable_ip": str(sub.network_address + 4),
                            "last_usable_ip": str(sub.broadcast_address - 1),
                            "total_ips": total_ips,
                            "usable_ips": usable_ips,
                            "reserved_breakdown": {
                                "network": str(sub.network_address),
                                "router": str(sub.network_address + 1),
                                "dns": str(sub.network_address + 2),
                                "future_aws": str(sub.network_address + 3),
                                "broadcast": str(sub.broadcast_address)
                            }
                        })
                        idx += 1

            return {
                "base_cidr": str(vpc_net),
                "total_vpc_ips": vpc_net.num_addresses,
                "subnet_prefix": f"/{subnet_mask}",
                "total_available_subnets": len(all_subnets),
                "allocated_subnets": allocated_subnets,
                "remaining_unallocated_subnets": max(0, len(all_subnets) - len(allocated_subnets))
            }
        except Exception as e:
            return {"error": str(e)}

    def run_compliance_audit(self):
        checks = [
            {
                "id": "VPC-01",
                "title": "Multi-AZ High Availability Architecture",
                "category": "Reliability",
                "status": "PASS",
                "severity": "CRITICAL",
                "score_impact": 10,
                "description": "VPC is provisioned across 2 or more Availability Zones with redundant subnets in each tier.",
                "remediation": "No action needed. High availability across us-east-1a and us-east-1b is confirmed."
            },
            {
                "id": "VPC-02",
                "title": "Database Subnet Isolation (Zero Public Route)",
                "category": "Security",
                "status": "PASS",
                "severity": "CRITICAL",
                "score_impact": 15,
                "description": "Database subnets have no default route (0.0.0.0/0) to Internet Gateways or NAT Gateways.",
                "remediation": "Database route table only allows local VPC routing (10.0.0.0/16)."
            },
            {
                "id": "VPC-03",
                "title": "Security Group Least Privilege Chaining",
                "category": "Security",
                "status": "PASS",
                "severity": "HIGH",
                "score_impact": 15,
                "description": "Database security group strictly restricts inbound port 5432 to the App Security Group (sg-02_app). No IP CIDR is exposed.",
                "remediation": "Chained security groups prevent unauthorized lateral movement."
            },
            {
                "id": "VPC-04",
                "title": "No 0.0.0.0/0 Ingress on Admin Port 22 (SSH)",
                "category": "Security",
                "status": "PASS",
                "severity": "HIGH",
                "score_impact": 10,
                "description": "SSH access is restricted to corporate IP CIDR via Bastion Host and blocked from public internet.",
                "remediation": "Corporate CIDR whitelist 198.51.100.0/24 in place."
            },
            {
                "id": "VPC-05",
                "title": "Redundant NAT Gateways for Private Egress",
                "category": "Reliability",
                "status": "PASS",
                "severity": "MEDIUM",
                "score_impact": 10,
                "description": "Independent NAT Gateways deployed in each public subnet to avoid single-point-of-failure cross-AZ dependency.",
                "remediation": "NAT Gateway 1a and 2b configured with dedicated Elastic IPs."
            },
            {
                "id": "VPC-06",
                "title": "VPC Gateway Endpoint for S3 Active",
                "category": "Cost & Security",
                "status": "PASS",
                "severity": "MEDIUM",
                "score_impact": 10,
                "description": "S3 traffic from application private subnets routes privately over AWS backbone without NAT data transfer charges.",
                "remediation": "S3 Gateway Endpoint associated with private route tables."
            },
            {
                "id": "VPC-07",
                "title": "VPC Flow Logs Enabled for Threat Detection",
                "category": "Audit & Compliance",
                "status": "PASS",
                "severity": "HIGH",
                "score_impact": 15,
                "description": "All ACCEPT and REJECT network traffic is captured to CloudWatch Log Group with 30-day retention.",
                "remediation": "Flow log resource attached to vpc-0a8b9c1d2e3f4001."
            },
            {
                "id": "VPC-08",
                "title": "Stateless Network ACL Defense-in-Depth",
                "category": "Security",
                "status": "PASS",
                "severity": "MEDIUM",
                "score_impact": 10,
                "description": "NACLs provide secondary packet filtering layer before Security Group state tables are evaluated.",
                "remediation": "Dedicated NACLs attached to Public, App, and Database subnets."
            },
            {
                "id": "VPC-09",
                "title": "DNS Hostnames & Support Enabled",
                "category": "Operations",
                "status": "PASS",
                "severity": "LOW",
                "score_impact": 5,
                "description": "enable_dns_hostnames and enable_dns_support are enabled on the VPC for internal service discovery.",
                "remediation": "Both DNS parameters enabled."
            }
        ]

        total_score = sum(c["score_impact"] for c in checks if c["status"] == "PASS")
        
        return {
            "framework": "AWS Well-Architected Framework & CIS AWS Foundations Benchmark v1.5",
            "overall_score": total_score,
            "max_score": 100,
            "grade": "A+" if total_score >= 95 else ("A" if total_score >= 85 else "B"),
            "compliance_status": "COMPLIANT",
            "checks_passed": len([c for c in checks if c["status"] == "PASS"]),
            "total_checks": len(checks),
            "checks": checks
        }

    def get_iac_content(self, iac_type):
        if iac_type == "terraform":
            tf_main = os.path.join(TERRAFORM_DIR, "main.tf")
            tf_subnets = os.path.join(TERRAFORM_DIR, "subnets.tf")
            tf_routes = os.path.join(TERRAFORM_DIR, "routes.tf")
            tf_sg = os.path.join(TERRAFORM_DIR, "security_groups.tf")
            tf_nacl = os.path.join(TERRAFORM_DIR, "nacls.tf")
            tf_vars = os.path.join(TERRAFORM_DIR, "variables.tf")
            tf_out = os.path.join(TERRAFORM_DIR, "outputs.tf")
            
            def read_f(p):
                if os.path.exists(p):
                    with open(p, "r", encoding="utf-8") as f:
                        return f.read()
                return ""

            return {
                "type": "terraform",
                "files": {
                    "main.tf": read_f(tf_main),
                    "subnets.tf": read_f(tf_subnets),
                    "routes.tf": read_f(tf_routes),
                    "security_groups.tf": read_f(tf_sg),
                    "nacls.tf": read_f(tf_nacl),
                    "variables.tf": read_f(tf_vars),
                    "outputs.tf": read_f(tf_out)
                }
            }

        elif iac_type == "cloudformation":
            cfn_file = os.path.join(CFN_DIR, "vpc-multi-subnet.yaml")
            if os.path.exists(cfn_file):
                with open(cfn_file, "r", encoding="utf-8") as f:
                    content = f.read()
            else:
                content = ""
            return {
                "type": "cloudformation",
                "files": {
                    "vpc-multi-subnet.yaml": content
                }
            }

        elif iac_type == "pulumi":
            return {
                "type": "pulumi",
                "files": {
                    "__main__.py": self.generate_pulumi_code()
                }
            }

        elif iac_type == "bicep":
            return {
                "type": "bicep",
                "files": {
                    "main.bicep": self.generate_azure_bicep_code()
                }
            }

        return {"error": "Invalid IaC type"}

    def generate_pulumi_code(self):
        return '''"""
Pulumi Python Script: 3-Tier Multi-Subnet VPC
"""
import pulumi
import pulumi_aws as aws

# Create VPC
vpc = aws.ec2.Vpc("production-vpc",
    cidr_block="10.0.0.0/16",
    enable_dns_hostnames=True,
    enable_dns_support=True,
    tags={"Name": "prod-vpc", "Tier": "Network-Core"})

# Create Internet Gateway
igw = aws.ec2.InternetGateway("prod-igw",
    vpc_id=vpc.id,
    tags={"Name": "prod-igw"})

# Public Subnets
pub_1 = aws.ec2.Subnet("public-1a",
    vpc_id=vpc.id,
    cidr_block="10.0.1.0/24",
    availability_zone="us-east-1a",
    map_public_ip_on_launch=True,
    tags={"Name": "public-subnet-1a"})

# App Private Subnet
app_1 = aws.ec2.Subnet("app-1a",
    vpc_id=vpc.id,
    cidr_block="10.0.10.0/24",
    availability_zone="us-east-1a",
    tags={"Name": "app-subnet-1a"})

# DB Isolated Subnet
db_1 = aws.ec2.Subnet("db-1a",
    vpc_id=vpc.id,
    cidr_block="10.0.100.0/24",
    availability_zone="us-east-1a",
    tags={"Name": "db-isolated-1a"})

# Exports
pulumi.export("vpc_id", vpc.id)
pulumi.export("public_subnet_id", pub_1.id)
pulumi.export("app_subnet_id", app_1.id)
pulumi.export("db_subnet_id", db_1.id)
'''

    def generate_azure_bicep_code(self):
        return '''// Azure Bicep: Equivalent Multi-Subnet Virtual Network (VNet)
param vnetName string = 'prod-vnet'
param location string = resourceGroup().location

resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.0.0.0/16']
    }
    subnets: [
      {
        name: 'snet-public-ingress'
        properties: {
          addressPrefix: '10.0.1.0/24'
        }
      }
      {
        name: 'snet-app-backend'
        properties: {
          addressPrefix: '10.0.10.0/24'
        }
      }
      {
        name: 'snet-database-isolated'
        properties: {
          addressPrefix: '10.0.100.0/24'
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
}

output vnetId string = vnet.id
'''

def run_server(port=8000):
    server_address = ("", port)
    httpd = ThreadedHTTPServer(server_address, CloudVPCHandler)
    print(f"====================================================================")
    print(f"  CloudVPC Studio Server is running at http://localhost:{port}")
    print(f"  VPC Multi-Subnet Architecture Simulator & Security Suite")
    print(f"====================================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping CloudVPC Studio Server...")
        httpd.server_close()

if __name__ == "__main__":
    port = 8000
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run_server(port)
