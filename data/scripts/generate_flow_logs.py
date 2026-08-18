"""
VPC Flow Logs & Network Security Event Dataset Generator
Generates realistic, production-grade AWS VPC Flow Logs (version 2 format)
including normal 3-tier web application traffic and realistic cyber threat patterns.
"""

import csv
import json
import random
import time
from datetime import datetime, timezone

def generate_vpc_dataset(num_records=12000, output_csv="data/vpc_flow_logs_dataset.csv", output_json="data/vpc_flow_logs_dataset.json"):
    import os
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)

    account_id = "123456789012"
    vpc_id = "vpc-0a8b9c1d2e3f4001"
    
    # Topology definition
    subnets = {
        # Public Tier
        "subnet-pub-1a": {"tier": "Public", "az": "us-east-1a", "cidr": "10.0.1.0/24", "eni": "eni-01a_alb_01", "role": "ALB Public Ingress"},
        "subnet-pub-1b": {"tier": "Public", "az": "us-east-1b", "cidr": "10.0.2.0/24", "eni": "eni-01b_alb_02", "role": "ALB Public Ingress"},
        "subnet-nat-1a": {"tier": "Public", "az": "us-east-1a", "cidr": "10.0.1.0/24", "eni": "eni-01a_nat_01", "role": "NAT Gateway AZ-1"},
        "subnet-nat-1b": {"tier": "Public", "az": "us-east-1b", "cidr": "10.0.2.0/24", "eni": "eni-01b_nat_02", "role": "NAT Gateway AZ-2"},
        "subnet-bastion": {"tier": "Public", "az": "us-east-1a", "cidr": "10.0.1.0/24", "eni": "eni-01a_bas_01", "role": "Bastion Host"},
        
        # Private App Tier
        "subnet-app-1a": {"tier": "Application", "az": "us-east-1a", "cidr": "10.0.10.0/24", "eni": "eni-10a_app_01", "role": "Web/API App Node 1"},
        "subnet-app-1b": {"tier": "Application", "az": "us-east-1b", "cidr": "10.0.20.0/24", "eni": "eni-20b_app_02", "role": "Web/API App Node 2"},
        
        # Isolated Database Tier
        "subnet-db-1a": {"tier": "Database", "az": "us-east-1a", "cidr": "10.0.100.0/24", "eni": "eni-100a_rds_01", "role": "RDS PostgreSQL Primary"},
        "subnet-db-1b": {"tier": "Database", "az": "us-east-1b", "cidr": "10.0.200.0/24", "eni": "eni-200b_rds_02", "role": "RDS PostgreSQL Standby"}
    }

    internal_ips = {
        "alb_1a": "10.0.1.15",
        "alb_1b": "10.0.2.18",
        "nat_1a": "10.0.1.50",
        "nat_1b": "10.0.2.50",
        "bastion": "10.0.1.200",
        "app_1a": "10.0.10.45",
        "app_1b": "10.0.20.78",
        "rds_primary": "10.0.100.12",
        "rds_standby": "10.0.200.14"
    }

    legitimate_clients = [
        "198.51.100.42", "203.0.113.15", "192.0.2.77", "198.51.100.101",
        "203.0.113.88", "198.51.100.210", "203.0.113.155", "192.0.2.22"
    ]
    
    malicious_ips = [
        "185.220.101.5",  # Tor exit node scanner
        "45.155.205.233", # Known brute force IP
        "194.26.29.112",  # Port scanner
        "91.240.118.172", # Vulnerability probe
        "141.98.11.88"    # Direct DB probe attempt
    ]

    base_time = int(time.time()) - (86400 * 2) # Past 48 hours
    records = []
    
    print(f"Generating {num_records} VPC Flow Log entries across 3 tiers...")

    for i in range(num_records):
        # Time progression
        timestamp = base_time + int((i / num_records) * 86400 * 2) + random.randint(0, 10)
        start_time = timestamp
        end_time = timestamp + random.randint(15, 60)
        
        # Decide traffic scenario
        rand_scenario = random.random()
        
        if rand_scenario < 0.45:
            # 1. Normal Internet to ALB HTTPS traffic
            src_ip = random.choice(legitimate_clients)
            target_alb = random.choice(["alb_1a", "alb_1b"])
            dst_ip = internal_ips[target_alb]
            eni = "eni-01a_alb_01" if target_alb == "alb_1a" else "eni-01b_alb_02"
            src_port = random.randint(32768, 65535)
            dst_port = random.choice([443, 80])
            protocol = 6 # TCP
            packets = random.randint(8, 45)
            bytes_transferred = packets * random.randint(300, 1450)
            action = "ACCEPT"
            log_status = "OK"
            tier = "Public"
            scenario_name = "Public Ingress HTTPS/HTTP"

        elif rand_scenario < 0.70:
            # 2. ALB to Application Nodes (Internal Forwarding)
            src_alb = random.choice(["alb_1a", "alb_1b"])
            src_ip = internal_ips[src_alb]
            target_app = random.choice(["app_1a", "app_1b"])
            dst_ip = internal_ips[target_app]
            eni = "eni-10a_app_01" if target_app == "app_1a" else "eni-20b_app_02"
            src_port = random.randint(32768, 65535)
            dst_port = 8080 # App microservice port
            protocol = 6 # TCP
            packets = random.randint(12, 60)
            bytes_transferred = packets * random.randint(500, 1500)
            action = "ACCEPT"
            log_status = "OK"
            tier = "Application"
            scenario_name = "ALB to App Service"

        elif rand_scenario < 0.85:
            # 3. Application Tier to Database Tier (Secure Query)
            src_app = random.choice(["app_1a", "app_1b"])
            src_ip = internal_ips[src_app]
            dst_ip = internal_ips["rds_primary"]
            eni = "eni-100a_rds_01"
            src_port = random.randint(32768, 65535)
            dst_port = 5432 # PostgreSQL
            protocol = 6 # TCP
            packets = random.randint(15, 120)
            bytes_transferred = packets * random.randint(800, 2400)
            action = "ACCEPT"
            log_status = "OK"
            tier = "Database"
            scenario_name = "App to RDS PostgreSQL (Allowed by SG)"

        elif rand_scenario < 0.92:
            # 4. App Tier Outbound to Internet via NAT Gateway (OS security updates, S3 API)
            src_app = random.choice(["app_1a", "app_1b"])
            src_ip = internal_ips[src_app]
            dst_ip = random.choice(["151.101.65.140", "52.216.128.32", "140.82.113.4"]) # GitHub / AWS S3 / PyPI
            eni = "eni-01a_nat_01" if src_app == "app_1a" else "eni-01b_nat_02"
            src_port = random.randint(40000, 65535)
            dst_port = 443
            protocol = 6 # TCP
            packets = random.randint(20, 150)
            bytes_transferred = packets * random.randint(1000, 1500)
            action = "ACCEPT"
            log_status = "OK"
            tier = "Public"
            scenario_name = "Private Subnet Egress via NAT Gateway"

        elif rand_scenario < 0.96:
            # 5. ATTACK SCENARIO: Direct Internet attempt to access Database Subnet (Port 5432 / 3306)
            src_ip = random.choice(malicious_ips)
            dst_ip = random.choice([internal_ips["rds_primary"], internal_ips["rds_standby"]])
            eni = "eni-100a_rds_01"
            src_port = random.randint(30000, 65000)
            dst_port = random.choice([5432, 3306, 1433, 27017])
            protocol = 6
            packets = random.randint(1, 3)
            bytes_transferred = packets * 54
            action = "REJECT" # Blocked by DB Security Group & Isolated Subnet Route Table!
            log_status = "OK"
            tier = "Database"
            scenario_name = "SECURITY ALERT: Unauthorized External DB Probe (Blocked by SG)"

        elif rand_scenario < 0.985:
            # 6. ATTACK SCENARIO: SSH Brute Force attempt on Public Tier / Bastion
            src_ip = random.choice(malicious_ips)
            dst_ip = internal_ips["bastion"]
            eni = "eni-01a_bas_01"
            src_port = random.randint(40000, 65000)
            dst_port = 22 # SSH
            protocol = 6
            packets = random.randint(1, 4)
            bytes_transferred = packets * 64
            action = "REJECT" # Blocked by Bastion SG restricting SSH to corporate IP
            log_status = "OK"
            tier = "Public"
            scenario_name = "SECURITY ALERT: Unauthorized SSH Attempt (Blocked by SG)"

        else:
            # 7. ATTACK SCENARIO: Rapid Port Scanning Reconnaissance
            src_ip = random.choice(malicious_ips)
            target = random.choice(["alb_1a", "app_1a", "rds_primary"])
            dst_ip = internal_ips[target]
            eni = "eni-01a_alb_01" if "alb" in target else ("eni-10a_app_01" if "app" in target else "eni-100a_rds_01")
            src_port = random.randint(40000, 65000)
            dst_port = random.choice([21, 23, 25, 445, 1433, 3389, 8080, 9200, 27017])
            protocol = 6
            packets = 1
            bytes_transferred = 44
            action = "REJECT"
            log_status = "OK"
            tier = "Public" if "alb" in target else ("Application" if "app" in target else "Database")
            scenario_name = "SECURITY ALERT: Port Scanning Reconnaissance (Blocked by NACL/SG)"

        record = {
            "version": "2",
            "account_id": account_id,
            "interface_id": eni,
            "src_addr": src_ip,
            "dst_addr": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "protocol_name": "TCP" if protocol == 6 else ("UDP" if protocol == 17 else "ICMP"),
            "packets": packets,
            "bytes": bytes_transferred,
            "start_time": start_time,
            "end_time": end_time,
            "timestamp_iso": datetime.fromtimestamp(start_time, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
            "action": action,
            "log_status": log_status,
            "tier": tier,
            "scenario": scenario_name
        }
        records.append(record)

    # Sort chronologically
    records.sort(key=lambda x: x["start_time"])

    # Write CSV
    with open(output_csv, mode="w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "version", "account_id", "interface_id", "src_addr", "dst_addr",
            "src_port", "dst_port", "protocol", "protocol_name", "packets", "bytes",
            "start_time", "end_time", "timestamp_iso", "action", "log_status", "tier", "scenario"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in records:
            writer.writerow(r)

    # Write JSON (sampled summary + first 500 for fast frontend ingestion)
    with open(output_json, mode="w", encoding="utf-8") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_records": len(records),
            "vpc_id": vpc_id,
            "records": records[:1000],  # Embedded preview records
            "metadata": {
                "subnets": subnets,
                "internal_ips": internal_ips,
                "malicious_ips": malicious_ips
            }
        }, f, indent=2)

    print(f"[SUCCESS] Generated {len(records)} flow logs in {output_csv} and {output_json}")

if __name__ == "__main__":
    generate_vpc_dataset()
