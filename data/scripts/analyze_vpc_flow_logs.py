"""
VPC Flow Logs Data Science & Security Threat Analytics Engine
Analyzes flow logs using Pandas to compute:
- Ingress/Egress bandwidth & packet volumes per subnet tier
- Accept vs Reject ratios
- Top Talker source IPs
- Attack scenario breakdown (Port scans, DB access attempts, SSH brute force)
- Security posture & anomaly metrics
"""

import os
import json
import pandas as pd
import numpy as np

def analyze_flow_logs(csv_path="data/vpc_flow_logs_dataset.csv", output_summary="data/flow_logs_analytics_summary.json"):
    if not os.path.exists(csv_path):
        print(f"Error: Dataset not found at {csv_path}")
        return None
        
    print(f"Loading VPC Flow Logs from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    total_records = len(df)
    total_bytes = int(df["bytes"].sum())
    total_packets = int(df["packets"].sum())
    
    # Action breakdown
    action_counts = df["action"].value_counts().to_dict()
    accept_count = int(action_counts.get("ACCEPT", 0))
    reject_count = int(action_counts.get("REJECT", 0))
    rejection_ratio = round((reject_count / total_records) * 100, 2) if total_records > 0 else 0
    
    # Tier breakdown
    tier_summary = []
    for tier, group in df.groupby("tier"):
        tier_summary.append({
            "tier": tier,
            "records": int(len(group)),
            "total_bytes": int(group["bytes"].sum()),
            "total_packets": int(group["packets"].sum()),
            "accepted": int((group["action"] == "ACCEPT").sum()),
            "rejected": int((group["action"] == "REJECT").sum()),
            "reject_ratio": round(((group["action"] == "REJECT").sum() / len(group)) * 100, 2)
        })
        
    # Top Talkers (Source IPs by Volume)
    top_sources = []
    for ip, group in df.groupby("src_addr")["bytes"].sum().sort_values(ascending=False).head(8).items():
        sub = df[df["src_addr"] == ip]
        is_threat = bool(("ALERT" in str(sub["scenario"].iloc[0])) or (int((sub["action"] == "REJECT").sum()) > 50))
        top_sources.append({
            "ip": str(ip),
            "total_bytes": int(group),
            "packets": int(sub["packets"].sum()),
            "actions": {str(k): int(v) for k, v in sub["action"].value_counts().items()},
            "is_threat": is_threat
        })

    # Destination Port Breakdown
    top_ports = []
    for port, group in df.groupby("dst_port")["bytes"].sum().sort_values(ascending=False).head(8).items():
        sub = df[df["dst_port"] == port]
        top_ports.append({
            "port": int(port),
            "service": get_service_name(int(port)),
            "total_bytes": int(group),
            "records": int(len(sub)),
            "accepted": int((sub["action"] == "ACCEPT").sum()),
            "rejected": int((sub["action"] == "REJECT").sum())
        })

    # Security Threats Detected
    threat_records = df[df["scenario"].str.contains("SECURITY ALERT", na=False)]
    threats = []
    for scenario_name, group in threat_records.groupby("scenario"):
        threats.append({
            "threat_name": str(scenario_name),
            "incident_count": int(len(group)),
            "unique_attackers": int(group["src_addr"].nunique()),
            "attacker_ips": [str(ip) for ip in group["src_addr"].unique()],
            "targeted_ports": [int(p) for p in group["dst_port"].unique()],
            "status": "BLOCKED_BY_FIREWALL",
            "severity": "CRITICAL" if "DB" in scenario_name else ("HIGH" if "SSH" in scenario_name else "MEDIUM")
        })

    # Hourly distribution for charting
    df['timestamp'] = pd.to_datetime(df['start_time'], unit='s')
    hourly = df.set_index('timestamp').resample('4h')[['bytes', 'packets']].sum().reset_index()
    hourly_trend = []
    for _, row in hourly.iterrows():
        hourly_trend.append({
            "time": row['timestamp'].strftime('%m-%d %H:%M'),
            "bytes": int(row['bytes']),
            "packets": int(row['packets'])
        })

    summary = {
        "dataset_metadata": {
            "total_records": total_records,
            "total_bytes": total_bytes,
            "total_bytes_formatted": format_bytes(total_bytes),
            "total_packets": total_packets,
            "accept_count": accept_count,
            "reject_count": reject_count,
            "rejection_ratio_percent": rejection_ratio
        },
        "tier_summary": tier_summary,
        "top_sources": top_sources,
        "top_ports": top_ports,
        "security_threats": threats,
        "traffic_trend": hourly_trend
    }
    
    with open(output_summary, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        
    print(f"[SUCCESS] Analyzed {total_records} records. Summary saved to {output_summary}")
    return summary

def get_service_name(port):
    services = {
        80: "HTTP (Web Ingress)",
        443: "HTTPS (Web Ingress)",
        8080: "App Microservice",
        5432: "PostgreSQL Database",
        3306: "MySQL Database",
        22: "SSH Secure Shell",
        3389: "RDP Remote Desktop",
        1433: "MSSQL",
        27017: "MongoDB",
        9200: "Elasticsearch"
    }
    return services.get(port, f"Custom Port {port}")

def format_bytes(bytes_num):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_num < 1024.0:
            return f"{bytes_num:.2f} {unit}"
        bytes_num /= 1024.0
    return f"{bytes_num:.2f} PB"

if __name__ == "__main__":
    analyze_flow_logs()
