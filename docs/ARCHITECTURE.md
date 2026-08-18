# Virtual Private Cloud (VPC) Multi-Subnet Architecture Specification

## 1. Executive Summary
This document provides the formal architectural design of a high-availability, multi-tier **Virtual Private Cloud (VPC)** designed to host an enterprise web application with mission-critical security isolation. The network topology segregates public entry points from compute containers and private database clusters across two Availability Zones (`us-east-1a` and `us-east-1b`).

---

## 2. High-Level Network Topology Diagram

```
+-----------------------------------------------------------------------------------------------------------------------+
|  AWS Virtual Private Cloud (VPC): 10.0.0.0/16 (us-east-1)                                                             |
|                                                                                                                       |
|  [Internet Gateway: igw-01] <====================================================== (Public Internet Traffic)         |
|         |                                                                                                             |
|         +---------------------------------------+---------------------------------------+                             |
|                                                 |                                       |                             |
|  +-------------------------------------------+  |  +-------------------------------------------+                      |
|  | AVAILABILITY ZONE 1 (us-east-1a)          |  |  | AVAILABILITY ZONE 2 (us-east-1b)          |                      |
|  |                                           |  |  |                                           |                      |
|  | +---------------------------------------+ |  |  | +---------------------------------------+ |                      |
|  | | PUBLIC SUBNET 1a (10.0.1.0/24)        | |  |  | | PUBLIC SUBNET 1b (10.0.2.0/24)        | |                      |
|  | | - Application Load Balancer (Primary) | |  |  | | - ALB Standby Ingress Node          | |                      |
|  | | - NAT Gateway 1a (EIP: 54.210.10.22)  | |  |  | | - NAT Gateway 1b (EIP: 54.210.20.44)  | |                      |
|  | | - Bastion Host (10.0.1.200)           | |  |  | +---------------------------------------+ |                      |
|  | +---------------------------------------+ |  |                        |                     |                      |
|  |                   |                       |  |                        |                     |                      |
|  |                   v (Port 8080)           |  |                        v (Port 8080)         |                      |
|  | +---------------------------------------+ |  |  +---------------------------------------+ |                      |
|  | | APP PRIVATE SUBNET 1a (10.0.10.0/24)  | |  |  | | APP PRIVATE SUBNET 1b (10.0.20.0/24)  | |                      |
|  | | - Web / API Compute Instances (EC2)   | |  |  | | - Web / API Compute Instances (EC2)   | |                      |
|  | | - Outbound Egress: -> NAT Gateway 1a  | |  |  | | - Outbound Egress: -> NAT Gateway 1b  | |                      |
|  | +---------------------------------------+ |  |  +---------------------------------------+ |                      |
|  |                   |                       |  |                        |                     |                      |
|  |                   v (Port 5432)           |  |                        v (Port 5432)         |                      |
|  | +---------------------------------------+ |  |  +---------------------------------------+ |                      |
|  | | DB ISOLATED SUBNET 1a (10.0.100.0/24) | |  |  | | DB ISOLATED SUBNET 1b (10.0.200.0/24) | |                      |
|  | | - RDS Aurora PostgreSQL (Primary)     | |  |  | | - RDS Aurora Standby Replica         | |                      |
|  | | - Route: Local VPC Only (No 0.0.0.0/0)| |  |  | | - Route: Local VPC Only (No 0.0.0.0/0)| |                      |
|  | +---------------------------------------+ |  |  +---------------------------------------+ |                      |
|  |                   ^                       |  |                        ^                     |                      |
|  |                   +=======================|==|========================+                     |                      |
|  |                                (Sync Storage Replication)                                   |                      |
|  +-------------------------------------------+  |  +-------------------------------------------+                      |
|                                                 |                                                                     |
|  [S3 VPC Gateway Endpoint: vpce-s3-01] <========+ (Direct Private S3 API Access)                                     |
+-----------------------------------------------------------------------------------------------------------------------+
```

---

## 3. CIDR Subnetting Matrix

| Subnet Identifier | Name | Tier | CIDR Block | Total IPs | Usable IPs | Route Table | Associated NACL |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `subnet-01a_pub_01` | `prod-public-subnet-1a` | Public | `10.0.1.0/24` | 256 | 251 | `rtb-public` | `nacl-public` |
| `subnet-01b_pub_02` | `prod-public-subnet-1b` | Public | `10.0.2.0/24` | 256 | 251 | `rtb-public` | `nacl-public` |
| `subnet-10a_app_01` | `prod-app-private-subnet-1a` | Application | `10.0.10.0/24` | 256 | 251 | `rtb-app-az1` | `nacl-app` |
| `subnet-20b_app_02` | `prod-app-private-subnet-1b` | Application | `10.0.20.0/24` | 256 | 251 | `rtb-app-az2` | `nacl-app` |
| `subnet-100a_db_01` | `prod-db-isolated-subnet-1a` | Database | `10.0.100.0/24` | 256 | 251 | `rtb-db-isolated` | `nacl-db` |
| `subnet-200b_db_02` | `prod-db-isolated-subnet-1b` | Database | `10.0.200.0/24` | 256 | 251 | `rtb-db-isolated` | `nacl-db` |

> [!NOTE]
> **AWS Reserved IP Allocation:**
> For any AWS subnet (e.g. `10.0.1.0/24`):
> 1. `10.0.1.0`: Network address.
> 2. `10.0.1.1`: Reserved by AWS for the VPC router.
> 3. `10.0.1.2`: Reserved by AWS for DNS (AmazonProvidedDNS).
> 4. `10.0.1.3`: Reserved by AWS for future use.
> 5. `10.0.1.255`: Network broadcast address (AWS does not support broadcast, but address is reserved).

---

## 4. Route Table Configuration

### Public Route Table (`rtb-public`)
- `10.0.0.0/16` -> `local` (VPC internal communication)
- `0.0.0.0/0` -> `igw-09a8b7c6d5e4f3a21` (Internet Gateway)

### Application Route Table AZ-1 (`rtb-app-az1`)
- `10.0.0.0/16` -> `local`
- `0.0.0.0/0` -> `nat-01a2b3c4d5e6f7001` (NAT Gateway in AZ-1a)
- `pl-63a5400a (S3)` -> `vpce-0123456789abcdef0` (VPC Gateway Endpoint)

### Application Route Table AZ-2 (`rtb-app-az2`)
- `10.0.0.0/16` -> `local`
- `0.0.0.0/0` -> `nat-02a2b3c4d5e6f7002` (NAT Gateway in AZ-1b)
- `pl-63a5400a (S3)` -> `vpce-0123456789abcdef0` (VPC Gateway Endpoint)

### Isolated Database Route Table (`rtb-db-isolated`)
- `10.0.0.0/16` -> `local`
- **NO 0.0.0.0/0 Route**: Guarantees databases cannot initiate or receive internet traffic.

---

## 5. Security Group Chaining Model (Stateful)

```
[Public Internet]
       |
       | Port 443 / 80
       v
+-------------------------------+
|   sg-01_alb (ALB SG)          |
| Ingress: 0.0.0.0/0 :443, :80  |
+-------------------------------+
       |
       | Port 8080
       v
+-------------------------------+
|   sg-02_app (App SG)          |
| Ingress: sg-01_alb :8080      |
| Ingress: sg-bastion :22       |
+-------------------------------+
       |
       | Port 5432
       v
+-------------------------------+
|   sg-03_db (Database SG)      |
| Ingress: sg-02_app :5432 ONLY |
+-------------------------------+
```
