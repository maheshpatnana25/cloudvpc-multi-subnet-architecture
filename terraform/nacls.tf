# ==========================================
# 1. PUBLIC SUBNET NETWORK ACL (Defense in Depth)
# ==========================================
resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.public_1.id, aws_subnet.public_2.id]

  # Allow Inbound HTTP
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }

  # Allow Inbound HTTPS
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Allow Inbound Ephemeral return ports (for outbound requests)
  ingress {
    rule_no    = 120
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Outbound Allow All (Stateless return traffic)
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "${var.environment}-public-nacl"
  }
}

# ==========================================
# 2. APPLICATION SUBNET NETWORK ACL
# ==========================================
resource "aws_network_acl" "app" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.app_1.id, aws_subnet.app_2.id]

  # Allow Inbound traffic on app port from VPC
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 8080
    to_port    = 8080
  }

  # Allow Inbound SSH from Public Subnets (Bastion)
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.public_subnet_cidrs[0]
    from_port  = 22
    to_port    = 22
  }

  # Allow Inbound Ephemeral response ports
  ingress {
    rule_no    = 120
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Outbound Allow All
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name = "${var.environment}-app-nacl"
  }
}

# ==========================================
# 3. DATABASE SUBNET NETWORK ACL (Isolated)
# ==========================================
resource "aws_network_acl" "db" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = [aws_subnet.db_1.id, aws_subnet.db_2.id]

  # Inbound DB queries ONLY from App Subnet 1
  ingress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.app_subnet_cidrs[0]
    from_port  = 5432
    to_port    = 5432
  }

  # Inbound DB queries ONLY from App Subnet 2
  ingress {
    rule_no    = 101
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.app_subnet_cidrs[1]
    from_port  = 5432
    to_port    = 5432
  }

  # Outbound response to App Subnets ephemeral ports
  egress {
    rule_no    = 100
    protocol   = "tcp"
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 1024
    to_port    = 65535
  }

  tags = {
    Name = "${var.environment}-db-nacl"
  }
}
