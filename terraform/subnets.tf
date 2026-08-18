# ==========================================
# 1. PUBLIC TIER SUBNETS (Multi-AZ)
# ==========================================
resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[0]
  availability_zone       = var.availability_zones[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.environment}-public-subnet-1a"
    Tier = "Public"
    Role = "ALB-NAT-Bastion"
  }
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[1]
  availability_zone       = var.availability_zones[1]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.environment}-public-subnet-1b"
    Tier = "Public"
    Role = "ALB-NAT-Bastion"
  }
}

# ==========================================
# 2. APPLICATION / PRIVATE SUBNETS (Multi-AZ)
# ==========================================
resource "aws_subnet" "app_1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.app_subnet_cidrs[0]
  availability_zone       = var.availability_zones[0]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.environment}-app-private-subnet-1a"
    Tier = "Application"
    Role = "Web-App-Nodes"
  }
}

resource "aws_subnet" "app_2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.app_subnet_cidrs[1]
  availability_zone       = var.availability_zones[1]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.environment}-app-private-subnet-1b"
    Tier = "Application"
    Role = "Web-App-Nodes"
  }
}

# ==========================================
# 3. DATABASE / ISOLATED SUBNETS (Multi-AZ)
# ==========================================
resource "aws_subnet" "db_1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.db_subnet_cidrs[0]
  availability_zone       = var.availability_zones[0]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.environment}-db-isolated-subnet-1a"
    Tier = "Database"
    Role = "RDS-Cluster-Master"
  }
}

resource "aws_subnet" "db_2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.db_subnet_cidrs[1]
  availability_zone       = var.availability_zones[1]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.environment}-db-isolated-subnet-1b"
    Tier = "Database"
    Role = "RDS-Cluster-Replica"
  }
}

# Database Subnet Group for RDS
resource "aws_db_subnet_group" "rds" {
  name        = "${var.environment}-db-subnet-group"
  description = "Isolated database subnets for RDS Multi-AZ"
  subnet_ids  = [aws_subnet.db_1.id, aws_subnet.db_2.id]

  tags = {
    Name = "${var.environment}-db-subnet-group"
  }
}
