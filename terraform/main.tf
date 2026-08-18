terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "CloudVPC-Multi-Subnet"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# --- VPC Core ---
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.environment}-vpc"
    Tier = "Network-Core"
  }
}

# --- Internet Gateway ---
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.environment}-igw"
  }
}

# --- Elastic IPs for NAT Gateways ---
resource "aws_eip" "nat_eip_1" {
  domain     = "vpc"
  depends_on = [aws_internet_gateway.gw]
  tags = {
    Name = "${var.environment}-nat-eip-1"
  }
}

resource "aws_eip" "nat_eip_2" {
  domain     = "vpc"
  depends_on = [aws_internet_gateway.gw]
  tags = {
    Name = "${var.environment}-nat-eip-2"
  }
}

# --- NAT Gateways (Multi-AZ for High Availability) ---
resource "aws_nat_gateway" "nat_1" {
  allocation_id = aws_eip.nat_eip_1.id
  subnet_id     = aws_subnet.public_1.id

  tags = {
    Name = "${var.environment}-nat-gw-1a"
  }
}

resource "aws_nat_gateway" "nat_2" {
  allocation_id = aws_eip.nat_eip_2.id
  subnet_id     = aws_subnet.public_2.id

  tags = {
    Name = "${var.environment}-nat-gw-1b"
  }
}

# --- S3 Gateway Endpoint (Zero Cost & Direct Internal Routing) ---
resource "aws_vpc_endpoint" "s3" {
  vpc_id          = aws_vpc.main.id
  service_name    = "com.amazonaws.${var.aws_region}.s3"
  route_table_ids = [aws_route_table.app_1.id, aws_route_table.app_2.id]

  tags = {
    Name = "${var.environment}-s3-endpoint"
  }
}
