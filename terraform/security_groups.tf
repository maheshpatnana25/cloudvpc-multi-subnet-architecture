# ==========================================
# 1. APPLICATION LOAD BALANCER SECURITY GROUP
# ==========================================
resource "aws_security_group" "alb" {
  name        = "${var.environment}-alb-sg"
  description = "Permit inbound HTTPS and HTTP from internet"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Allow HTTP for redirect to HTTPS"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description     = "Allow outbound to Application Tier SG"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  tags = {
    Name = "${var.environment}-alb-sg"
  }
}

# ==========================================
# 2. BASTION / JUMP HOST SECURITY GROUP
# ==========================================
resource "aws_security_group" "bastion" {
  name        = "${var.environment}-bastion-sg"
  description = "Permit SSH only from approved corporate IP"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow SSH from corporate network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.corporate_ip_cidr]
  }

  egress {
    description     = "Allow SSH forwarding to App Tier SG"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  tags = {
    Name = "${var.environment}-bastion-sg"
  }
}

# ==========================================
# 3. APPLICATION TIER SECURITY GROUP
# ==========================================
resource "aws_security_group" "app" {
  name        = "${var.environment}-app-sg"
  description = "Permit traffic only from ALB and Bastion"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Allow HTTP from ALB SG"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description     = "Allow SSH from Bastion SG"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }

  egress {
    description     = "Allow PostgreSQL queries to DB Tier SG"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.db.id]
  }

  egress {
    description = "Allow Outbound HTTPS via NAT for OS updates and S3 API"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-app-sg"
  }
}

# ==========================================
# 4. DATABASE TIER SECURITY GROUP
# Strictly permit connections ONLY from App Tier SG
# ==========================================
resource "aws_security_group" "db" {
  name        = "${var.environment}-db-sg"
  description = "Strictly permit database traffic only from App Tier"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Allow PostgreSQL from App Tier SG only"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  tags = {
    Name = "${var.environment}-db-sg"
  }
}
