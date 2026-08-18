variable "aws_region" {
  type        = string
  description = "AWS deployment region"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment name"
  default     = "prod"
}

variable "vpc_cidr" {
  type        = string
  description = "Base CIDR block for the Virtual Private Cloud"
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  type        = list(string)
  description = "List of Availability Zones for Multi-AZ redundancy"
  default     = ["us-east-1a", "us-east-1b"]
}

variable "public_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for Public Ingress Subnets"
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "app_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for Application/Compute Private Subnets"
  default     = ["10.0.10.0/24", "10.0.20.0/24"]
}

variable "db_subnet_cidrs" {
  type        = list(string)
  description = "CIDR blocks for Isolated Database Subnets"
  default     = ["10.0.100.0/24", "10.0.200.0/24"]
}

variable "corporate_ip_cidr" {
  type        = string
  description = "Whitelisted IP range for Bastion SSH admin access"
  default     = "198.51.100.0/24"
}
