output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "The CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = [aws_subnet.public_1.id, aws_subnet.public_2.id]
}

output "app_subnet_ids" {
  description = "IDs of the private application subnets"
  value       = [aws_subnet.app_1.id, aws_subnet.app_2.id]
}

output "db_subnet_ids" {
  description = "IDs of the isolated database subnets"
  value       = [aws_subnet.db_1.id, aws_subnet.db_2.id]
}

output "nat_gateway_ips" {
  description = "Public Elastic IP addresses of the NAT Gateways"
  value       = [aws_eip.nat_eip_1.public_ip, aws_eip.nat_eip_2.public_ip]
}

output "security_groups" {
  description = "Map of created Security Group IDs"
  value = {
    alb_sg     = aws_security_group.alb.id
    bastion_sg = aws_security_group.bastion.id
    app_sg     = aws_security_group.app.id
    db_sg      = aws_security_group.db.id
  }
}

output "db_subnet_group_name" {
  description = "Name of the RDS DB Subnet Group"
  value       = aws_db_subnet_group.rds.name
}
