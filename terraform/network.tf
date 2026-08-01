# A single small EC2 instance doesn't need a dedicated VPC - the default VPC's default
# subnets already route to an internet gateway, which is all this needs (design doc §2
# deliberately keeps this to one box, no ALB/NAT/private subnets).
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }

  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

# Inbound 80/443 only - no SSH. Shell access is via SSM Session Manager (network.tf's
# IAM counterpart in iam.tf grants the SSM managed instance policy), per design doc §2:
# "no SSH inbound from the internet." Outbound is unrestricted at the network layer -
# the request budget is enforced in the application (ratelimit.py), not by the network.
resource "aws_security_group" "scanner" {
  name        = "${var.project_name}-scanner"
  description = "ichnos scanner: public info page/opt-out only, no SSH"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "HTTP (public info page, opt-out, certbot HTTP-01 fallback)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS (public info page, opt-out)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "unrestricted outbound - scan traffic + package installs + AWS APIs"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-scanner"
  }
}
