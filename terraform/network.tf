# This account has no default VPC in us-east-1, and the one non-default VPC that does
# exist is completely untagged - no way to know what else depends on it. Rather than
# guess, ichnos gets its own small dedicated VPC: one public subnet, one AZ (design doc
# §12 already accepts single-AZ as an MVP trade-off), one instance. This also keeps the
# blast-radius isolation the design doc recommends for a scanning project - its own
# security group in its own VPC, not mixed into whatever else runs in the account.
resource "aws_vpc" "ichnos" {
  cidr_block           = "10.42.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}"
  }
}

resource "aws_internet_gateway" "ichnos" {
  vpc_id = aws_vpc.ichnos.id

  tags = {
    Name = "${var.project_name}"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.ichnos.id
  cidr_block              = "10.42.0.0/26"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.ichnos.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ichnos.id
  }

  tags = {
    Name = "${var.project_name}-public"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Inbound 80/443 only - no SSH. Shell access is via SSM Session Manager (network.tf's
# IAM counterpart in iam.tf grants the SSM managed instance policy), per design doc §2:
# "no SSH inbound from the internet." Outbound is unrestricted at the network layer -
# the request budget is enforced in the application (ratelimit.py), not by the network.
resource "aws_security_group" "scanner" {
  name        = "${var.project_name}-scanner"
  description = "ichnos scanner: public info page/opt-out only, no SSH"
  vpc_id      = aws_vpc.ichnos.id

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
