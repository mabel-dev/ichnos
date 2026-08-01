# Allocated independently of the instance - this is the fixed identity (design doc §2)
# that must survive an ASG replacing the instance. user_data reassociates it on boot
# (compute.tf); the IAM role's ec2:AssociateAddress permission is scoped to exactly
# this one allocation (iam.tf).
resource "aws_eip" "scanner" {
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-scanner"
  }
}
