data "aws_ami" "ubuntu_arm64" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    region                        = var.aws_region
    eip_allocation_id             = aws_eip.scanner.id
    exclusions_table              = aws_dynamodb_table.exclusions.name
    schedule_table                = aws_dynamodb_table.scan_schedule.name
    scan_metadata_table           = aws_dynamodb_table.scan_metadata.name
    current_state_table           = aws_dynamodb_table.current_state.name
    rate_interval_seconds         = var.rate_interval_seconds
    scan_candidates_per_cron_tick = var.scan_candidates_per_cron_tick
    opteryx_workspace             = var.opteryx_workspace
    opteryx_collection            = var.opteryx_collection
    opteryx_pat_secret_arn        = aws_secretsmanager_secret.opteryx_pat.arn
    organisation_name             = var.organisation_name
    abuse_email                   = var.abuse_email
    domain_name                   = var.domain_name
    jurisdiction_countries        = join(",", var.jurisdiction_countries)
    jurisdiction_s3_bucket        = aws_s3_bucket.data.bucket
    jurisdiction_s3_key           = "jurisdiction/jurisdiction-blocklist.conf"
    ichnos_git_url                = var.ichnos_git_url
    ichnos_git_ref                = var.ichnos_git_ref
    log_group_name                = aws_cloudwatch_log_group.scanner.name
  })
}

resource "aws_launch_template" "scanner" {
  name_prefix   = "${var.project_name}-scanner-"
  image_id      = data.aws_ami.ubuntu_arm64.id
  instance_type = var.instance_type

  iam_instance_profile {
    name = aws_iam_instance_profile.scanner.name
  }

  vpc_security_group_ids = [aws_security_group.scanner.id]

  # IMDSv2 required - user_data itself uses the token-based metadata flow.
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }

  user_data = base64encode(local.user_data)

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project_name}-scanner"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "scanner" {
  name                = "${var.project_name}-scanner"
  desired_capacity    = 1
  min_size            = 1
  max_size            = 1
  vpc_zone_identifier = [aws_subnet.public.id]
  health_check_type   = "EC2"

  # Best-effort - EC2 health checks don't know this instance is "healthy" in any
  # ichnos-specific sense (e.g. actually scanning), just that it's running. See design
  # doc §12: region/AZ loss and deeper health semantics are explicitly out of scope
  # for the MVP single-instance deployment.
  health_check_grace_period = 300

  launch_template {
    id      = aws_launch_template.scanner.id
    version = aws_launch_template.scanner.latest_version
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-scanner"
    propagate_at_launch = true
  }
}
