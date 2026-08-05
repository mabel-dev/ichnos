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
    region                 = var.aws_region
    eip_allocation_id      = aws_eip.scanner.id
    scanner_public_ip      = aws_eip.scanner.public_ip
    exclusions_table       = aws_dynamodb_table.exclusions.name
    schedule_table         = aws_dynamodb_table.scan_schedule.name
    version_index_table    = aws_dynamodb_table.version_index.name
    rate_interval_seconds  = var.rate_interval_seconds
    zmap_rate_pps          = var.zmap_rate_pps
    scan_protocol_budgets  = var.scan_protocol_budgets
    opteryx_workspace      = var.opteryx_workspace
    opteryx_collection     = var.opteryx_collection
    opteryx_pat_secret_arn = aws_secretsmanager_secret.opteryx_pat.arn
    organisation_name      = var.organisation_name
    abuse_email            = var.abuse_email
    domain_name            = var.domain_name
    jurisdiction_countries = join(",", var.jurisdiction_countries)
    jurisdiction_s3_bucket = aws_s3_bucket.data.bucket
    jurisdiction_s3_key    = "jurisdiction/jurisdiction-blocklist.conf"
    cert_s3_bucket         = aws_s3_bucket.data.bucket
    cert_s3_key            = "certs/letsencrypt.tar.gz"
    ichnos_git_url         = var.ichnos_git_url
    ichnos_git_ref         = var.ichnos_git_ref
    log_group_name         = aws_cloudwatch_log_group.scanner.name
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

  # gzip, not plain base64: EC2 caps user_data at 16384 decoded bytes and this script
  # crossed that (16671 bytes) when the scanner-identity vars were added, which is why
  # `apply` started failing with InvalidUserData.Malformed and the running instance's
  # /etc/ichnos/env drifted behind this template. cloud-init sniffs the gzip magic
  # number and decompresses before executing, so the script itself needs no change -
  # and at ~6.5 KB compressed there's ample headroom for it to keep growing.
  user_data = base64gzip(local.user_data)

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

  # Without this, pointing the ASG at a new launch template version changes nothing
  # about the instance already running - `apply` reports success, the scanner keeps
  # running whatever it booted with, and the drift is invisible unless someone thinks
  # to compare the instance's launch template version against the group's. That is not
  # hypothetical: the 8pps/6400 change found this instance three versions behind (16
  # against the group's 17), so some earlier user_data change had silently never taken
  # effect either. Every setting that reaches the worker does so through user_data (the
  # env file and the cron entries it writes), so "launch template updated" has to mean
  # "instance rebuilt" or an apply is only half a deployment.
  #
  # min_healthy_percentage = 0 because the group is a single instance: any higher and
  # the refresh cannot start, since taking the one instance out of service necessarily
  # drops health to 0%. That means a real gap in scanning while the replacement runs
  # user_data - now up to a full hourly tick rather than a few 15-minute ones, which
  # is the accepted trade for this deployment (design doc §12 puts multi-instance
  # availability out of MVP scope). Publish runs hourly, and cmd_scan writes nothing to
  # pending_dir until a run completes, so a refresh during a run discards that run's
  # results entirely along with anything else pending on the old root volume; run
  # `ichnos publish` first, and prefer refreshing shortly after :05 when a run has just
  # published rather than mid-run.
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 0
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-scanner"
    propagate_at_launch = true
  }
}
