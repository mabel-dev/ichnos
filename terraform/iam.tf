# Least-privilege instance role (design doc §9) - no AdministratorAccess, no wildcard
# resource ARNs except where the AWS action itself doesn't support resource-level
# restriction (noted per-statement below).

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scanner" {
  name               = "${var.project_name}-scanner"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_instance_profile" "scanner" {
  name = "${var.project_name}-scanner"
  role = aws_iam_role.scanner.name
}

# Shell access via SSM Session Manager instead of SSH (design doc §2/§11: "no SSH
# inbound from the internet"). AWS-managed policy, not custom - this is the standard,
# documented way to grant it.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.scanner.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "scanner" {
  statement {
    sid = "DynamoDBOperationalTables"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
      "dynamodb:Query",
      "dynamodb:Scan",
    ]
    resources = [
      aws_dynamodb_table.exclusions.arn,
      aws_dynamodb_table.scan_schedule.arn,
      aws_dynamodb_table.scan_metadata.arn,
      aws_dynamodb_table.current_state.arn,
    ]
  }

  statement {
    sid       = "JurisdictionBlocklistS3"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.data.arn}/jurisdiction/*"]
    # NOTE: raw-logs/* isn't granted here because nothing in the app uploads there
    # yet (design doc §12's raw discovery-log audit trail isn't implemented in code -
    # see ichnos README's "Not yet in this repo"). Add that statement when it is,
    # rather than granting unused access now.
  }

  statement {
    sid       = "OpteryxPatSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [aws_secretsmanager_secret.opteryx_pat.arn]
  }

  statement {
    sid = "ScopedLogsAndMetrics"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams", # needed by the CloudWatch agent tailing /var/log/ichnos/*
    ]
    resources = ["${aws_cloudwatch_log_group.scanner.arn}:*"]
  }

  statement {
    sid       = "MetricsPutOnly"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"] # PutMetricData has no resource-level permissions to scope to
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["ichnos"]
    }
  }

  statement {
    sid       = "ReassociateOwnEip"
    actions   = ["ec2:AssociateAddress"]
    resources = ["arn:aws:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:elastic-ip/${aws_eip.scanner.id}"]
  }

  statement {
    sid     = "CertbotDnsRoute53Write"
    actions = ["route53:ChangeResourceRecordSets"]
    resources = [
      "arn:aws:route53:::hostedzone/${aws_route53_zone.main.zone_id}",
    ]
  }

  statement {
    sid = "CertbotDnsRoute53Read"
    actions = [
      "route53:GetChange",
      "route53:ListHostedZones",
      "route53:ListHostedZonesByName",
      "route53:ListResourceRecordSets",
    ]
    resources = ["*"] # none of these support resource-level restriction
  }
}

resource "aws_iam_role_policy" "scanner" {
  name   = "${var.project_name}-scanner"
  role   = aws_iam_role.scanner.id
  policy = data.aws_iam_policy_document.scanner.json
}
