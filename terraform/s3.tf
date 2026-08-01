data "aws_caller_identity" "current" {}

# One bucket, two prefixes - keeps the IAM policy in iam.tf to a single bucket ARN.
#   raw-logs/          audit trail of raw scan output (design doc §12), short retention
#   jurisdiction/       jurisdiction-blocklist.conf, S3-backed so a freshly-replaced
#                        instance doesn't start scanning with an empty exclusion list
#                        before the next weekly refresh (a gap identified while
#                        building this - see conversation/commit history)
resource "aws_s3_bucket" "data" {
  bucket = "${var.project_name}-data-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "expire-raw-logs"
    status = "Enabled"
    filter {
      prefix = "raw-logs/"
    }
    expiration {
      days = 30
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  rule {
    id     = "expire-old-jurisdiction-versions"
    status = "Enabled"
    filter {
      prefix = "jurisdiction/"
    }
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}
