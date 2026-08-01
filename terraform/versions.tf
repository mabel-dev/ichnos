terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # State is deliberately NOT local by default - losing local state means losing track
  # of every resource below, including things (DynamoDB tables holding the exclusion
  # list) you really don't want to accidentally recreate. See README.md for the
  # one-time bootstrap of the S3 backend before the first `terraform init` here.
  backend "s3" {
    # bucket, key, region, dynamodb_table are supplied via `-backend-config` at
    # `terraform init` time (or a backend.hcl file, gitignored) rather than hardcoded
    # here, since the backend bucket name isn't knowable until you've run the
    # bootstrap step in README.md.
  }
}
