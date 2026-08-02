# Table names and partition key attribute names below match storage/dynamodb.py
# exactly (design doc §3.1) - changing either here requires changing the code (or
# setting the corresponding ICHNOS_*_TABLE env var) to match.

resource "aws_dynamodb_table" "exclusions" {
  name         = "Exclusions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "ip_or_cidr"

  attribute {
    name = "ip_or_cidr"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  # Losing an opt-out is a compliance problem, not just an inconvenience (design doc
  # §12) - PITR here, unlike CurrentState below.
  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_dynamodb_table" "scan_schedule" {
  name         = "ScanSchedule"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "protocol"

  attribute {
    name = "protocol"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_dynamodb_table" "current_state" {
  name         = "CurrentState"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "key"

  attribute {
    name = "key"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  # No PITR - rebuildable by re-deriving from recently-published Observations/Versions
  # in Opteryx if ever lost (design doc §12), and at MVP volume this table stays small
  # enough that the cost of PITR isn't worth it either way.
}
