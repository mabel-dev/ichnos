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

# Which fingerprints have ever had a Versions row published. Deliberately NOT folded
# into CurrentState: that table answers "what is this host serving now?" and is keyed by
# host, which is exactly the question that produced duplicate version rows when it was
# used to answer "have we published this payload?" as well (see storage/base.py's
# VersionIndexStore). One item per distinct fingerprint, written once, never updated.
resource "aws_dynamodb_table" "version_index" {
  name         = "VersionIndex"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "fingerprint_id"

  attribute {
    name = "fingerprint_id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  # No PITR, and no TTL. Losing this table means already-published fingerprints get
  # republished once each - duplicate rows, the exact bug it exists to prevent - so it
  # must not expire items, but it is rebuildable from `ichnos.landing.versions` (a
  # SELECT DISTINCT fingerprint_id load) rather than needing point-in-time recovery.
}
