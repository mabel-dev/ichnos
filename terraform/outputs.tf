output "name_servers" {
  description = "Set these as the custom nameservers for the domain in Squarespace's domain management UI (README.md's manual delegation step)."
  value       = aws_route53_zone.main.name_servers
}

output "scanner_public_ip" {
  description = "The fixed Elastic IP."
  value       = aws_eip.scanner.public_ip
}

output "eip_allocation_id" {
  description = "Needed for the manual reverse-DNS step (README.md) - `aws ec2 modify-address-attribute --allocation-id <this> --domain-name scan.<domain>`."
  value       = aws_eip.scanner.id
}

output "opteryx_pat_secret_arn" {
  description = "Populate this secret's value out-of-band (see README.md) before the instance boots, or `ichnos publish` will fail until it's set and the instance is replaced/restarted."
  value       = aws_secretsmanager_secret.opteryx_pat.arn
}

output "data_bucket" {
  description = "S3 bucket holding the jurisdiction blocklist (jurisdiction/) - raw scan logs (raw-logs/) aren't written yet, see iam.tf's comment."
  value       = aws_s3_bucket.data.bucket
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.scanner.name
}

output "dynamodb_tables" {
  value = {
    exclusions    = aws_dynamodb_table.exclusions.name
    schedule      = aws_dynamodb_table.scan_schedule.name
    current_state = aws_dynamodb_table.current_state.name
    version_index = aws_dynamodb_table.version_index.name
  }
}
