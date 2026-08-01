# Empty shell only - the actual PAT value is populated out-of-band via the AWS CLI or
# console after `apply`, never through Terraform state or this chat/repo (secret
# material shouldn't sit in either). See README.md for the exact command.
#
# Expected JSON shape (config.py / cli.py read these via opteryx_upload.PATAuthenticator):
#   {"client_id": "...", "client_secret": "opt_..._01"}
resource "aws_secretsmanager_secret" "opteryx_pat" {
  name        = "${var.project_name}/opteryx-pat"
  description = "Opteryx Upload Service PAT (client_id/client_secret) - value set out-of-band, not by Terraform"

  # Terraform destroy would otherwise schedule a 30-day deletion window by default,
  # which is fine, but a short recovery window is enough for a value nothing else
  # depends on being re-derivable from (just re-issue a new PAT on the Opteryx side).
  recovery_window_in_days = 7
}
