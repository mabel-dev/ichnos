# ichnos Terraform (Phase 1)

Provisions the AWS side of the design doc's MVP: one self-healing EC2 worker behind a
fixed EIP, DynamoDB operational tables, S3 for the jurisdiction blocklist, Secrets
Manager for the Opteryx PAT, a scoped IAM role, Route 53 DNS, and basic CloudWatch
alarms. See [`../scan.opteryx/DESIGN.md`](../../scan.opteryx/DESIGN.md) for the full
design rationale.

**This has not been applied.** Nothing here has created any real AWS resources yet -
`terraform validate` passes locally, but `apply` needs your AWS credentials, which
aren't configured in this environment.

## Prerequisites

- Terraform >= 1.5 (`brew install hashicorp/tap/terraform` if you don't have it)
- AWS credentials for the target account, configured however you normally do that
  (`aws configure`, SSO, env vars) - not through this repo or this chat
- The domain (`ichnos.online`) already registered - done
- An Opteryx PAT already provisioned for the `scan`/`measurement` workspace - done,
  per your earlier answer; you'll need the `client_id`/`client_secret` values handy
  for the manual step below (never paste them into chat or a Terraform file)

## One-time: bootstrap the state backend

`versions.tf` uses an S3 backend deliberately, not local state - losing local state
here means losing track of every resource, including the DynamoDB tables holding the
live exclusion list. This can't be created by the same Terraform config that needs it
to exist first, so it's a plain AWS CLI step, once, ever:

```bash
aws s3api create-bucket --bucket ichnos-terraform-state-<your-account-id> \
  --region us-east-1
aws s3api put-bucket-versioning --bucket ichnos-terraform-state-<your-account-id> \
  --versioning-configuration Status=Enabled
aws dynamodb create-table --table-name ichnos-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST --region us-east-1
```

## Configure

```bash
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars - abuse_email is required, everything else has a sensible default
```

## Init and apply

```bash
terraform init \
  -backend-config="bucket=ichnos-terraform-state-<your-account-id>" \
  -backend-config="key=ichnos/terraform.tfstate" \
  -backend-config="region=us-east-1" \
  -backend-config="dynamodb_table=ichnos-terraform-locks"

terraform plan
terraform apply
```

## Manual steps after `apply` (none of these are automatable from here)

1. **Delegate the domain.** `terraform output name_servers` prints 4 NS values. Set
   those as `ichnos.online`'s custom nameservers in Squarespace's domain management UI.
   Cert issuance (a cron job on the instance) will fail harmlessly and retry every 30
   minutes until this propagates - that's expected, not a bug, see the comment in
   `user_data.sh.tftpl`.
2. **Populate the Opteryx PAT.** Terraform only creates an empty secret shell:
   ```bash
   aws secretsmanager put-secret-value \
     --secret-id "$(terraform output -raw opteryx_pat_secret_arn)" \
     --secret-string '{"client_id":"...","client_secret":"opt_..._01"}'
   ```
   Run this yourself, directly - the values shouldn't pass through this repo, Terraform
   state, or any chat session. If the instance already booted before this is set,
   terminate it (the ASG will launch a replacement that picks up the now-populated
   secret) rather than waiting for the next scheduled replacement.
3. **Set the PTR record.** No AWS Support case needed - `modify-address-attribute` is
   self-service:
   ```bash
   aws ec2 modify-address-attribute \
     --allocation-id "$(terraform output -raw eip_allocation_id)" \
     --domain-name "scan.ichnos.online" \
     --region us-east-1
   ```
   `dns.tf`'s `scanner_ptr_target` record (`scan.ichnos.online -> the EIP`) must exist
   and have propagated *before* running this - AWS validates the forward record
   resolves before accepting the PTR. Not the bare root domain - a dedicated
   subdomain, since the root already serves the public info page over its own cert
   and this hostname isn't meant to be browsed to directly. The [ZMap best-practices
   guidance](https://github.com/zmap/zmap/wiki/Scanning-Best-Practices) this project
   follows specifically calls out publishing reverse DNS, so it's worth doing
   promptly rather than as an afterthought.
4. **Confirm the SNS email subscription.** AWS emails a confirmation link to
   `abuse_email` after `apply` - alarms won't deliver until it's clicked.

## Verifying it worked

```bash
curl -I http://ichnos.online/        # should work almost immediately
curl -I https://ichnos.online/       # works once certbot succeeds (after NS delegation)
aws logs tail /ichnos/scanner --follow --region us-east-1
```

Check the info page lists the `http`/`https` schedule entries, and that
`/ichnos/scanner`'s log streams show scan/publish activity within the first hour.

## Known gaps, not resolved by this configuration

- **Raw scan-log audit trail isn't implemented in the app** (design doc §12 describes
  it; the code doesn't write to `s3://<bucket>/raw-logs/` yet) - the IAM policy
  deliberately doesn't grant that prefix yet either (`iam.tf`'s comment). Add both
  together when that feature lands.
- **Single region, single AZ** - explicitly accepted as an MVP trade-off (design doc
  §12), not addressed here.
- **Cost**: roughly matches the design doc's ~$18–26/month estimate; this adds Route 53
  hosted zone ($0.50/mo) and CloudWatch alarms/SNS (negligible) on top.

## Tearing down

`terraform destroy` removes everything, including the DynamoDB tables (the
`Exclusions`/`ScanSchedule` tables have point-in-time recovery, but PITR doesn't
survive table *deletion* - if you want to keep the exclusion list, export it first).
The Secrets Manager secret has a 7-day recovery window (`secrets.tf`) rather than
immediate deletion.
