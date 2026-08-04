variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "domain_name" {
  description = "Public domain for the scanner's info page/opt-out/PTR. Registered separately (not by Terraform) - this only creates the Route 53 hosted zone for it. See README.md for the nameserver delegation step at the registrar."
  type        = string
  default     = "ichnos.online"
}

variable "project_name" {
  description = "Short name used to tag/name every resource."
  type        = string
  default     = "ichnos"
}

variable "instance_type" {
  description = "EC2 instance type. Must be an arm64 (Graviton) type - the AMI lookup is arm64-only."
  type        = string
  default     = "t4g.small"
}

variable "abuse_email" {
  description = "Contact address shown on the public info page and used for Let's Encrypt/certbot registration. No sensible default - must be set in terraform.tfvars."
  type        = string
}

variable "organisation_name" {
  description = "Organisation name shown on the public info page."
  type        = string
  default     = "TBD"
}

variable "opteryx_workspace" {
  description = "Opteryx Upload Service workspace this project publishes into."
  type        = string
  default     = "ichnos"
}

variable "opteryx_collection" {
  description = "Opteryx Upload Service collection this project publishes into - a landing zone for raw ingested data, upstream of any curated/refined collections."
  type        = string
  default     = "landing"
}

variable "rate_interval_seconds" {
  description = "Global scan throttle: minimum seconds between outbound requests (design doc §4)."
  type        = number
  default     = 5
}

variable "zmap_rate_pps" {
  description = "Native ZMap discovery rate in whole packets/second (`--rate` rejects fractional values). Mirrors config.py's `zmap_rate_pps` default, which documents how the current figure was arrived at and what to watch after changing it. Sized jointly with `scan_candidates_per_cron_tick` - a run takes roughly `candidates / rate_pps + cooldown_seconds`, so changing this alone changes how much of the hourly cron interval a run consumes."
  type        = number
  default     = 32
}

variable "scan_candidates_per_cron_tick" {
  description = "Candidates per `ichnos scan` invocation - sized so one run takes roughly as long as the cron interval between invocations (see cli.py's module docstring). Native ZMap discovery runs at config.py's zmap_rate_pps (32 pps), so one run takes roughly `candidates / rate_pps + cooldown_seconds` - at the defaults, 105000 candidates takes ~3284s (~54.7 min), leaving a 316s buffer inside the hourly cron interval. There is little room above that figure: 110000 leaves only 4.6% and would not survive the variance measured at 16pps, and the whole sizing depends on the rate being 32 - at 30pps the same candidate count leaves 2.8% and overruns. Sized on *relative* buffer, not absolute: run-to-run variance comes from the serial ZGrab2 backlog, which scales with the candidate count, so the buffer has to scale with it too. 21 measured runs at 12800-in-15-minutes had a median of 803.3s against a predicted 803.0 but a worst case of 864.3s (+7.64%, an https run - highest hit rate, most grabs, most 30s timeouts), comfortably inside that window's 12.1% buffer. Reproducing that same relative overrun on an hourly run needs ~10% of headroom to survive it: 56000 leaves 2.77% and would overrun by 170s, 54000 leaves 6.57% and still overruns. Because the cron entries are flock-guarded (user_data.sh.tftpl) an overrun does not just run long - it skips the following hour, so the cost of undersizing the buffer is a lost hour, not a late finish. At 105000 hourly this is 2,520,000 per protocol per day, 7,560,000 across the three - about 3.3 years to cover 3e9 addresses if nothing were ever sampled twice, which with the per-tick random seed means roughly 63% coverage by then rather than a sweep (see cli.py's seed derivation). The trade taken when this moved from 15-minute to hourly slices was coarser observability and a larger unit of loss on an unclean exit, since cmd_scan writes nothing to pending_dir until a run completes."
  type        = number
  default     = 105000
}

variable "ichnos_git_url" {
  description = "Git URL the instance installs the ichnos package from (not yet published to PyPI)."
  type        = string
  default     = "https://github.com/mabel-dev/ichnos.git"
}

variable "ichnos_git_ref" {
  description = "Git ref (branch/tag/commit) of ichnos to install."
  type        = string
  default     = "main"
}

variable "jurisdiction_countries" {
  description = "ISO country codes pre-excluded from scanning (design doc §3.1.1)."
  type        = list(string)
  default     = ["JP", "KP", "KR", "CN", "RU", "IR"]
}
