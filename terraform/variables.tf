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

variable "scan_candidates_per_cron_tick" {
  description = "Candidates per `ichnos scan` invocation - sized so one run takes roughly as long as the cron interval between invocations (see cli.py's module docstring). Native ZMap discovery runs at config.py's zmap_rate_pps (2 pps as of the post-observation increase - see its docstring), so one run takes roughly `candidates / rate_pps + cooldown_seconds` - at the defaults, 1600 candidates takes ~803s (~13.4 min), the same real-but-thin buffer inside the 15-minute cron interval as the original 800-candidates-at-1pps sizing (doubling both candidates and rate leaves runtime unchanged). The scan cron entries are flock-guarded (user_data.sh.tftpl) specifically so an occasional overrun past that buffer degrades to a skipped tick, never an overlapping concurrent run."
  type        = number
  default     = 1600
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
