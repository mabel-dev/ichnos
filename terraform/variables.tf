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
  description = <<-EOT
    EC2 instance type. Must be an arm64 (Graviton) type - the AMI lookup is arm64-only.

    Fixed-performance, not burstable, and that is the point. This ran on a t4g.small
    until the workload outgrew it: measured at ~41% of 2 vCPUs sustained against a 20%
    baseline, so the credit balance sat at zero and surplus accrued at ~27 credits an
    hour - roughly $13/month on top of the $12.26 base, for an instance that was still
    CPU-starved. Burstable pricing is a discount for being idle, and a scanner that
    runs 52 minutes of every 60 is never idle; the credit model was giving us nothing
    but an accounting layer over a machine that was too small.

    c6g.large is 2 fixed vCPUs and 4 GiB. Both halves matter: load average was 1.55 on
    the old box, and memory ran to 1.1 GiB of 1.8 GiB with only two of a possible 24
    concurrent zgrab2 workers alive, so 2 GiB variants (a1.medium, c6g.medium,
    c7g.medium) are ruled out by RAM as much as by having a single vCPU. a1 is ruled
    out separately - Graviton1 is materially slower per core than the Graviton2 this
    replaces, so it would have been a downgrade at a lower price.
  EOT
  type        = string
  default     = "c6g.large"
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
  description = "Native ZMap discovery rate in whole packets/second (`--rate` rejects fractional values). Mirrors config.py's `zmap_rate_pps` default, which documents how the current figure was arrived at and what to watch after changing it. This is only the fallback for runs that do not pass `--rate-pps`; the hourly cron entries set rate and candidates together per protocol, see `scan_protocol_budgets`."
  type        = number
  default     = 32
}

variable "scan_protocol_budgets" {
  description = <<-EOT
    Per-protocol discovery budget: candidates per hourly run, and the ZMap `--rate` to
    spend them at. One run takes roughly `candidates / rate_pps + cooldown_seconds`, so
    the pair has to be sized together - at these values every protocol takes ~3128s and
    leaves a 472s (15.1%) buffer inside the hourly cron interval.

    Split per protocol because they do not cost the same. A run's grab load is
    candidates x hit rate, and the measured rates differ by more than 2x - https 1.71%
    responsive, http 1.52%, ssh 0.77% - so an equal candidate count buys unequal work.
    https was the protocol that skipped a tick overnight at a uniform 105000/32pps,
    being the one that finds the most hosts to grab; ssh has by far the most headroom.

    A budget that does not fit the hour is not merely tight: the cron entries are
    flock-guarded, so an overrunning run skips the following one. 150000 at 32pps would
    take 4690s against a 3600s hour and lose every other run - which is why the higher
    candidate counts carry the higher rate rather than sharing one.
  EOT
  type = map(object({
    candidates = number
    rate_pps   = number
  }))
  default = {
    http  = { candidates = 150000, rate_pps = 48 }
    https = { candidates = 100000, rate_pps = 32 }
    ssh   = { candidates = 150000, rate_pps = 48 }
  }
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
