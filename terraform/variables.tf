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

variable "refresh_rate_per_second" {
  description = "How many known hosts a second `refresh` may re-grab. Not the limiting factor in practice - grab_timeout_seconds is, since refresh targets a 15-day window and a host that has gone away occupies a worker for the whole timeout. Kept below the pool's real throughput so the number means something."
  type        = number
  default     = 1
}

variable "refresh_duration_seconds" {
  description = "Wall-clock budget for one `refresh` run. Makes refresh cost duration x rate rather than scaling with how many hosts discovery has found; coverage becomes a rolling cycle rather than a daily sweep. 0 means unbounded."
  type        = number
  default     = 3300
}

variable "grab_timeout_seconds" {
  description = "Bound on a single ZGrab2 invocation. Dropped from 30s: discovery measured a 585ms median and 1195ms p95, so 10s is eight times the p95 and costs almost no real grabs, while a dead host no longer holds a worker for half a minute. This was refresh's actual bottleneck - at 30s an 8-worker pool managed 0.8/s against a configured 10/s."
  type        = number
  default     = 10
}

variable "grab_concurrency" {
  description = "How many ZGrab2 grabs may be in flight at once, for both discovery and refresh. Bounds simultaneous outbound handshakes; every one is to a different host, so it does not make the scan heavier for anyone being scanned."
  type        = number
  default     = 8
}

variable "scan_protocol_budgets" {
  description = <<-EOT
    Per-protocol discovery budget: candidates per hourly run, and the ZMap `--rate` to
    spend them at. One run takes roughly `candidates / rate_pps + cooldown_seconds`, so
    the pair has to be sized together - at these values every protocol takes ~3128s and
    leaves a 472s (15.1%) buffer inside the hourly cron interval.

    Split per protocol because they do not cost the same. A run's grab load is
    candidates x hit rate, and the measured rates differ by more than 2x - https 1.70%
    responsive, http 1.56%, ssh 0.76% - so an equal candidate count buys unequal work.
    https was the protocol that skipped a tick at a uniform 105000/32pps, being the one
    that finds the most hosts to grab; ssh has by far the most headroom, which is why
    it carries the largest candidate count here despite the smallest share of grabs.

    A budget that does not fit the hour is not merely tight: the cron entries are
    flock-guarded, so an overrunning run skips the following one. 150000 at 32pps would
    take 4690s against a 3600s hour and lose every other run - which is why the higher
    candidate counts carry the higher rate rather than sharing one.

    Sized against measured CPU rather than the hour, because CPU is what binds now -
    the grab pool sits at 12-18% utilisation and every protocol has 472s of buffer.
    Five hours on c6g.large at 400000 candidates/hour, 15 runs, zero skipped ticks and
    durations of 3134-3163s against a predicted 3128s, measured ~40% of 2 vCPU during
    active runs with peaks of 49.5%.

    650000 was tried and is too much. It was sized by scaling that 40% linearly to an
    expected 65%; measured, it ran at 91.4% average and 96.1% peak, and every run
    overran by ~8% - enough to eat the 472s buffer and make the following tick skip.
    CPU does not scale linearly with candidates: the two measured points (40% at
    400000, 91.4% at 650000) fit candidates^1.7, so each increment costs more than the
    last. Extrapolating linearly from a single point is what got this wrong.

    575000 was then tried on that curve, projected at ~74-76%, and measured 89.6%
    average and 96.2% peak - essentially identical to 650000 despite 12% fewer
    candidates, with runs overrunning 10-16% and two of three ticks skipped. So the
    curve was numerology: CPU pins near 90% at both, which means something saturates
    that is not proportional to candidate count in the way two points suggested.

    Two failed projections in a row is enough. 450000 is a bisect step above the one
    configuration with real evidence behind it - 400000, fifteen runs, +0.2 to +1.1%
    over predicted, 40% CPU - and nothing here is predicted, only measured. If it comes
    in near 3128s the next step is 500000; if it does not, 400000 is the ceiling for 2
    vCPUs and more throughput wants c6g.xlarge rather than more tuning.

    ssh carries the largest candidate count because it is the cheapest per candidate:
    a 0.75% hit rate against http's 1.51% and https's 1.66%, so it buys the most
    coverage per unit of grab work. If runs do start drifting past 3128s, ssh is also
    the first place to trim for the same reason.
  EOT
  type = map(object({
    candidates = number
    rate_pps   = number
  }))
  default = {
    http  = { candidates = 125000, rate_pps = 40 }
    https = { candidates = 125000, rate_pps = 40 }
    ssh   = { candidates = 200000, rate_pps = 64 }
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
