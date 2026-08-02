# Route 53 hosted zone for the registered domain (registered at Squarespace, not here -
# Terraform only manages DNS *records* for it). After the first `apply`, take the NS
# records from `terraform output name_servers` and set them as the custom nameservers
# in Squarespace's domain management UI - that delegation step can't be automated from
# here, it's a change on a third-party registrar's own account. See README.md.
resource "aws_route53_zone" "main" {
  name    = var.domain_name
  comment = "ichnos - Internet measurement service (design doc: scan.opteryx/DESIGN.md)"
}

# Points the domain at the scanner's fixed EIP - this IS the design's core requirement
# that navigating to the scanner's IP (and now, its name) shows the public info page.
resource "aws_route53_record" "root_a" {
  zone_id = aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "A"
  ttl     = 300
  records = [aws_eip.scanner.public_ip]
}

# Forward record for the scanner's reverse-DNS hostname (scan.<domain> -> the EIP).
# One hostname, not scan-01/scan-02 - a single instance today, not a fleet. Not meant
# to be visited directly (no TLS cert, no distinct content there); it exists purely
# so AWS's reverse-DNS PTR for the EIP has a matching forward record to validate
# against (`aws ec2 modify-address-attribute --domain-name`, set once outside
# Terraform - see README.md). Receiving mail/network-security tooling is far more
# likely to treat probe traffic as legitimate when the source IP resolves to
# something other than a bare AWS-assigned hostname.
resource "aws_route53_record" "scanner_ptr_target" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "scan.${var.domain_name}"
  type    = "A"
  ttl     = 300
  records = [aws_eip.scanner.public_ip]
}
