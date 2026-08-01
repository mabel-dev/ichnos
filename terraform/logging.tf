resource "aws_cloudwatch_log_group" "scanner" {
  name = "/ichnos/scanner"
  # Short-lived operational logs (design doc §10) - the long-term historical record
  # lives in Opteryx, not CloudWatch.
  retention_in_days = 90
}

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-alerts"
}

resource "aws_sns_topic_subscription" "alerts_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.abuse_email
  # AWS emails a confirmation link to this address after `apply` - alarms won't
  # actually deliver until that link is clicked. Not automatable from here.
}

# Log-based error signal: logging_setup.py stamps every line with a level, and cli.py
# already calls logger.error(...) on real failure paths (protocol not scheduled,
# publish failure, missing PAT). This turns those into an alarmable metric without
# needing any new custom-metrics code in the app.
resource "aws_cloudwatch_log_metric_filter" "errors" {
  name           = "${var.project_name}-error-lines"
  log_group_name = aws_cloudwatch_log_group.scanner.name
  pattern        = "\"ERROR\""

  metric_transformation {
    name      = "ErrorCount"
    namespace = "ichnos"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "error_rate" {
  alarm_name          = "${var.project_name}-error-lines"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.errors.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.errors.metric_transformation[0].namespace
  period              = 900 # 15 min
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_description   = "An ERROR-level log line was written - check /ichnos/scanner (publish failures, missing schedule entries, etc)."
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

# The single instance disappearing (crash, terminated, failed health check without
# ASG replacing it in time) - the most basic "is this thing even running" signal.
resource "aws_cloudwatch_metric_alarm" "instance_down" {
  alarm_name          = "${var.project_name}-instance-down"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "GroupInServiceInstances"
  namespace           = "AWS/AutoScaling"
  period              = 300
  statistic           = "Average"
  threshold           = 1
  treat_missing_data  = "breaching"
  alarm_description   = "Fewer than 1 instance in service - the scanner/public site is down."
  alarm_actions       = [aws_sns_topic.alerts.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.scanner.name
  }
}
