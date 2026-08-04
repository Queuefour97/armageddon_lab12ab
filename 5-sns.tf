##############################################################
# 5-sns.tf
#
# SNS Topic for critical security alerts.
#
# critical-alert topic receives notifications from two sources:
#
#   Source 1 — EventBridge critical rule (4-eventbridge.tf)
#     Fires instantly when CRITICAL finding is published.
#     Does NOT wait for Lambda to finish.
#     This is the "instant page" path.
#
#   Source 2 — soar-response-agent Lambda (3-lambdas.tf)
#     Fires after the Lambda has validated the finding,
#     selected the playbook, and generated the Bedrock summary.
#     Contains the full analyst context.
#     This is the "detailed notification" path.
#
# SNS MessageAttributes (set by the Lambda):
#   severity  — allows downstream filtering (Slack, PagerDuty)
#   playbook  — allows routing by response type
#
# Email subscription confirms to the address on record.
# AWS sends a confirmation email — click the link to activate.
# Until confirmed, SNS will not deliver to this endpoint.
##############################################################

resource "aws_sns_topic" "critical_alert" {
  name = "critical-alert"
}

resource "aws_sns_topic_subscription" "critical_alert_email" {
  topic_arn = aws_sns_topic.critical_alert.arn
  protocol  = "email"
  endpoint  = var.alert_email

  # After terraform apply, AWS sends a confirmation email.
  # Click "Confirm subscription" in that email.
  # Until confirmed, SNS will show the subscription as
  # "PendingConfirmation" and will not deliver messages.
}
