##############################################################
# 4-eventbridge.tf
#
# EventBridge Rules for severity-based SOAR routing.
#
# WHY aws_cloudwatch_event_rule (NOT aws_scheduler_schedule):
#
#   aws_scheduler_schedule = time-based
#     "Run this Lambda every 5 minutes"
#     Used in lab06162026 for unused-token-detector
#
#   aws_cloudwatch_event_rule = event-driven
#     "When THIS specific event arrives with THESE fields,
#      route it to THESE targets"
#     Used here because the correlation agent publishes a
#     custom event and EventBridge routes it by severity
#
# Event flow:
#   correlation agent calls events:PutEvents with:
#     source      = "seir.waf.correlation"
#     detail-type = "WAF Threat Finding Created"
#     detail      = { finding_id, severity, risk_score }
#
#   EventBridge evaluates both rules:
#     Rule 1: severity in [MEDIUM, HIGH] → soar-response-agent
#     Rule 2: severity in [CRITICAL]     → soar-response-agent
#                                          + critical-alert SNS
#
# WHY two separate rules for CRITICAL?
#   CRITICAL events hit BOTH the Lambda AND SNS simultaneously.
#   The SNS fires instantly at the edge — no waiting for Lambda
#   to finish its DynamoDB/Bedrock work. The on-call engineer
#   gets paged immediately while the Lambda creates the ticket.
#
# Zero-Trust payload design (Theo's "doorbell" pattern):
#   The EventBridge event contains ONLY finding_id.
#   The SOAR Lambda retrieves the full record from DynamoDB
#   using ConsistentRead=True. This prevents attackers from
#   injecting fake low-severity payloads into EventBridge
#   to bypass security checks.
##############################################################


##############################################################
# Rule 1 — Medium and High Findings
#
# Matches events where detail.severity is MEDIUM or HIGH.
# Target: soar-response-agent Lambda only.
##############################################################

resource "aws_cloudwatch_event_rule" "medium_high_finding_rule" {
  name        = "waf-medium-high-finding-rule"
  description = "Routes MEDIUM and HIGH WAF correlation findings to the SOAR response agent."
  state       = "ENABLED"

  event_pattern = jsonencode({
    source      = ["seir.waf.correlation"]
    detail-type = ["WAF Threat Finding Created"]
    detail = {
      severity = ["MEDIUM", "HIGH"]
    }
  })
}

resource "aws_cloudwatch_event_target" "medium_high_soar_target" {
  rule = aws_cloudwatch_event_rule.medium_high_finding_rule.name
  arn  = aws_lambda_function.soar_response_agent.arn
}

resource "aws_lambda_permission" "medium_high_eventbridge_invoke" {
  statement_id  = "AllowMediumHighRuleInvokeSOAR"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.soar_response_agent.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.medium_high_finding_rule.arn
}


##############################################################
# Rule 2 — Critical Findings
#
# Matches events where detail.severity is CRITICAL.
# Targets: soar-response-agent Lambda AND critical-alert SNS.
#
# Both targets fire simultaneously — SNS pages the engineer
# instantly while Lambda handles the detailed workflow.
##############################################################

resource "aws_cloudwatch_event_rule" "critical_finding_rule" {
  name        = "waf-critical-finding-rule"
  description = "Routes CRITICAL WAF correlation findings to SOAR agent and SNS simultaneously."
  state       = "ENABLED"

  event_pattern = jsonencode({
    source      = ["seir.waf.correlation"]
    detail-type = ["WAF Threat Finding Created"]
    detail = {
      severity = ["CRITICAL"]
    }
  })
}

resource "aws_cloudwatch_event_target" "critical_soar_target" {
  rule = aws_cloudwatch_event_rule.critical_finding_rule.name
  arn  = aws_lambda_function.soar_response_agent.arn
}

resource "aws_cloudwatch_event_target" "critical_sns_target" {
  rule = aws_cloudwatch_event_rule.critical_finding_rule.name
  arn  = aws_sns_topic.critical_alert.arn
}

resource "aws_lambda_permission" "critical_eventbridge_invoke" {
  statement_id  = "AllowCriticalRuleInvokeSOAR"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.soar_response_agent.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.critical_finding_rule.arn
}


##############################################################
# SNS Topic Policy — Allow EventBridge to Publish
#
# SNS rejects all messages unless the topic resource policy
# explicitly allows the publisher. Without this, EventBridge
# can match the CRITICAL rule but cannot deliver to SNS.
##############################################################

resource "aws_sns_topic_policy" "critical_alert_policy" {
  arn = aws_sns_topic.critical_alert.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowEventBridgePublish"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.critical_alert.arn
      }
    ]
  })
}
