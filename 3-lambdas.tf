##############################################################
# 3-lambdas.tf
#
# All three Lambda functions and their CloudWatch log groups.
#
# Lambda 1: waf-bedrock-analyzer
#   Source:  src/waf_bedrock_analyzer.py (Theo's 12b version)
#   Trigger: Manual invoke or EventBridge Scheduler (optional)
#   Flow:    CloudWatch WAF logs → normalize → DynamoDB + Bedrock
#
# Lambda 2: waf-threat-correlation-agent
#   Source:  src/waf_threat_correlation_agent.py (modified)
#   Trigger: Manual invoke or EventBridge Scheduler (optional)
#   Flow:    DynamoDB waf-events → score IPs → Bedrock →
#            save finding → publish EventBridge event
#
# Lambda 3: soar-response-agent
#   Source:  src/soar_response_agent.py
#   Trigger: EventBridge rules (defined in 4-eventbridge.tf)
#   Flow:    Get finding → validate → select playbook →
#            Bedrock summary → create incident → SNS → update
#
# Source files live in ./src/ relative to this Terraform folder.
# Terraform zips them automatically via archive_file data source.
# The zip hash changes when source changes — triggers redeploy.
##############################################################


##############################################################
# WAF Log Group
#
# WAF requires log group names to start with aws-waf-logs-
# This is where the WAF Web ACL (if attached) writes block logs.
# The waf-bedrock-analyzer Lambda reads from this group.
##############################################################

resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "aws-waf-logs-armageddon"
  retention_in_days = 7
}


##############################################################
# Lambda 1 — WAF Bedrock Analyzer
##############################################################

resource "aws_cloudwatch_log_group" "waf_analyzer_logs" {
  name              = "/aws/lambda/waf-bedrock-analyzer"
  retention_in_days = 7
}

data "archive_file" "waf_analyzer_zip" {
  type        = "zip"
  source_file = "./src/waf_bedrock_analyzer.py"
  output_path = "./build/waf_bedrock_analyzer.zip"
}

resource "aws_lambda_function" "waf_bedrock_analyzer" {
  function_name = "waf-bedrock-analyzer"
  role          = aws_iam_role.waf_analyzer_role.arn
  handler       = "waf_bedrock_analyzer.lambda_handler"
  runtime       = "python3.13"
  timeout       = 60
  memory_size   = 128

  filename         = data.archive_file.waf_analyzer_zip.output_path
  source_code_hash = data.archive_file.waf_analyzer_zip.output_base64sha256

  environment {
    variables = {
      WAF_LOG_GROUP    = aws_cloudwatch_log_group.waf_logs_chewbacca.name
      DYNAMODB_TABLE   = aws_dynamodb_table.waf_events.name
      BEDROCK_MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
      LOOKBACK_MINUTES = "10" 
      MAX_LOG_EVENTS   = "25"
    }
  }

  depends_on = [
    aws_iam_role_policy.waf_analyzer_policy,
    aws_iam_role_policy_attachment.waf_analyzer_basic,
    aws_cloudwatch_log_group.waf_analyzer_logs,
  ]
}


##############################################################
# Lambda 2 — WAF Threat Correlation Agent
##############################################################

resource "aws_cloudwatch_log_group" "correlation_agent_logs" {
  name              = "/aws/lambda/waf-threat-correlation-agent"
  retention_in_days = 7
}

data "archive_file" "correlation_agent_zip" {
  type        = "zip"
  source_file = "./src/waf_threat_correlation_agent.py"
  output_path = "./build/waf_threat_correlation_agent.zip"
}

resource "aws_lambda_function" "waf_threat_correlation_agent" {
  function_name = "waf-threat-correlation-agent"
  role          = aws_iam_role.correlation_agent_role.arn
  handler       = "waf_threat_correlation_agent.lambda_handler"
  runtime       = "python3.13"
  timeout       = 120
  memory_size   = 256

  filename         = data.archive_file.correlation_agent_zip.output_path
  source_code_hash = data.archive_file.correlation_agent_zip.output_base64sha256

  environment {
    variables = {
      WAF_EVENTS_TABLE           = aws_dynamodb_table.waf_events.name
      CORRELATION_FINDINGS_TABLE = aws_dynamodb_table.correlation_findings.name
      BEDROCK_MODEL_ID           = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
      CORRELATION_WINDOW_MINUTES = "60"
      MINIMUM_EVENT_COUNT        = "3"
      MAX_EVENTS                 = "500"
      ADMIN_URI_KEYWORDS         = "admin,login,signin,auth,token,cognito"
      EVENT_BUS_NAME             = "default"
    }
  }

  depends_on = [
    aws_iam_role_policy.correlation_agent_policy,
    aws_iam_role_policy_attachment.correlation_agent_basic,
    aws_cloudwatch_log_group.correlation_agent_logs,
  ]
}


##############################################################
# Lambda 3 — SOAR Response Agent
##############################################################

resource "aws_cloudwatch_log_group" "soar_agent_logs" {
  name              = "/aws/lambda/soar-response-agent"
  retention_in_days = 7
}

data "archive_file" "soar_agent_zip" {
  type        = "zip"
  source_file = "./src/soar_response_agent.py"
  output_path = "./build/soar_response_agent.zip"
}

resource "aws_lambda_function" "soar_response_agent" {
  function_name = "soar-response-agent"
  role          = aws_iam_role.soar_agent_role.arn
  handler       = "soar_response_agent.lambda_handler"
  runtime       = "python3.13"
  timeout       = 120
  memory_size   = 256

  filename         = data.archive_file.soar_agent_zip.output_path
  source_code_hash = data.archive_file.soar_agent_zip.output_base64sha256

  environment {
    variables = {
      CORRELATION_FINDINGS_TABLE = aws_dynamodb_table.correlation_findings.name
      SECURITY_INCIDENTS_TABLE   = aws_dynamodb_table.security_incidents.name
      SNS_TOPIC_ARN              = aws_sns_topic.critical_alert.arn
      BEDROCK_MODEL_ID           = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
      ENABLE_BEDROCK             = "true"
    }
  }

  depends_on = [
    aws_iam_role_policy.soar_agent_policy,
    aws_iam_role_policy_attachment.soar_agent_basic,
    aws_cloudwatch_log_group.soar_agent_logs,
  ]
}
