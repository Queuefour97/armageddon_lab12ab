##############################################################
# 6-outputs.tf
#
# Terraform outputs — displayed after every apply.
# Use these values for testing commands.
##############################################################

output "waf_analyzer_function_name" {
  description = "Lambda function name for the WAF Bedrock Analyzer"
  value       = aws_lambda_function.waf_bedrock_analyzer.function_name
}

output "correlation_agent_function_name" {
  description = "Lambda function name for the WAF Threat Correlation Agent"
  value       = aws_lambda_function.waf_threat_correlation_agent.function_name
}

output "soar_agent_function_name" {
  description = "Lambda function name for the SOAR Response Agent"
  value       = aws_lambda_function.soar_response_agent.function_name
}

output "waf_events_table_name" {
  description = "DynamoDB table name for WAF events"
  value       = aws_dynamodb_table.waf_events.name
}

output "correlation_findings_table_name" {
  description = "DynamoDB table name for correlation findings"
  value       = aws_dynamodb_table.correlation_findings.name
}

output "security_incidents_table_name" {
  description = "DynamoDB table name for security incidents"
  value       = aws_dynamodb_table.security_incidents.name
}

output "critical_alert_topic_arn" {
  description = "SNS topic ARN for critical alerts"
  value       = aws_sns_topic.critical_alert.arn
}

output "medium_high_rule_name" {
  description = "EventBridge rule name for MEDIUM and HIGH findings"
  value       = aws_cloudwatch_event_rule.medium_high_finding_rule.name
}

output "critical_rule_name" {
  description = "EventBridge rule name for CRITICAL findings"
  value       = aws_cloudwatch_event_rule.critical_finding_rule.name
}

output "waf_log_group_name" {
  description = "CloudWatch log group for WAF logs"
  value       = aws_cloudwatch_log_group.waf_logs.name
}

output "account_id" {
  description = "AWS account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "region" {
  description = "AWS region"
  value       = data.aws_region.current.name
}

output "api_gateway_python_url" {
  description = "API Gateway Python endpoint URL"
  value       = "https://${aws_api_gateway_rest_api.lambda_rest_api.id}.execute-api.${data.aws_region.current.name}.amazonaws.com/prod/python"
}

output "api_gateway_node_url" {
  description = "API Gateway Node endpoint URL"
  value       = "https://${aws_api_gateway_rest_api.lambda_rest_api.id}.execute-api.${data.aws_region.current.name}.amazonaws.com/prod/node"
}
