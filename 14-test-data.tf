##############################################################
# 14-test-data.tf
#
# Test data for Lambda testing — NOT production infrastructure.
# This file inserts a sample finding into waf-correlation-findings
# so the soar-response-agent can be tested via the Lambda console
# or CLI without needing to run the full correlation pipeline.
#
# To remove test data: delete this file and run terraform apply.
##############################################################

resource "aws_dynamodb_table_item" "test_finding" {
  table_name = aws_dynamodb_table.correlation_findings.name
  hash_key   = "finding_id"

  item = <<ITEM
{
  "finding_id":        {"S": "7ea476d0-1fea-4ff0-a95a-6377faac5cb4"},
  "severity":          {"S": "HIGH"},
  "risk_score":        {"N": "75"},
  "attack_type":       {"S": "XSS"},
  "source_ip":         {"S": "192.168.1.1"},
  "timestamp":         {"S": "2026-07-23T00:00:00Z"},
  "waf_rule":          {"S": "AWSManagedRulesCommonRuleSet"},
  "request_uri":       {"S": "/prod/python"},
  "action_taken":      {"S": "BLOCK"},
  "status":            {"S": "OPEN"},
  "created_at":        {"S": "2026-07-23T00:00:00Z"},
  "primary_source_ip": {"S": "192.168.1.1"},
  "primary_target":    {"S": "/prod/python"},
  "event_count":       {"N": "10"},
  "window_start":      {"S": "2026-07-23T00:00:00Z"},
  "window_end":        {"S": "2026-07-23T01:00:00Z"},
  "bedrock_report":    {"S": "XSS attack detected from 192.168.1.1 targeting /prod/python endpoint. Attack was blocked by AWSManagedRulesCommonRuleSet. Recommend reviewing source IP for additional malicious activity."}
}
ITEM
}