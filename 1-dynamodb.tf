##############################################################
# 1-dynamodb.tf
#
# All DynamoDB tables for the armageddon_12ab stack.
#
# Table 1: waf-events
#   Written by: waf-bedrock-analyzer Lambda
#   Read by:    waf-threat-correlation-agent Lambda
#   Purpose:    Stores every normalized WAF block event
#   Key field:  event_id (deterministic — CloudWatch eventId
#               or SHA256 hash, prevents duplicates)
#   New fields vs Class 7: event_epoch (integer Unix timestamp)
#   required by the correlation agent's time-window filter,
#   source_ip (was client_ip in Class 7)
#
# Table 2: waf-correlation-findings
#   Written by: waf-threat-correlation-agent Lambda
#   Read by:    soar-response-agent Lambda
#   Purpose:    Stores correlation findings with risk scores,
#               Bedrock threat reports, and workflow status
#   Key field:  finding_id (UUID)
#
# Table 3: security-incidents
#   Written by: soar-response-agent Lambda
#   Purpose:    One record per SOAR workflow execution.
#               incident_id = INC-{finding_id} — deterministic
#               so EventBridge retries cannot create duplicates
#   Key field:  incident_id
##############################################################


##############################################################
# Table 1 — WAF Events (telemetry store)
##############################################################

resource "aws_dynamodb_table" "waf_events" {
  name         = "waf-events"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }

  tags = {
    Name = "waf-events"
  }
}


##############################################################
# Table 2 — WAF Correlation Findings
##############################################################

resource "aws_dynamodb_table" "correlation_findings" {
  name         = "waf-correlation-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  tags = {
    Name = "waf-correlation-findings"
  }
}


##############################################################
# Table 3 — Security Incidents
#
# ConditionExpression="attribute_not_exists(incident_id)"
# in the SOAR agent prevents duplicate incidents when
# EventBridge retries the same event (at-least-once delivery).
##############################################################

resource "aws_dynamodb_table" "security_incidents" {
  name         = "security-incidents"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "incident_id"

  attribute {
    name = "incident_id"
    type = "S"
  }

  tags = {
    Name = "security-incidents"
  }
}


