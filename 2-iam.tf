##############################################################
# 2-iam.tf
#
# IAM roles and policies for all three Lambda functions.
# Each Lambda gets its own dedicated role — least privilege.
#
# Role 1: waf-analyzer-role
#   Used by: waf-bedrock-analyzer Lambda
#   Needs:   logs:FilterLogEvents (read WAF CloudWatch logs)
#            dynamodb:PutItem (write to waf-events)
#            bedrock:InvokeModel (SOC summary per event)
#
# Role 2: correlation-agent-role
#   Used by: waf-threat-correlation-agent Lambda
#   Needs:   dynamodb:Scan (read waf-events for time window)
#            dynamodb:PutItem/GetItem (write correlation finding)
#            bedrock:InvokeModel (threat interpretation)
#            events:PutEvents (publish custom EventBridge event)
#
# Role 3: soar-agent-role
#   Used by: soar-response-agent Lambda
#   Needs:   dynamodb:GetItem/UpdateItem (read+update finding)
#            dynamodb:PutItem (write security incident)
#            sns:Publish (send analyst notification)
#            bedrock:InvokeModel (analyst+manager summaries)
##############################################################


##############################################################
# Role 1 — WAF Bedrock Analyzer
##############################################################

resource "aws_iam_role" "waf_analyzer_role" {
  name = "armageddon-waf-analyzer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "waf_analyzer_basic" {
  role       = aws_iam_role.waf_analyzer_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "waf_analyzer_policy" {
  name = "waf-analyzer-permissions"
  role = aws_iam_role.waf_analyzer_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Read WAF logs from CloudWatch
        # Resource * required — log group ARN scoping breaks
        # when WAF logging config changes between applies
        Effect   = "Allow"
        Action   = ["logs:FilterLogEvents"]
        Resource = "*"
      },
      {
        # Write normalized WAF events to DynamoDB
        # ConditionExpression in the Lambda prevents duplicates
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:GetItem"]
        Resource = [aws_dynamodb_table.waf_events.arn]
      },
      {
        # Call Bedrock for per-event SOC summary
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = "*"
      }
    ]
  })
}


##############################################################
# Role 2 — Correlation Agent
##############################################################

resource "aws_iam_role" "correlation_agent_role" {
  name = "armageddon-correlation-agent-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "correlation_agent_basic" {
  role       = aws_iam_role.correlation_agent_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "correlation_agent_policy" {
  name = "correlation-agent-permissions"
  role = aws_iam_role.correlation_agent_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Scan waf-events for the correlation time window
        # Uses FilterExpression on event_epoch field
        Effect   = "Allow"
        Action   = ["dynamodb:Scan", "dynamodb:GetItem", "dynamodb:Query"]
        Resource = [aws_dynamodb_table.waf_events.arn]
      },
      {
        # Write and read correlation findings
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = [aws_dynamodb_table.correlation_findings.arn]
      },
      {
        # Call Bedrock for threat interpretation
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = "*"
      },
      {
        # Publish custom event to trigger SOAR agent via
        # EventBridge rules defined in 4-eventbridge.tf
        # source = seir.waf.correlation
        # detail-type = WAF Threat Finding Created
        Effect   = "Allow"
        Action   = ["events:PutEvents"]
        Resource = "*"
      }
    ]
  })
}


##############################################################
# Role 3 — SOAR Response Agent
##############################################################

resource "aws_iam_role" "soar_agent_role" {
  name = "armageddon-soar-agent-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "soar_agent_basic" {
  role       = aws_iam_role.soar_agent_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "soar_agent_policy" {
  name = "soar-agent-permissions"
  role = aws_iam_role.soar_agent_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Read finding from waf-correlation-findings
        # ConsistentRead=True in Lambda ensures authoritative data
        # Update finding status to RESPONSE_COMPLETED
        Effect = "Allow"
        Action = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
        Resource = [aws_dynamodb_table.correlation_findings.arn]
      },
      {
        # Write security incident record
        # ConditionExpression prevents duplicates on EB retry
        Effect = "Allow"
        Action = ["dynamodb:PutItem", "dynamodb:GetItem"]
        Resource = [aws_dynamodb_table.security_incidents.arn]
      },
      {
        # Publish SOC notification to critical-alert topic
        # SNS MessageAttributes allow downstream routing
        # by severity and playbook name
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.critical_alert.arn]
      },
      {
        # Generate analyst and manager summaries
        # Bedrock does NOT select the playbook —
        # that is deterministic Python (PLAYBOOKS dict)
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = "*"
      }
    ]
  })
}
