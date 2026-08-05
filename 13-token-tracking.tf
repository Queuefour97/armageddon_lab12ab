#
######### PHASE 1 — DynamoDB Token Tracking Table ##########
# Table: token-tracking
# Partition Key: token_id (String)
# Capacity: On-Demand (pay-per-request)
#
# Each record tracks one token issued by get_token.py:
#    {
#      "token_id": "abc123",
#      "username": "student1",
#      "issued_at": "2026-05-19T20:00:00Z",
#      "used": false
#    }
#
# NOTE: Only declare attributes used as hash/range/GSI keys in
# attribute blocks. Regular fields like "used" are written by
# Lambda at runtime — no attribute block needed for them.

resource "aws_dynamodb_table" "token_tracking" {
  name         = "token-tracking"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "token_id" # Partition key - keep this it is required at the table level

  # # Primary key using new key_schema syntax (hash_key top-level is deprecated)
  # key_schema {
  #   attribute_name = "token_id"
  #   key_type       = "HASH"
  # }

  # Attribute declarations — only for keys and GSI/LSI index attributes
  attribute {
    name = "token_id"
    type = "S"
  }

  attribute {
    name = "username"
    type = "S"
  }

  attribute {
    name = "issued_at"
    type = "S" # ISO 8601 string sorts correctly as a range key
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  # GSI: query all tokens for a given username, sorted by issue time
  global_secondary_index {
    name            = "global_lab_table_index"
    hash_key        = "username"
    range_key       = "issued_at"
    projection_type = "ALL"
  }

  tags = {
    Managedby = "Terraform"
  }
}

# # WAF Events
# resource "aws_dynamodb_table" "waf_bedfish_table" {
#   name         = "waf-bedfish-table"
#   billing_mode = "PAY_PER_REQUEST"
#   #   read_capacity  = 20
#   #   write_capacity = 20
#   hash_key = "event_id" #Note: hash_key - (Required, Forces new resource) Attribute to use as the hash (partition) key. Must also be defined as an attribute. See below

#   #https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/HowItWorks.NamingRulesDataTypes.html
#   attribute {
#     name = "event_id"
#     type = "S"
#   }

#   #https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/TTL.html
#   #Deleted items work similarly to those deleted through typical delete operations. Once deleted, items go into DynamoDB Streams as service deletions instead of user deletes, and are removed from local secondary indexes and global secondary indexes just like other delete operations. 
#   #   ttl {
#   #     attribute_name = "TimeToExist"
#   #     attribute_name = "expire_at"
#   #     enabled        = true
#   #   }

#   tags = {
#     Name        = "dynamodb-table-waf-events"
#     Environment = "serverless"
#   }
# }
# #
###### PHASE 2 and 3 — IAM: Grant Lambda DynamoDB Access ######
#
# The existing lambda_role only has AWSLambdaBasicExecutionRole (CloudWatch logs).
# This policy adds the DynamoDB permissions needed for:
#   Phase 2: get_token.py    --> PutItem    (write new token record)
#   Phase 3: update_token.py --> UpdateItem (mark token used=true)
#   Phase 4: detection.py   --> Scan       (find unused/stale tokens)

resource "aws_iam_policy" "lambda_dynamodb_policy" {
  name        = "lambda_dynamodb_token_policy"
  description = "Allows Lambda functions to read/write the token-tracking DynamoDB table"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",    # Phase 2 — write new token
          "dynamodb:UpdateItem", # Phase 3 — mark token used
          "dynamodb:Scan",       # Phase 4 — find stale unused tokens
          "dynamodb:GetItem"     # utility read
        ]
        Resource = aws_dynamodb_table.token_tracking.arn
      },
      {
        # SOAR phase — Bedrock AI enrichment for stale token alerts
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = "*"
      }

    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_dynamodb_attach" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_dynamodb_policy.arn
}


#
######PHASE 4 — Detection Lambda: unused-token-detector ##########
#
# Scans token-tracking for records where:
#   used = false  AND  issued_at is older than 10 minutes
# Logs a CloudWatch ALERT for each stale token found.

data "archive_file" "detection_lambda" {
  type        = "zip"
  source_file = "./src/detection.py"
  output_path = "./build/detection.zip"
}

resource "aws_lambda_function" "unused_token_detector" {
  filename      = data.archive_file.detection_lambda.output_path
  function_name = "unused-token-detector"
  role          = aws_iam_role.lambda_role.arn
  handler       = "detection.lambda_handler"
  runtime       = "python3.13"
#  code_sha256   = data.archive_file.detection_lambda.output_base64sha256

  timeout = 60

  environment {
    variables = {
      TABLE_NAME       = aws_dynamodb_table.token_tracking.name
      STALE_MINUTES    = "10"
      BEDROCK_MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
    }
  }

  tags = {
    Managedby = "Terraform"
  }

  depends_on = [aws_iam_role_policy_attachment.lambda_dynamodb_attach]
}


#
####### PHASE 5 — EventBridge Scheduler: every 5 minutes ########

resource "aws_iam_role" "eventbridge_scheduler_role" {
  name = "eventbridge_token_detector_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "scheduler.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "eventbridge_invoke_policy" {
  name = "eventbridge_invoke_detector"
  role = aws_iam_role.eventbridge_scheduler_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
      Effect   = "Allow"
      Action   = ["lambda:InvokeFunction"]
      Resource = [
        aws_lambda_function.unused_token_detector.arn,
          aws_lambda_function.waf_bedrock_analyzer.arn,
          aws_lambda_function.waf_threat_correlation_agent.arn
       ]
      }
    ]
  })
}

resource "aws_scheduler_schedule" "unused_token_check" {
  name        = "unused-token-check"
  description = "Triggers unused-token-detector every 5 minutes"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "rate(5 minutes)"

  target {
    arn      = aws_lambda_function.unused_token_detector.arn
    role_arn = aws_iam_role.eventbridge_scheduler_role.arn
  }
}

resource "aws_lambda_permission" "eventbridge_invoke_detector" {
  statement_id  = "AllowEventBridgeScheduler"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.unused_token_detector.function_name
  principal     = "scheduler.amazonaws.com"
  source_arn    = aws_scheduler_schedule.unused_token_check.arn
}


#
####### PHASE 6 — CloudWatch Alert Output (Log Group) ########

resource "aws_cloudwatch_log_group" "detector_log_group" {
  name              = "/aws/lambda/unused-token-detector"
  retention_in_days = 30

  tags = {
    Managedby = "Terraform"
  }
}

##############################################################
# EventBridge Scheduler — WAF Bedrock Analyzer
#
# Automatically triggers waf-bedrock-analyzer every 10 minutes
# so WAF events are collected without manual invocation.
# Uses the existing eventbridge_scheduler_role.
##############################################################

resource "aws_scheduler_schedule" "waf_analyzer_schedule" {
  name        = "waf-analyzer-schedule"
  description = "Triggers waf-bedrock-analyzer every 10 minutes to collect WAF events"
  state       = "ENABLED"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "rate(10 minutes)"

  target {
    arn      = aws_lambda_function.waf_bedrock_analyzer.arn
    role_arn = aws_iam_role.eventbridge_scheduler_role.arn
    input    = jsonencode({})
  }
}

resource "aws_lambda_permission" "eventbridge_invoke_waf_analyzer" {
  statement_id  = "AllowSchedulerInvokeWAFAnalyzer"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.waf_bedrock_analyzer.function_name
  principal     = "scheduler.amazonaws.com"
  source_arn    = aws_scheduler_schedule.waf_analyzer_schedule.arn
}


##############################################################
# EventBridge Scheduler — WAF Threat Correlation Agent
#
# Automatically triggers correlation agent every 15 minutes.
# Runs after the analyzer has had time to collect events.
# 15 minutes > 10 minutes ensures analyzer runs first.
##############################################################

resource "aws_scheduler_schedule" "correlation_agent_schedule" {
  name        = "correlation-agent-schedule"
  description = "Triggers waf-threat-correlation-agent every 15 minutes"
  state       = "ENABLED"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression = "rate(15 minutes)"

  target {
    arn      = aws_lambda_function.waf_threat_correlation_agent.arn
    role_arn = aws_iam_role.eventbridge_scheduler_role.arn
    input    = jsonencode({})
  }
}

resource "aws_lambda_permission" "eventbridge_invoke_correlation_agent" {
  statement_id  = "AllowSchedulerInvokeCorrelationAgent"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.waf_threat_correlation_agent.function_name
  principal     = "scheduler.amazonaws.com"
  source_arn    = aws_scheduler_schedule.correlation_agent_schedule.arn
}
