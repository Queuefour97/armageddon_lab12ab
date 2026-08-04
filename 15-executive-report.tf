##############################################################
# Executive Security Dashboard Agent
#
# Phase 1: S3 Bucket
# Phase 2: IAM Role and Policy
# Phase 3: Lambda Layer (ReportLab)
# Phase 4: Lambda Function
##############################################################


##############################################################
# PHASE 1 — S3 Bucket
#
# Stores the executive PDF and JSON reports.
# Bucket name includes account ID for global uniqueness.
# Public access is blocked — reports contain sensitive data.
# force_destroy = true allows terraform destroy to empty
# the bucket automatically without manual cleanup.
##############################################################

resource "aws_s3_bucket" "executive_reports" {
  bucket        = "chewbacca-s3-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
  tags = {
    Name      = "Executive Security Reports"
    Managedby = "Terraform"
    Lab       = "12b"
  }
}

resource "aws_s3_bucket_versioning" "executive_reports_versioning" {
  bucket = aws_s3_bucket.executive_reports.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "executive_reports_public_access" {
  bucket                  = aws_s3_bucket.executive_reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


##############################################################
# PHASE 2 — IAM Role and Policy
#
# The executive report Lambda needs three capabilities:
#   dynamodb:Scan      — read waf-events, waf-correlation-findings,
#                        and security-incidents tables
#   bedrock:InvokeModel — generate the executive narrative
#   s3:PutObject       — write PDF and JSON to the S3 bucket
#
# AWSLambdaBasicExecutionRole is attached separately —
# it grants logs:CreateLogGroup, logs:CreateLogStream,
# and logs:PutLogEvents for CloudWatch logging.
##############################################################

resource "aws_iam_role" "executive_report_role" {
  name = "armageddon-executive-report-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
  tags = {
    Managedby = "Terraform"
    Lab       = "12b"
  }
}

resource "aws_iam_role_policy_attachment" "executive_report_basic" {
  role       = aws_iam_role.executive_report_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "executive_report_policy" {
  name = "executive-report-permissions"
  role = aws_iam_role.executive_report_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Read all three security tables for report data
        Sid    = "ReadSecurityData"
        Effect = "Allow"
        Action = ["dynamodb:Scan"]
        Resource = [
          aws_dynamodb_table.waf_events.arn,
          aws_dynamodb_table.correlation_findings.arn,
          aws_dynamodb_table.security_incidents.arn
        ]
      },
      {
        # Call Bedrock for executive narrative generation
        Sid      = "InvokeBedrock"
        Effect   = "Allow"
        Action   = ["bedrock:InvokeModel"]
        Resource = "*"
      },
      {
        # Write PDF and JSON reports to S3
        # Scoped to executive-reports prefix only
        Sid    = "WriteExecutiveReports"
        Effect = "Allow"
        Action = ["s3:PutObject"]
        Resource = [
          "${aws_s3_bucket.executive_reports.arn}/executive-reports/*"
        ]
      }
    ]
  })
}


##############################################################
# PHASE 3 — Lambda Layer (ReportLab)
#
# ReportLab is NOT included in the standard Lambda Python
# runtime. It must be packaged as a Lambda Layer.
#
# The layer zip must follow this structure:
#   python/
#   └── lib/
#       └── python3.13/
#           └── site-packages/
#               └── reportlab/
#
# Build the zip BEFORE running terraform apply:
#   mkdir -p /tmp/reportlab_layer/python/lib/python3.13/site-packages
#   pip install reportlab==4.4.3 \
#     --target /tmp/reportlab_layer/python/lib/python3.13/site-packages \
#     --platform manylinux2014_x86_64 \
#     --implementation cp \
#     --python-version 3.13 \
#     --only-binary=:all: \
#     --upgrade
#   cd /tmp/reportlab_layer
#   zip -r ~/Documents/TheoWAF/class7/armageddon_12ab/build/reportlab_layer.zip python/
##############################################################

resource "aws_lambda_layer_version" "reportlab_layer" {
  layer_name          = "reportlab-layer"
  filename            = "./build/reportlab_layer.zip"
  compatible_runtimes = ["python3.13"]
  description         = "ReportLab 4.4.3 — PDF generation for executive reports"
  lifecycle {
    create_before_destroy = true
  }
}


##############################################################
# PHASE 4 — Lambda Function
#
# Memory: 1024 MB — ReportLab PDF generation is memory hungry
# Timeout: 120 seconds — DynamoDB scans + Bedrock + PDF build
# Ephemeral storage: 512 MB — PDF built in memory, not /tmp
#
# Lambda test event:
#   { "report_period_hours": 24 }
#
# S3 output layout:
#   chewbacca-s3-{account_id}/
#   └── executive-reports/
#       └── YYYY/MM/DD/
#           ├── pdf/executive-security-{timestamp}.pdf
#           └── json/executive-security-{timestamp}.json
##############################################################

resource "aws_cloudwatch_log_group" "executive_report_log_group" {
  name              = "/aws/lambda/executive-dashboard-agent"
  retention_in_days = 7
  tags = {
    Managedby = "Terraform"
    Lab       = "12b"
  }
}

data "archive_file" "executive_report_zip" {
  type        = "zip"
  source_file = "./src/executive_dashboard_agent.py"
  output_path = "./build/executive_dashboard_agent.zip"
}

resource "aws_lambda_function" "executive_dashboard_agent" {
  function_name = "executive-dashboard-agent"
  role          = aws_iam_role.executive_report_role.arn
  handler       = "executive_dashboard_agent.lambda_handler"
  runtime       = "python3.13"
  timeout       = 120
  memory_size   = 1024

  ephemeral_storage {
    size = 512
  }

  filename         = data.archive_file.executive_report_zip.output_path
  source_code_hash = data.archive_file.executive_report_zip.output_base64sha256

  # ReportLab layer — required for PDF generation
  layers = [aws_lambda_layer_version.reportlab_layer.arn]

  environment {
    variables = {
      WAF_EVENTS_TABLE           = aws_dynamodb_table.waf_events.name
      CORRELATION_FINDINGS_TABLE = aws_dynamodb_table.correlation_findings.name
      SECURITY_INCIDENTS_TABLE   = aws_dynamodb_table.security_incidents.name
      REPORT_BUCKET              = aws_s3_bucket.executive_reports.bucket
      REPORT_PREFIX              = "executive-reports"
      BEDROCK_MODEL_ID           = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
      ENABLE_BEDROCK             = "true"
      REPORT_PERIOD_HOURS        = "24"
      MAX_ITEMS_PER_TABLE        = "5000"
      ORGANIZATION_NAME          = "SEIR Cloud Security"
      REPORT_TITLE               = "Executive Security Report"
    }
  }

  depends_on = [
    aws_iam_role_policy.executive_report_policy,
    aws_iam_role_policy_attachment.executive_report_basic,
    aws_cloudwatch_log_group.executive_report_log_group,
    aws_lambda_layer_version.reportlab_layer,
  ]

  tags = {
    Managedby = "Terraform"
    Lab       = "12b"
  }
}


##############################################################
# Outputs
##############################################################

output "executive_report_bucket" {
  description = "S3 bucket name for executive security reports"
  value       = aws_s3_bucket.executive_reports.bucket
}

output "executive_report_function_name" {
  description = "Lambda function name for executive dashboard agent"
  value       = aws_lambda_function.executive_dashboard_agent.function_name
}

output "reportlab_layer_arn" {
  description = "ARN of the ReportLab Lambda layer"
  value       = aws_lambda_layer_version.reportlab_layer.arn
}
