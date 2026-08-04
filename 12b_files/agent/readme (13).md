
Required dependency

Create requirements.txt:


    reportlab==4.4.3

ReportLab is not included in the standard Lambda runtime. It must be packaged with the deployment ZIP or supplied as a Lambda layer. Lambda layers can carry third-party Python dependencies, and their contents must be compatible with the Lambda Linux runtime.

Required environment variables

    WAF_EVENTS_TABLE=waf-events
    CORRELATION_FINDINGS_TABLE=waf-correlation-findings
    SECURITY_INCIDENTS_TABLE=security-incidents
    
    REPORT_BUCKET=chewbacca-s3-123456789012
    REPORT_PREFIX=executive-reports
    
    BEDROCK_MODEL_ID=anthropic.claude-3-haiku-20240307-v1:0
    ENABLE_BEDROCK=true
    
    REPORT_PERIOD_HOURS=24
    MAX_ITEMS_PER_TABLE=5000
    
    ORGANIZATION_NAME=SEIR Cloud Security
    REPORT_TITLE=Executive Security Report

  Required IAM permissions


        {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "ReadSecurityData",
          "Effect": "Allow",
          "Action": [
            "dynamodb:Scan"
          ],
          "Resource": [
            "arn:aws:dynamodb:REGION:ACCOUNT_ID:table/waf-events",
            "arn:aws:dynamodb:REGION:ACCOUNT_ID:table/waf-correlation-findings",
            "arn:aws:dynamodb:REGION:ACCOUNT_ID:table/security-incidents"
          ]
        },
        {
          "Sid": "InvokeBedrock",
          "Effect": "Allow",
          "Action": [
            "bedrock:InvokeModel"
          ],
          "Resource": "*"
        },
        {
          "Sid": "WriteExecutiveReports",
          "Effect": "Allow",
          "Action": [
            "s3:PutObject"
          ],
          "Resource": [
            "arn:aws:s3:::chewbacca-s3-123456789012/executive-reports/*"
          ]
        }
      ]
    }


bedrock:InvokeModel authorizes the model inference call, while S3 PutObject writes the complete PDF and JSON objects to the bucket.

S3 output layout

The code produces:


        chewbacca-s3-123456789012/
        └── executive-reports/
            └── 2026/
                └── 07/
                    └── 14/
                        ├── pdf/
                        │   └── executive-security-20260714T230000Z.pdf
                        └── json/
                            └── executive-security-20260714T230000Z.json

Both objects come from the same report document, so the PDF and JSON should contain synchronized facts.

Lambda test event

        {
          "report_period_hours": 24
        }

Lambda configuration

        Memory: 1024 MB
        Timeout: 120 seconds
        Ephemeral storage: 512 MB

This implementation creates the PDF in memory, so it does not require /tmp. Lambda does provide configurable /tmp storage from 512 MB through 10,240 MB when later revisions need temporary chart images or larger report artifacts.

