# ArmageddonLab 12a & 12b — AWS Cloud Security Pipeline

## Project Overview

This repository contains the complete infrastructure-as-code (IaC) and source code for a production-grade AWS cloud security pipeline built as part of the TheoWAF curriculum. The pipeline ingests AWS WAF telemetry, correlates threats using deterministic scoring, automates incident response using AI, and generates executive security reports — all deployed and managed with Terraform.

This lab builds directly on top of the Class 7 foundation (WAF + API Gateway + Cognito + DynamoDB + EventBridge + Bedrock) and extends it with two new labs:

- **Lab 12a** — Threat correlation, SOAR automation, and AI-driven incident response
- **Lab 12b** — Executive security dashboard with PDF report generation

---

## Architecture

```
                          INTERNET
                             │
                             ▼
                  ┌─────────────────────┐
                  │      AWS WAF v2      │
                  │   (token-api-waf)    │
                  │                      │
                  │  Rule 1: CommonRules  │  ← Blocks XSS, SQLi, OWASP Top 10
                  │  Rule 2: KnownBadIn  │  ← Blocks Log4Shell, SSRF
                  │  Rule 3: RateLimit   │  ← Blocks >100 req/5min per IP
                  │  Rule 4: IPRepute    │  ← Blocks known malicious IPs
                  └──────────┬───────────┘
                             │
                             ▼
                  ┌─────────────────────┐
                  │   API Gateway REST   │
                  │  /prod/python        │  ← RBAC enforced via Cognito
                  │  /prod/node          │  ← Simple compute endpoint
                  └──────────┬───────────┘
                             │
               ┌─────────────┴──────────────┐
               │                            │
               ▼                            ▼
    ┌──────────────────┐         ┌──────────────────┐
    │  Python Lambda   │         │   Node Lambda    │
    │  (RBAC + Cognito)│         │  (Compute only)  │
    └──────────────────┘         └──────────────────┘


SECURITY PIPELINE (automated):

WAF blocks request
       │
       ▼
CloudWatch Logs
(aws-waf-logs-chewbacca)
       │
       ▼
waf-bedrock-analyzer Lambda
  ├── Normalizes WAF log events
  ├── Adds event_epoch (integer timestamp)
  ├── Calls Bedrock → SOC summary per event
  └── Writes to waf-events DynamoDB
       │
       ▼
waf-threat-correlation-agent Lambda
  ├── Scans waf-events (60-min window)
  ├── Groups events by source IP, URI, WAF rule
  ├── Calculates deterministic risk score
  ├── Calls Bedrock → threat interpretation
  ├── Saves finding to waf-correlation-findings
  └── Publishes EventBridge custom event
       │
       ▼
EventBridge Rules (severity routing)
  ├── MEDIUM/HIGH → soar-response-agent
  └── CRITICAL    → soar-response-agent + SNS (instant page)
       │
       ▼
soar-response-agent Lambda
  ├── Retrieves full finding from DynamoDB
  ├── Validates status = OPEN
  ├── Selects deterministic playbook:
  │     LOW      → RECORD_ONLY
  │     MEDIUM   → NOTIFY_ANALYST
  │     HIGH     → CREATE_AND_ESCALATE_INCIDENT
  │     CRITICAL → REQUEST_URGENT_REVIEW
  ├── Calls Bedrock → analyst + manager summaries
  ├── Creates incident in security-incidents DynamoDB
  ├── Publishes SNS notification
  └── Updates finding status → RESPONSE_COMPLETED
       │
       ▼
executive-dashboard-agent Lambda (Lab 12b)
  ├── Reads all 3 security tables
  ├── Calls Bedrock → executive narrative
  ├── Generates PDF report using ReportLab
  └── Uploads PDF + JSON to S3
```

---

## Repository Structure

```
armageddon_lab12ab/
│
├── Terraform Files (Infrastructure as Code)
│   ├── 0-auth.tf              ← Reserved for auth resources
│   ├── 0-providers.tf         ← AWS provider, region, data sources
│   ├── 1-dynamodb.tf          ← All DynamoDB tables
│   ├── 2-iam.tf               ← IAM roles for all 3 security Lambdas
│   ├── 3-lambdas.tf           ← WAF analyzer, correlation, SOAR Lambdas
│   ├── 4-eventbridge.tf       ← EventBridge rules for severity routing
│   ├── 5-sns.tf               ← SNS critical alert topic + subscription
│   ├── 6-outputs.tf           ← Terraform outputs (URLs, ARNs, names)
│   ├── 7-variables.tf         ← Variable declarations (email masked)
│   ├── 8-api-lambdas.tf       ← Python and Node API Lambdas
│   ├── 9-chewbacca-iam.tf     ← chewbacca_lambda_role (Class 7)
│   ├── 10-rest-api.tf         ← API Gateway REST API
│   ├── 11-cognito.tf          ← Cognito user pool, groups, MFA
│   ├── 12-waf.tf              ← WAF Web ACL, rules, logging config
│   ├── 13-token-tracking.tf   ← Token tracking + unused-token-detector
│   ├── 14-test-data.tf        ← Test finding for SOAR agent testing
│   └── 15-executive-report.tf ← S3 bucket, ReportLab layer, exec Lambda
│
├── src/                        ← Lambda source code
│   ├── waf_bedrock_analyzer.py          ← Lab 12b updated analyzer
│   ├── waf_threat_correlation_agent.py  ← Correlation + risk scoring
│   ├── soar_response_agent.py           ← SOAR playbook executor
│   ├── executive_dashboard_agent.py     ← PDF report generator
│   ├── detection.py                     ← Stale token detector
│   ├── chewbacca-python-lambda.py       ← API Lambda with RBAC
│   └── chewbacca-node-lambda.js         ← API Lambda (Node.js)
│
├── policies/                   ← IAM policy JSON files
│   ├── access-DynamoDB.json    ← DynamoDB permissions
│   ├── bedrock.json            ← Bedrock permissions
│   └── waf_role.json           ← WAF analyzer permissions
│
├── build/                      ← Auto-generated Lambda zips (gitignored)
├── terraform.tfvars            ← Secret values — NEVER committed (gitignored)
├── .gitignore                  ← Protects secrets and build artifacts
└── README.md                   ← This file
```

---

## AWS Services Used

| Service | Purpose |
|---|---|
| AWS WAF v2 | Edge protection — blocks attacks before reaching application |
| API Gateway | HTTP entry point — routes requests to Lambda functions |
| Lambda (Python) | RBAC enforcement via Cognito group claims |
| Lambda (Node.js) | Compute endpoint demonstration |
| Cognito | Authentication — JWT tokens, MFA/TOTP, user groups |
| DynamoDB | Telemetry store — WAF events, findings, incidents, tokens |
| EventBridge Rules | Event-driven routing by severity level |
| EventBridge Scheduler | Time-based trigger — unused token detection every 5 min |
| Amazon Bedrock | AI enrichment — SOC summaries, threat analysis, exec reports |
| SNS | Critical alert notifications via email |
| S3 | Executive report storage (PDF + JSON) |
| CloudWatch Logs | Observability — WAF logs, Lambda execution logs |
| IAM | Least-privilege roles — separate role per Lambda |
| Terraform | Infrastructure as Code — full lifecycle management |
| Lambda Layers | ReportLab dependency for PDF generation |

---

## DynamoDB Tables

| Table | Primary Key | Written By | Read By | Purpose |
|---|---|---|---|---|
| `waf-events` | `event_id` | waf-bedrock-analyzer | waf-threat-correlation-agent | WAF block event telemetry |
| `waf-correlation-findings` | `finding_id` | waf-threat-correlation-agent | soar-response-agent | Threat correlation findings |
| `security-incidents` | `incident_id` | soar-response-agent | executive-dashboard-agent | SOAR incident records |
| `token-tracking` | `token_id` | get_token.py | unused-token-detector | Cognito JWT token tracking |

---

## Lambda Functions

### waf-bedrock-analyzer
Reads WAF block events from CloudWatch Logs (`aws-waf-logs-chewbacca`), normalizes each event into a structured record with `event_epoch` (integer Unix timestamp required by the correlation agent), calls Amazon Bedrock for a per-event SOC summary, and writes to the `waf-events` DynamoDB table. Uses deterministic event IDs to prevent duplicate records on repeated invocations.

### waf-threat-correlation-agent
Scans the `waf-events` table for events within a configurable time window (default 60 minutes). Groups events by source IP, target URI, and WAF rule. Calculates a deterministic risk score (0-100) based on event count, URI diversity, rule diversity, sensitive URI targeting, and burst activity. Classifies severity (LOW/MEDIUM/HIGH/CRITICAL). Calls Bedrock for threat interpretation. Saves the finding to `waf-correlation-findings` and publishes a custom EventBridge event to trigger the SOAR agent.

**Risk scoring breakdown:**

| Condition | Points |
|---|---|
| 5+ events from same IP | +20 |
| 15+ events from same IP | +10 |
| 3+ unique URIs targeted | +20 |
| 2+ WAF rule types triggered | +20 |
| Sensitive URI targeted (admin/auth/login) | +15 |
| 100% block rate | +5 |
| 5+ events within 5 minutes (burst) | +10 |

### soar-response-agent
Receives EventBridge events containing only `finding_id` (doorbell pattern — prevents payload injection). Retrieves the full finding from DynamoDB using `ConsistentRead=True`. Validates status is `OPEN`. Selects a deterministic playbook based on severity — Bedrock does NOT choose the playbook. Calls Bedrock for analyst and manager summaries. Creates a security incident with deterministic ID `INC-{finding_id}` (idempotent — prevents duplicates on EventBridge retries). Publishes SNS notification. Updates finding status to `RESPONSE_COMPLETED`.

### executive-dashboard-agent (Lab 12b)
Reads from all three security DynamoDB tables. Calculates security metrics and posture. Calls Bedrock for an executive narrative. Generates a multi-page PDF report using ReportLab (delivered as a Lambda layer). Uploads both PDF and JSON to S3 under a date-partitioned path (`executive-reports/YYYY/MM/DD/`).

### unused-token-detector
Scans `token-tracking` for JWT tokens where `used=False` and age exceeds `STALE_MINUTES`. Calls Bedrock to generate a SOAR-style incident summary per stale token. Triggered automatically by EventBridge Scheduler every 5 minutes.

---

## EventBridge Design

This lab uses **two different EventBridge services** for different purposes:

| Resource | Service | Type | Used For |
|---|---|---|---|
| `aws_cloudwatch_event_rule` | EventBridge Rules | Event-driven | Route findings by severity to SOAR agent |
| `aws_scheduler_schedule` | EventBridge Scheduler | Time-based | Trigger unused-token-detector every 5 min |

### Severity Routing Rules

| Rule | Matches | Targets |
|---|---|---|
| `waf-medium-high-finding-rule` | severity = MEDIUM or HIGH | soar-response-agent Lambda |
| `waf-critical-finding-rule` | severity = CRITICAL | soar-response-agent Lambda + SNS topic |

The correlation agent publishes events with:
```json
{
  "source": "seir.waf.correlation",
  "detail-type": "WAF Threat Finding Created",
  "detail": {
    "finding_id": "uuid",
    "severity": "HIGH",
    "risk_score": 75
  }
}
```

---

## IAM — Least Privilege Design

Each Lambda has its own dedicated IAM role with only the permissions it needs:

| Role | Lambda | Key Permissions |
|---|---|---|
| `armageddon-waf-analyzer-role` | waf-bedrock-analyzer | logs:FilterLogEvents, dynamodb:PutItem, bedrock:InvokeModel |
| `armageddon-correlation-agent-role` | waf-threat-correlation-agent | dynamodb:Scan, dynamodb:PutItem, bedrock:InvokeModel, events:PutEvents |
| `armageddon-soar-agent-role` | soar-response-agent | dynamodb:GetItem/UpdateItem/PutItem, sns:Publish, bedrock:InvokeModel |
| `armageddon-executive-report-role` | executive-dashboard-agent | dynamodb:Scan (3 tables), bedrock:InvokeModel, s3:PutObject |
| `chewbacca_lambda_role` | API Lambdas + token detector | DynamoDB token-tracking, bedrock:InvokeModel |

---

## Prerequisites

### Tools Required
```bash
terraform --version   # 1.10+
aws --version         # AWS CLI v2
python --version      # Python 3.x
git --version
```

### AWS Configuration
```bash
aws configure
aws sts get-caller-identity
```

### Bedrock Model Access
This lab uses `us.anthropic.claude-haiku-4-5-20251001-v1:0` — a cross-region inference profile. The `us.` prefix is required for newer Anthropic models on AWS Bedrock. Direct model IDs without this prefix are now LEGACY and may become inaccessible after 30 days of inactivity.

### Windows Git Bash Notes
- Path mangling: prefix commands with `MSYS_NO_PATHCONV=1`
- SSL revocation: add `--ssl-no-revoke` to all curl commands
- Shell characters: URL-encode `<` as `%3C` and `>` as `%3E` in curl
- ZIP command: use `python -m zipfile` instead of `zip`
- Output capture: use `command 2>&1 | tee output.txt` to save output

---

## Deployment

### First-Time Deployment

```bash
# 1. Clone the repository
git clone https://github.com/Queuefour97/armageddon_lab12ab.git
cd armageddon_lab12ab

# 2. Create terraform.tfvars (not in repo — gitignored)
echo 'alert_email = "your-email@gmail.com"' > terraform.tfvars

# 3. Build the ReportLab Lambda layer (required for Lab 12b)
mkdir -p /tmp/reportlab_layer/python/lib/python3.13/site-packages

python -m pip install reportlab==4.4.3 \
  --target /tmp/reportlab_layer/python/lib/python3.13/site-packages \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 3.13 \
  --only-binary=:all: \
  --upgrade

cd /tmp/reportlab_layer
python -m zipfile -c ~/path/to/armageddon_lab12ab/build/reportlab_layer.zip python/
cd ~/path/to/armageddon_lab12ab

# 4. Initialize and deploy
terraform init
terraform plan 2>&1 | tee plan_output.txt
terraform apply 2>&1 | tee apply_output.txt
```

### Post-Deployment Manual Steps

```bash
# 1. Check SNS confirmation email and click "Confirm subscription"

# 2. Verify WAF logging is attached
aws wafv2 list-web-acls --scope REGIONAL \
  --query 'WebACLs[].{Name:Name,Id:Id}' --output table

# 3. Verify Lambda env vars
aws lambda get-function-configuration \
  --function-name waf-bedrock-analyzer \
  --query 'Environment.Variables.WAF_LOG_GROUP'
# Expected: "aws-waf-logs-chewbacca"

# 4. Get current API Gateway URL
terraform output api_gateway_python_url
```

### Bring Stack Back Up After Destroy

```bash
cd armageddon_lab12ab
terraform init
terraform apply 2>&1 | tee apply_output.txt

# After apply:
# 1. Check email for SNS confirmation and click the link
# 2. Get new API Gateway URL: terraform output api_gateway_python_url
# 3. Get new WAF ID: aws wafv2 list-web-acls --scope REGIONAL --output table
# 4. Verify WAF logging: aws wafv2 get-logging-configuration --resource-arn <new-arn>
# 5. Verify Lambda env var: aws lambda get-function-configuration --function-name waf-bedrock-analyzer --query 'Environment.Variables.WAF_LOG_GROUP'
```

---

## Testing

### Quick Smoke Test
```bash
# WAF should block XSS — expected: 403
curl -I --ssl-no-revoke \
  "$(terraform output -raw api_gateway_python_url)?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

### Full Pipeline Test

```bash
API_URL=$(terraform output -raw api_gateway_python_url)

# Step 1 — Generate WAF block events
for i in {1..10}; do
  curl --ssl-no-revoke -o /dev/null -w "%{http_code}\n" \
  "${API_URL}?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
done

# Step 2 — Wait for WAF to flush logs to CloudWatch
sleep 30

# Step 3 — Run WAF analyzer
aws lambda invoke --function-name waf-bedrock-analyzer response_waf.json
cat response_waf.json
# Expected: events_found > 0, events_stored > 0

# Step 4 — Run correlation agent
aws lambda invoke --function-name waf-threat-correlation-agent response_correlation.json
cat response_correlation.json
# Expected: finding_created=true, severity=MEDIUM or HIGH

# Step 5 — Run SOAR agent with EventBridge format
# Replace <finding_id> with the value from Step 4
MSYS_NO_PATHCONV=1 aws lambda invoke \
  --function-name soar-response-agent \
  --payload '{"version":"0","detail-type":"WAF Threat Finding Created","source":"seir.waf.correlation","detail":{"finding_id":"<finding_id>","severity":"HIGH","risk_score":75}}' \
  --cli-binary-format raw-in-base64-out \
  response_soar.json
cat response_soar.json
# Expected: incident_created=true, notification_sent=true

# Step 6 — Generate executive report (Lab 12b)
MSYS_NO_PATHCONV=1 aws lambda invoke \
  --function-name executive-dashboard-agent \
  --payload '{"report_period_hours": 24}' \
  --cli-binary-format raw-in-base64-out \
  response_12b.json
cat response_12b.json
# Expected: PDF and JSON uploaded to S3

# Step 7 — Download the PDF report
aws s3 cp \
  s3://chewbacca-s3-975598471165/executive-reports/$(date +%Y/%m/%d)/pdf/ \
  . --recursive --include "*.pdf"

# Step 8 — Verify DynamoDB counts
aws dynamodb scan --table-name waf-events --select COUNT
aws dynamodb scan --table-name waf-correlation-findings --select COUNT
aws dynamodb scan --table-name security-incidents --select COUNT

# Step 9 — Verify EventBridge rules are active
aws events list-rules \
  --query 'Rules[?contains(Name, `waf`)].{Name:Name,State:State}' \
  --output table

# Step 10 — Final state check
terraform plan 2>&1 | tee final_plan.txt
# Expected: No changes
```

---

## Key Design Decisions

### Why separate IAM roles per Lambda?
Least-privilege principle. The WAF analyzer only needs to read CloudWatch and write to DynamoDB. Giving it SNS or S3 access would violate least privilege. If the Lambda is compromised, the blast radius is limited to exactly what it needs.

### Why EventBridge Rules instead of direct Lambda invocation?
EventBridge provides severity-based routing without the correlation agent needing to know about the SOAR agent. Adding a new response action (e.g. PagerDuty, Slack, JIRA) only requires a new EventBridge target — no code changes to the correlation agent.

### Why deterministic risk scoring instead of AI?
Bedrock generates the narrative but never decides the risk score or playbook. The Python code calculates scores using transparent, auditable math. This means the same inputs always produce the same output — critical for security systems where you need to explain decisions to auditors.

### Why `event_epoch` as an integer?
DynamoDB `FilterExpression` requires numeric comparisons for time-window filtering. ISO timestamp strings cannot be compared mathematically. The integer Unix timestamp allows `Attr("event_epoch").gte(minimum_epoch)` which is how the correlation agent's 60-minute window works.

### Why `us.` prefix on Bedrock model IDs?
Newer Anthropic models on AWS Bedrock require cross-region inference profiles. Direct model IDs like `anthropic.claude-3-haiku-20240307-v1:0` are LEGACY and become inaccessible after 30 days without use. The `us.` prefix routes through inference profiles that remain accessible.

### Why the "doorbell pattern" in SOAR agent?
The EventBridge event contains only `finding_id`. The SOAR agent retrieves the full record from DynamoDB. This prevents attackers from injecting fake low-severity payloads into EventBridge to bypass security checks. The authoritative data always comes from DynamoDB, not the event payload.

### Why `INC-{finding_id}` as incident ID?
Deterministic incident IDs make the SOAR workflow idempotent. If EventBridge retries the same event (at-least-once delivery guarantee), the conditional `put_item` prevents a duplicate incident from being created.

---

## Troubleshooting

### WAF analyzer finds 0 events
```bash
# Check WAF is logging to the right log group
aws wafv2 get-logging-configuration \
  --resource-arn <waf-arn> \
  --query 'LoggingConfiguration.LogDestinationConfigs'
# Should show: aws-waf-logs-chewbacca

# Check Lambda env var
aws lambda get-function-configuration \
  --function-name waf-bedrock-analyzer \
  --query 'Environment.Variables.WAF_LOG_GROUP'
# Should show: aws-waf-logs-chewbacca

# If WAF logging missing, reattach:
MSYS_NO_PATHCONV=1 aws wafv2 put-logging-configuration \
  --logging-configuration '{"ResourceArn":"<waf-arn>","LogDestinationConfigs":["arn:aws:logs:us-east-1:975598471165:log-group:aws-waf-logs-chewbacca"]}'
```

### Bedrock ResourceNotFoundException (Legacy model)
```bash
# Update Lambda to use active model
aws lambda update-function-configuration \
  --function-name <function-name> \
  --environment "Variables={...,BEDROCK_MODEL_ID=us.anthropic.claude-haiku-4-5-20251001-v1:0}"
```

### Correlation agent — Float types not supported
The `native_to_decimal()` function in `waf_threat_correlation_agent.py` converts all Python floats and ints to `Decimal` before writing to DynamoDB. The `bool` check must come before the `int` check because Python's `bool` is a subclass of `int`.

### Terraform state drift after destroy/apply
API Gateway and WAF get new IDs after every destroy/apply. Always run `terraform output` after apply to get current URLs and IDs.

### SNS subscription pending after apply
Check email for AWS confirmation message and click "Confirm subscription". Until confirmed, SNS will not deliver notifications.

### Lambda role reverts after terraform apply
If a Lambda role was set via CLI and the `.tf` file has a different role, `terraform apply` will revert it. Always fix the role in the `.tf` file, not just via CLI.

---

## Environment Variables Reference

| Lambda | Variable | Value | Purpose |
|---|---|---|---|
| waf-bedrock-analyzer | `WAF_LOG_GROUP` | `aws-waf-logs-chewbacca` | CloudWatch log group WAF writes to |
| waf-bedrock-analyzer | `DYNAMODB_TABLE` | `waf-events` | Table to write events to |
| waf-bedrock-analyzer | `LOOKBACK_MINUTES` | `10` | How far back to read WAF logs |
| waf-bedrock-analyzer | `MAX_LOG_EVENTS` | `25` | Max events per invocation |
| waf-threat-correlation-agent | `WAF_EVENTS_TABLE` | `waf-events` | Table to scan for correlation |
| waf-threat-correlation-agent | `CORRELATION_FINDINGS_TABLE` | `waf-correlation-findings` | Table to save findings |
| waf-threat-correlation-agent | `CORRELATION_WINDOW_MINUTES` | `60` | Time window for correlation |
| waf-threat-correlation-agent | `MINIMUM_EVENT_COUNT` | `3` | Min events needed for correlation |
| waf-threat-correlation-agent | `EVENT_BUS_NAME` | `default` | EventBridge bus to publish to |
| soar-response-agent | `CORRELATION_FINDINGS_TABLE` | `waf-correlation-findings` | Table to retrieve findings from |
| soar-response-agent | `SECURITY_INCIDENTS_TABLE` | `security-incidents` | Table to write incidents to |
| soar-response-agent | `SNS_TOPIC_ARN` | `arn:aws:sns:...` | Topic for notifications |
| soar-response-agent | `ENABLE_BEDROCK` | `true` | Toggle Bedrock enrichment |
| executive-dashboard-agent | `REPORT_BUCKET` | `chewbacca-s3-975598471165` | S3 bucket for reports |
| executive-dashboard-agent | `REPORT_PREFIX` | `executive-reports` | S3 key prefix |
| executive-dashboard-agent | `ORGANIZATION_NAME` | `SEIR Cloud Security` | Appears in PDF header |
| executive-dashboard-agent | `REPORT_TITLE` | `Executive Security Report` | PDF title |
| executive-dashboard-agent | `REPORT_PERIOD_HOURS` | `24` | Hours of data to include |

---

## S3 Report Layout

```
chewbacca-s3-975598471165/
└── executive-reports/
    └── YYYY/
        └── MM/
            └── DD/
                ├── pdf/
                │   └── executive-security-{timestamp}.pdf
                └── json/
                    └── executive-security-{timestamp}.json
```

---

## Security Notes

- `terraform.tfvars` is gitignored — never commit it
- `terraform.tfstate` is gitignored — contains resource IDs and sensitive values
- `build/` is gitignored — contains compiled Lambda zips
- SNS subscription endpoint is stored in `terraform.tfvars` as `alert_email`
- All S3 buckets have public access blocked
- All IAM roles follow least-privilege principle
- WAF logging uses resource policy to allow WAF service to write to CloudWatch

---

## Author

**Jorune Simpkins**
Cloud Engineering Student — TheoWAF Curriculum
Building toward AI/ML and cloud engineering career
Georgia, USA

**GitHub:** https://github.com/Queuefour97
**Project:** ArmageddonLab 12a & 12b
**Date:** July 2026

---

## Lab Credits

Built as part of the TheoWAF AWS Security curriculum — Class 7 through Labs 12a and 12b.
This lab demonstrates enterprise-grade AI-driven security automation on AWS.

---

## Project Information

| Field | Detail |
|---|---|
| **Project Name** | ArmageddonLab 12a & 12b |
| **Author** | Jorune Simpkins |
| **Date** | July 2026 |
| **Curriculum** | TheoWAF AWS Security — Class 7 through Labs 12a and 12b |
| **Repository** | https://github.com/Queuefour97/armageddon_lab12ab |
| **AWS Region** | us-east-1 |
| **Stack** | armageddon_12ab |

---

*This project was built as a hands-on lab demonstrating production-grade AWS cloud security architecture, AI-driven threat detection, and automated incident response using Infrastructure as Code.*
