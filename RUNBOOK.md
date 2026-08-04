# ArmageddonLab 12a & 12b — Complete Runbook
**Author:** Jorune Simpkins
**Date:** August 2026
**Project:** ArmageddonLab 12a & 12b — AWS Cloud Security Pipeline
**Repository:** https://github.com/Queuefour97/armageddon_lab12ab
**Region:** us-east-1
**Account:** ********1165

---

## Table of Contents

1. [What This Lab Builds](#1-what-this-lab-builds)
2. [Architecture — How Everything Connects](#2-architecture--how-everything-connects)
3. [Prerequisites](#3-prerequisites)
4. [Repository Structure](#4-repository-structure)
5. [Terraform Files — What Each One Does](#5-terraform-files--what-each-one-does)
6. [Source Code Files — What Each One Does](#6-source-code-files--what-each-one-does)
7. [IAM Roles and Policies — Why Each Permission Exists](#7-iam-roles-and-policies--why-each-permission-exists)
8. [DynamoDB Tables — What Gets Stored Where](#8-dynamodb-tables--what-gets-stored-where)
9. [EventBridge — How Severity Routing Works](#9-eventbridge--how-severity-routing-works)
10. [First-Time Deployment](#10-first-time-deployment)
11. [Post-Deployment Checklist](#11-post-deployment-checklist)
12. [Bring Stack Back Up After Destroy](#12-bring-stack-back-up-after-destroy)
13. [How to Run Tests in AWS Console](#13-how-to-run-tests-in-aws-console)
14. [Complete Test Plan with Commands and Expected Outputs](#14-complete-test-plan-with-commands-and-expected-outputs)
15. [How to Find Key Values (finding_id, WAF ID, etc.)](#15-how-to-find-key-values)
16. [Troubleshooting Guide — Gotchas and Fixes](#16-troubleshooting-guide--gotchas-and-fixes)
17. [Destroy and Cost Management](#17-destroy-and-cost-management)
18. [Push Updates to GitHub](#18-push-updates-to-github)
19. [Key Design Decisions — Why We Did It This Way](#19-key-design-decisions--why-we-did-it-this-way)
20. [Differences from Original Class 7 Lab](#20-differences-from-original-class-7-lab)

---

## 1. What This Lab Builds

This lab builds a production-grade AWS cloud security pipeline that automatically:

1. **Detects** — AWS WAF blocks malicious requests (XSS, SQL injection, DDoS)
2. **Collects** — WAF block events are read from CloudWatch and stored in DynamoDB
3. **Correlates** — Multiple events from the same source IP are grouped and risk-scored
4. **Responds** — AI-generated incident summaries are created and routed by severity
5. **Notifies** — Security analysts receive email alerts with full incident context
6. **Reports** — Executive PDF reports summarize the security posture

The lab builds on top of the Class 7 foundation (WAF + API Gateway + Cognito + token tracking) and adds two new layers:

- **Lab 12a** — Threat correlation, SOAR automation, EventBridge severity routing
- **Lab 12b** — Executive security dashboard with PDF report generation

---

## 2. Architecture — How Everything Connects

```
                        INTERNET
                            │
                            ▼
               ┌─────────────────────┐
               │      AWS WAF v2      │
               │   (token-api-waf)    │
               │                      │
               │  Rule 1 Priority 1:  │ ← AWSManagedRulesCommonRuleSet
               │  Blocks XSS, SQLi    │   OWASP Top 10 attacks
               │                      │
               │  Rule 2 Priority 2:  │ ← AWSManagedRulesKnownBadInputs
               │  Blocks Log4Shell    │   SSRF, Java deserialization
               │                      │
               │  Rule 3 Priority 3:  │ ← RateLimitPerIP (custom rule)
               │  Rate limit 100/5min │   Blocks DDoS from single IP
               │                      │
               │  Rule 4 Priority 4:  │ ← AWSManagedRulesAmazonIpReputation
               │  Blocks bad IPs      │   Known malicious IP addresses
               └──────────┬───────────┘
                           │ Allowed traffic passes through
                           ▼
               ┌─────────────────────┐
               │   API Gateway REST   │
               │  /prod/python        │ ← RBAC enforced via Cognito JWT
               │  /prod/node          │ ← Simple compute demonstration
               └──────────┬───────────┘
                           │
              ┌────────────┴────────────┐
              │                         │
              ▼                         ▼
   ┌──────────────────┐      ┌──────────────────┐
   │  Python Lambda   │      │   Node Lambda    │
   │  chewbacca-      │      │  chewbacca-node  │
   │  python-lambda   │      │  -lambda         │
   │                  │      │                  │
   │  Reads Cognito   │      │  Returns Hello   │
   │  groups from JWT │      │  from Node       │
   │  Checks admins   │      │                  │
   │  group for RBAC  │      │                  │
   └──────────────────┘      └──────────────────┘


SECURITY PIPELINE (runs in parallel with API traffic):

WAF blocks a request
        │
        ▼ (WAF writes log to CloudWatch)
aws-waf-logs-chewbacca (CloudWatch Log Group)
        │
        ▼ (Lambda reads logs on demand)
waf-bedrock-analyzer Lambda
        │
        ├── Reads WAF logs (FilterLogEvents)
        ├── Normalizes each event:
        │     event_id (deterministic — prevents duplicates)
        │     event_epoch (integer Unix timestamp — required for time filtering)
        │     source_ip (was client_ip in Class 7)
        │     action, uri, rule, country, method
        ├── Calls Bedrock → SOC summary per event
        └── Writes to waf-events DynamoDB
                │
                ▼
        waf-events DynamoDB Table
                │
                ▼ (Correlation agent scans this table)
waf-threat-correlation-agent Lambda
        │
        ├── Scans waf-events for last 60 minutes
        ├── Groups events by source IP
        ├── Calculates deterministic risk score (0-100):
        │     5+ events from same IP    → +20 points
        │     15+ events from same IP   → +10 points
        │     3+ unique URIs targeted   → +20 points
        │     2+ WAF rule types fired   → +20 points
        │     Sensitive URI targeted    → +15 points
        │     100% block rate           → +5 points
        │     Burst (5+ in 5 minutes)   → +10 points
        ├── Classifies severity:
        │     score >= 80 → CRITICAL
        │     score >= 60 → HIGH
        │     score >= 30 → MEDIUM
        │     score < 30  → LOW
        ├── Calls Bedrock → threat interpretation
        ├── Saves finding to waf-correlation-findings
        └── Publishes EventBridge event (if MEDIUM/HIGH/CRITICAL)
                │
                ▼
        EventBridge Rules (severity routing)
                │
        ┌───────┴────────────────────┐
        │                            │
   MEDIUM/HIGH                  CRITICAL
        │                            │
        ▼                            ▼
soar-response-agent     soar-response-agent + SNS (instant page)
        │
        ├── Retrieves full finding from DynamoDB (doorbell pattern)
        ├── Validates status = OPEN
        ├── Selects deterministic playbook:
        │     LOW      → RECORD_ONLY (no EventBridge trigger)
        │     MEDIUM   → NOTIFY_ANALYST
        │     HIGH     → CREATE_AND_ESCALATE_INCIDENT
        │     CRITICAL → REQUEST_URGENT_REVIEW
        ├── Calls Bedrock → analyst + manager summaries
        ├── Creates incident in security-incidents DynamoDB
        │     incident_id = INC-{finding_id} (idempotent)
        ├── Publishes SNS notification → email to analyst
        └── Updates finding status → RESPONSE_COMPLETED
                │
                ▼
        security-incidents DynamoDB Table

        (Lab 12b — runs separately on demand)
        executive-dashboard-agent Lambda
        │
        ├── Reads all 3 security tables
        ├── Calls Bedrock → executive narrative
        ├── Generates PDF using ReportLab (Lambda Layer)
        └── Uploads PDF + JSON to S3
              chewbacca-s3-{account_id}/
              executive-reports/YYYY/MM/DD/
              ├── pdf/executive-security-{timestamp}.pdf
              └── json/executive-security-{timestamp}.json

        (Class 7 — runs every 5 minutes via EventBridge Scheduler)
        unused-token-detector Lambda
        │
        ├── Scans token-tracking for used=False tokens older than 10 min
        ├── Calls Bedrock → SOAR incident summary per stale token
        └── Logs alert to CloudWatch
```

---

## 3. Prerequisites

### Tools Required

```bash
# Verify all tools before starting
terraform --version   # Need 1.10+ for S3 native locking
aws --version         # Need AWS CLI v2
python --version      # Need Python 3.x
git --version         # Need Git for GitHub push
```

### AWS Configuration

```bash
aws configure
# Enter: Access Key ID, Secret Access Key, Region (us-east-1), Output (json)

# Verify you are authenticated
aws sts get-caller-identity
```

### Bedrock Model Access

Before deploying, verify the model works in your account:

```bash
MSYS_NO_PATHCONV=1 aws bedrock-runtime invoke-model \
  --model-id us.anthropic.claude-haiku-4-5-20251001-v1:0 \
  --body "{\"anthropic_version\":\"bedrock-2023-05-31\",\"max_tokens\":100,\"messages\":[{\"role\":\"user\",\"content\":\"say hello\"}]}" \
  --cli-binary-format raw-in-base64-out \
  output.json && cat output.json
```

**Expected:** JSON response with "Hello" in the content field.

**Why `us.` prefix:** Newer Anthropic models require cross-region inference profiles.
The `us.` prefix routes through AWS inference profiles. Without it you get
`ValidationException: Invocation of model ID ... with on-demand throughput isn't supported`.
Direct model IDs like `anthropic.claude-3-haiku-20240307-v1:0` are LEGACY and become
inaccessible after 30 days without use.

### Windows Git Bash — Critical Settings

**Problem 1 — Path mangling:**
Git Bash converts `/aws/...` paths to Windows paths like `C:/Program Files/Git/aws/...`

**Fix:** Add `MSYS_NO_PATHCONV=1` before any command with `/` paths:
```bash
MSYS_NO_PATHCONV=1 aws wafv2 put-logging-configuration ...
MSYS_NO_PATHCONV=1 terraform import aws_cloudwatch_log_group.waf_logs /aws/lambda/name
```

**Problem 2 — SSL certificate revocation:**
Windows blocks SSL checks causing connection errors.

**Fix:** Add `--ssl-no-revoke` to all curl commands:
```bash
curl --ssl-no-revoke "https://..."
```

**Problem 3 — Shell characters:**
`<` and `>` are shell redirect operators in bash. Using them in URLs breaks commands.

**Fix:** URL-encode them:
- `<` = `%3C`
- `>` = `%3E`
- `/` = `%2F` (when needed)

```bash
# WRONG — shell interprets < and > as file redirectors
curl "https://.../python?name=<script>alert(1)</script>"

# CORRECT — URL encoded
curl --ssl-no-revoke "https://.../python?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

**Problem 4 — zip command not available:**
Git Bash on Windows doesn't have the `zip` command.

**Fix:** Use Python's zipfile module instead:
```bash
python -m zipfile -c output.zip input_file.py
```

**Problem 5 — Bracket paste mode:**
When copying commands from Claude and pasting, you may see `^[[200~` at the start.

**Fix:** Open a fresh Git Bash terminal and type commands manually, or press
`Ctrl+C` to cancel and retype.

**Problem 6 — Capturing terminal output:**
You cannot copy terminal output as plain text reliably on Windows.

**Fix:** Use `tee` to save to a file:
```bash
terraform plan 2>&1 | tee plan_output.txt
terraform apply 2>&1 | tee apply_output.txt
```

---

## 4. Repository Structure

```
armageddon_lab12ab/
│
├── Terraform Files (Infrastructure as Code)
│   ├── 0-auth.tf              ← Reserved placeholder
│   ├── 0-providers.tf         ← AWS provider, region, data sources
│   ├── 1-dynamodb.tf          ← All DynamoDB tables
│   ├── 2-iam.tf               ← IAM roles for security Lambdas
│   ├── 3-lambdas.tf           ← WAF analyzer, correlation, SOAR Lambdas
│   ├── 4-eventbridge.tf       ← EventBridge rules for severity routing
│   ├── 5-sns.tf               ← SNS critical alert topic + email subscription
│   ├── 6-outputs.tf           ← Terraform outputs (URLs, ARNs, names)
│   ├── 7-variables.tf         ← Variable declarations (email masked)
│   ├── 8-api-lambdas.tf       ← Python and Node API Lambdas
│   ├── 9-chewbacca-iam.tf     ← chewbacca_lambda_role (Class 7)
│   ├── 10-rest-api.tf         ← API Gateway REST API
│   ├── 11-cognito.tf          ← Cognito user pool, groups, MFA
│   ├── 12-waf.tf              ← WAF Web ACL, rules, logging config
│   ├── 13-token-tracking.tf   ← Token tracking + unused-token-detector
│   ├── 14-test-data.tf        ← Pre-seeded HIGH severity test finding
│   └── 15-executive-report.tf ← S3 bucket, ReportLab layer, exec Lambda
│
├── src/                        ← Lambda source code
│   ├── waf_bedrock_analyzer.py          ← Lab 12b updated WAF analyzer
│   ├── waf_threat_correlation_agent.py  ← Correlation + risk scoring
│   ├── soar_response_agent.py           ← SOAR playbook executor
│   ├── executive_dashboard_agent.py     ← PDF report generator
│   ├── detection.py                     ← Stale token detector
│   ├── chewbacca-python-lambda.py       ← API Lambda with RBAC
│   ├── chewbacca-node-lambda.js         ← API Lambda (Node.js)
│   └── coolrunnings_get_easy_token.py   ← Cognito auth script
│
├── policies/                   ← IAM policy JSON files
│   ├── access-DynamoDB.json    ← DynamoDB permissions
│   ├── bedrock.json            ← Bedrock permissions
│   └── waf_role.json           ← WAF analyzer permissions
│
├── deliverables/               ← Lab deliverables
│   ├── lab12ab_tests.md        ← Test plan with commands
│   └── lab12ab_test_results.md ← Test results with outputs
│
├── build/                      ← Auto-generated Lambda zips (gitignored)
│   └── reportlab_layer.zip     ← Must be built before terraform apply
│
├── terraform.tfvars            ← Secret values — NEVER committed (gitignored)
├── .gitignore                  ← Protects secrets and build artifacts
└── README.md                   ← Project README
```

---

## 5. Terraform Files — What Each One Does

### `0-providers.tf` — Foundation
Declares the AWS provider and Terraform version. Also defines three data sources
used throughout all other files:
- `data.aws_caller_identity.current` — your account ID
- `data.aws_region.current` — current region
- `data.aws_partition.current` — aws vs aws-cn vs aws-us-gov

**Why data sources:** Instead of hardcoding `975598471165` everywhere, we use
`data.aws_caller_identity.current.account_id` so the code works in any account.

### `1-dynamodb.tf` — Data Storage
Creates three DynamoDB tables:
- `waf-events` — WAF block event telemetry (written by waf-bedrock-analyzer)
- `waf-correlation-findings` — Threat correlation findings (written by correlation agent)
- `security-incidents` — SOAR incident records (written by SOAR agent)

All use `PAY_PER_REQUEST` billing — you pay per read/write, not for idle capacity.
This is ideal for security pipelines with unpredictable traffic patterns.

### `2-iam.tf` — Security Permissions
Creates three IAM roles — one per security Lambda. Each role follows least privilege:
- `armageddon-waf-analyzer-role` — can read CloudWatch logs, write to waf-events, call Bedrock
- `armageddon-correlation-agent-role` — can scan waf-events, write findings, call Bedrock, put EventBridge events
- `armageddon-soar-agent-role` — can read/update findings, write incidents, publish SNS, call Bedrock
- `armageddon-executive-report-role` — can scan all 3 tables, call Bedrock, write to S3

### `3-lambdas.tf` — The Security Pipeline Lambdas
Creates four Lambda functions with their CloudWatch log groups and archive_file
data sources (which zip the source code automatically):
- `waf-bedrock-analyzer`
- `waf-threat-correlation-agent`
- `soar-response-agent`
- `executive-dashboard-agent`

Also creates the `aws-waf-logs-armageddon` CloudWatch log group (not the same as
`aws-waf-logs-chewbacca` which WAF actually writes to — see Gotcha #4).

### `4-eventbridge.tf` — Severity Routing
Creates two EventBridge rules using `aws_cloudwatch_event_rule` (NOT Scheduler):

**Why Rules not Scheduler:**
- `aws_scheduler_schedule` = time-based ("run every 5 minutes")
- `aws_cloudwatch_event_rule` = event-driven ("when THIS event arrives with THESE fields")

The correlation agent publishes a custom event and EventBridge routes it based on severity.

Rule 1 (`waf-medium-high-finding-rule`):
- Matches: `source = seir.waf.correlation`, `severity = MEDIUM or HIGH`
- Target: `soar-response-agent` Lambda

Rule 2 (`waf-critical-finding-rule`):
- Matches: `source = seir.waf.correlation`, `severity = CRITICAL`
- Targets: `soar-response-agent` Lambda AND `critical-alert` SNS topic simultaneously

Also creates `aws_lambda_permission` resources to allow EventBridge to invoke the Lambda,
and `aws_sns_topic_policy` to allow EventBridge to publish to SNS.

### `5-sns.tf` — Notifications
Creates the `critical-alert` SNS topic and email subscription.

**Gotcha:** After every `terraform destroy` and `terraform apply`, AWS sends a new
confirmation email. You MUST click "Confirm subscription" before SNS will deliver
messages. Until confirmed, SNS silently drops all messages.

Email address is stored in `terraform.tfvars` as `alert_email = "your@email.com"`
and referenced via `var.alert_email`. This keeps the email out of the `.tf` files
which are committed to GitHub.

### `6-outputs.tf` — Useful Values
Displays key values after every apply. Most important:
- `api_gateway_python_url` — use this for all curl tests
- `api_gateway_node_url` — alternate endpoint
- `waf_events_table_name` — DynamoDB table names for CLI commands

**Gotcha:** API Gateway gets a new ID after every destroy/apply. Always run
`terraform output api_gateway_python_url` after apply to get the current URL.

### `7-variables.tf` — Variable Declarations
Declares `alert_email` as a sensitive string variable. The `sensitive = true`
flag tells Terraform to show `(sensitive value)` in plan output instead of
the actual email address.

### `8-api-lambdas.tf` — API Endpoints
Creates the two API Lambdas from Class 7:
- `api_lambda_node` — Node.js, runtime `nodejs22.x` (was nodejs24.x — downgraded, not supported by this provider)
- `api_lambda_python` — Python, runtime `python3.13` (was python3.14 — downgraded)

Both use `AWS_PROXY` integration — API Gateway passes the full request to Lambda
including headers, query params, and the Cognito JWT claims in `requestContext`.

### `9-chewbacca-iam.tf` — Class 7 Role
The `chewbacca_lambda_role` from Class 7. Uses inline_policy (deprecated but functional)
to load permissions from three JSON files in `policies/`.

**Warning:** The `inline_policy is deprecated` warning appears on every plan/apply.
This is non-blocking. Future migration should use `aws_iam_role_policy` resources.

**Critical:** The JSON files must contain valid JSON — no `#` comments, no
`<region>` or `<account-id>` placeholder values. These caused `MalformedPolicyDocument`
errors in Class 7 until fixed.

### `10-rest-api.tf` — API Gateway
Creates the REST API with two endpoints protected by Cognito authorizer.
The `source_arn` in Lambda permissions uses `data.aws_region.current.name`
(NOT `.region` — that attribute doesn't exist and causes an error).

### `11-cognito.tf` — Authentication
Creates the Cognito user pool with MFA required, TOTP enabled, and two groups:
- `admins` — full access
- `students` — restricted access

The Python Lambda reads `cognito:groups` from JWT claims and enforces RBAC.

**Gotcha:** After destroy/apply, `cognitouser1` has no MFA device enrolled.
The `coolrunnings_get_easy_token.py` script fails with `MFA_SETUP` challenge.

**Fix sequence:**
```bash
# 1. Disable MFA temporarily
aws cognito-idp set-user-pool-mfa-config \
  --user-pool-id <pool-id> \
  --mfa-configuration OPTIONAL \
  --software-token-mfa-configuration Enabled=true

# 2. Reset password
aws cognito-idp admin-set-user-password \
  --user-pool-id <pool-id> \
  --username cognitouser1 \
  --password "BongoBeats1*" \
  --permanent

# 3. Run the auth script
python src/coolrunnings_get_easy_token.py
```

### `12-waf.tf` — WAF Protection
Creates the WAF Web ACL `token-api-waf` with 4 rules, associates it with API Gateway,
and creates the `aws-waf-logs-chewbacca` CloudWatch log group with a logging
configuration that links WAF to CloudWatch.

**Critical:** WAF log group names MUST start with `aws-waf-logs-`. Other prefixes
cause WAF to reject the logging configuration.

**Gotcha:** The `aws_wafv2_web_acl_logging_configuration` resource uses
`logs:FilterLogEvents` permission with `Resource = "*"`. If you scope this to
a specific log group ARN, it breaks when the WAF logging config changes between
applies.

### `13-token-tracking.tf` — Token Pipeline (Class 7)
Creates the token tracking pipeline:
- `token-tracking` DynamoDB table with GSI for username queries
- `lambda_dynamodb_token_policy` IAM policy
- `unused-token-detector` Lambda
- `eventbridge_token_detector_role` for EventBridge Scheduler
- `unused-token-check` EventBridge Scheduler (every 5 minutes)

### `14-test-data.tf` — Test Data
Pre-seeds a HIGH severity finding in `waf-correlation-findings` with a fixed
`finding_id: 7ea476d0-1fea-4ff0-a95a-6377faac5cb4` for testing the SOAR agent.

After the SOAR agent processes it, the finding status changes to `RESPONSE_COMPLETED`.
Running `terraform plan` will show it wants to reset to `OPEN` — this is expected.
Run `terraform apply` to reset it for the next test.

### `15-executive-report.tf` — Lab 12b
Creates:
- `chewbacca-s3-{account_id}` S3 bucket with versioning and public access blocked
- `reportlab-layer` Lambda layer (must build `build/reportlab_layer.zip` first)
- `executive-dashboard-agent` Lambda (1024MB memory, 120s timeout)
- `armageddon-executive-report-role` IAM role

**Critical:** The ReportLab layer zip must exist before `terraform apply`.
Build it with these commands (must be done after every machine reboot or fresh clone):

```bash
mkdir -p /tmp/reportlab_layer/python/lib/python3.13/site-packages

python -m pip install reportlab==4.4.3 \
  --target /tmp/reportlab_layer/python/lib/python3.13/site-packages \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 3.13 \
  --only-binary=:all: \
  --upgrade

cd /tmp/reportlab_layer
python -m zipfile -c ~/Documents/TheoWAF/class7/armageddon_12ab/build/reportlab_layer.zip python/
cd ~/Documents/TheoWAF/class7/armageddon_12ab
ls -lh build/reportlab_layer.zip
# Expected: 13M
```

---

## 6. Source Code Files — What Each One Does

### `waf_bedrock_analyzer.py` — WAF Event Processor

**What it does:**
1. Reads WAF block events from CloudWatch log group `aws-waf-logs-chewbacca`
2. Normalizes each event into a structured record
3. Calls Bedrock for a per-event SOC summary
4. Writes to `waf-events` DynamoDB table

**Key fields added (vs Class 7 version):**
- `event_epoch` — integer Unix timestamp (REQUIRED by correlation agent for time filtering)
- `source_ip` — renamed from `client_ip` to match correlation agent expectations
- Deterministic `event_id` using CloudWatch `eventId` or SHA256 hash to prevent duplicates

**Environment variables:**
```
WAF_LOG_GROUP    = aws-waf-logs-chewbacca
DYNAMODB_TABLE   = waf-events
BEDROCK_MODEL_ID = us.anthropic.claude-haiku-4-5-20251001-v1:0
LOOKBACK_MINUTES = 10
MAX_LOG_EVENTS   = 25
```

**Gotcha:** `WAF_LOG_GROUP` must point to `aws-waf-logs-chewbacca` (where WAF actually
writes logs) NOT `aws-waf-logs-armageddon` (which Terraform creates as a placeholder).
After every apply, verify:
```bash
aws lambda get-function-configuration \
  --function-name waf-bedrock-analyzer \
  --query 'Environment.Variables.WAF_LOG_GROUP'
# Must return: "aws-waf-logs-chewbacca"
```

---

### `waf_threat_correlation_agent.py` — Threat Correlation Engine

**What it does:**
1. Scans `waf-events` table for events within 60-minute window
2. Groups events by source IP, target URI, and WAF rule
3. Calculates deterministic risk score (never uses AI for scoring)
4. Calls Bedrock for human-readable threat interpretation
5. Saves finding to `waf-correlation-findings`
6. Publishes custom EventBridge event to trigger SOAR agent

**Key functions:**
- `get_recent_events()` — scans DynamoDB with `event_epoch` time filter
- `calculate_risk_score()` — pure Python math, transparent and auditable
- `classify_severity()` — maps score to LOW/MEDIUM/HIGH/CRITICAL
- `call_bedrock()` — sends evidence package to Claude for interpretation
- `save_finding()` — writes to DynamoDB with `native_to_decimal()` conversion
- `publish_finding_event()` — puts custom event on EventBridge

**Critical fix — `native_to_decimal()`:**
DynamoDB requires `Decimal` type for numbers, not Python `float` or `int`.
This function recursively converts the entire item before writing.
The `bool` check MUST come before the `int` check because Python's `bool`
is a subclass of `int` — `isinstance(True, int)` returns `True`.

```python
def native_to_decimal(value):
    if isinstance(value, bool):    # MUST be before int check
        return value
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, int):
        return Decimal(str(value))
    return value
```

**Environment variables:**
```
WAF_EVENTS_TABLE           = waf-events
CORRELATION_FINDINGS_TABLE = waf-correlation-findings
BEDROCK_MODEL_ID           = us.anthropic.claude-haiku-4-5-20251001-v1:0
CORRELATION_WINDOW_MINUTES = 60
MINIMUM_EVENT_COUNT        = 3
MAX_EVENTS                 = 500
ADMIN_URI_KEYWORDS         = admin,login,signin,auth,token,cognito
EVENT_BUS_NAME             = default
```

---

### `soar_response_agent.py` — SOAR Incident Response

**What it does:**
1. Receives EventBridge event (contains only `finding_id` — doorbell pattern)
2. Retrieves full finding from DynamoDB using `ConsistentRead=True`
3. Validates finding exists, status is OPEN, severity is valid
4. Selects playbook deterministically (Bedrock does NOT choose the playbook)
5. Calls Bedrock for analyst and manager summaries
6. Creates incident with `INC-{finding_id}` (idempotent — prevents duplicates)
7. Publishes SNS notification
8. Updates finding status to RESPONSE_COMPLETED

**Why the "doorbell pattern":**
The EventBridge event contains only the `finding_id`, not the full finding data.
The Lambda retrieves the authoritative record from DynamoDB. This prevents
attackers from injecting fake low-severity payloads into EventBridge to bypass
security checks.

**Why `INC-{finding_id}` as incident ID:**
EventBridge has at-least-once delivery guarantee — it may deliver the same event
twice. The deterministic incident ID plus a conditional `PutItem` prevents
duplicate incidents from being created on retry.

**Environment variables:**
```
CORRELATION_FINDINGS_TABLE = waf-correlation-findings
SECURITY_INCIDENTS_TABLE   = security-incidents
SNS_TOPIC_ARN              = arn:aws:sns:us-east-1:...
BEDROCK_MODEL_ID           = us.anthropic.claude-haiku-4-5-20251001-v1:0
ENABLE_BEDROCK             = true
```

---

### `executive_dashboard_agent.py` — Executive Report Generator (Lab 12b)

**What it does:**
1. Reads all 3 security DynamoDB tables for last 24 hours
2. Calculates security metrics and overall posture
3. Calls Bedrock for executive narrative
4. Generates multi-page PDF using ReportLab
5. Uploads PDF and JSON to S3

**Why a Lambda Layer for ReportLab:**
ReportLab is not in the standard Lambda Python runtime. It must be provided
as a Lambda Layer. The layer must be compiled for the Lambda Linux runtime
using `--platform manylinux2014_x86_64` — Windows binaries won't work.

**Test event:**
```json
{"report_period_hours": 24}
```

**S3 output layout:**
```
chewbacca-s3-{account_id}/
└── executive-reports/
    └── YYYY/MM/DD/
        ├── pdf/executive-security-{timestamp}.pdf
        └── json/executive-security-{timestamp}.json
```

---

### `detection.py` — Stale Token Detector (Class 7)

**What it does:**
1. Scans `token-tracking` table for tokens where `used=False` and age > 10 minutes
2. Calls Bedrock per stale token for a SOAR-style incident summary
3. Triggered automatically by EventBridge Scheduler every 5 minutes

---

### `chewbacca-python-lambda.py` — API Lambda with RBAC

**What it does:**
1. Reads Cognito JWT claims from `requestContext.authorizer.claims`
2. Extracts `cognito:groups` — arrives as comma-separated STRING not a list
3. Splits on comma: `groups = groups_raw.split(",") if groups_raw else []`
4. Checks if "admins" in groups
5. Returns 200 or 403

**Why string splitting matters:**
API Gateway passes Cognito groups as `"admins,students"` (string), not
`["admins", "students"]` (list). Using `claims.get("cognito:groups", [])` returns
a string, not an empty list, so membership checks fail. Must use `.split(",")`.

---

### `coolrunnings_get_easy_token.py` — Cognito Auth Script

**How to use:**
```bash
python src/coolrunnings_get_easy_token.py
```

**Inputs:**
- Client ID: get from `aws cognito-idp list-user-pool-clients --user-pool-id <id>`
- Region: `us-east-1`
- Username: `cognitouser1`
- Password: `BongoBeats1*`
- Answer `y` to display tokens

**Use the ID Token** (not Access Token) for API Gateway Authorization header.
The ID Token contains `cognito:groups` which the Lambda reads for RBAC.
Tokens expire in 15 minutes.

---

## 7. IAM Roles and Policies — Why Each Permission Exists

### `armageddon-waf-analyzer-role`

| Permission | Resource | Why |
|---|---|---|
| `logs:FilterLogEvents` | `*` | Read WAF events from CloudWatch. Must be `*` — scoping to specific ARN breaks when logging config changes |
| `dynamodb:PutItem` | `waf-events` table | Write normalized WAF events |
| `dynamodb:GetItem` | `waf-events` table | Check for duplicate event_id |
| `bedrock:InvokeModel` | `*` | Generate SOC summary per event |

### `armageddon-correlation-agent-role`

| Permission | Resource | Why |
|---|---|---|
| `dynamodb:Scan` | `waf-events` table | Scan for events in time window |
| `dynamodb:Query` | `waf-events` table | Future GSI queries |
| `dynamodb:GetItem` | `waf-events` table | Retrieve individual events |
| `dynamodb:PutItem` | `waf-correlation-findings` | Write new finding |
| `dynamodb:GetItem` | `waf-correlation-findings` | Read existing finding |
| `dynamodb:UpdateItem` | `waf-correlation-findings` | Update finding status |
| `bedrock:InvokeModel` | `*` | Generate threat interpretation |
| `events:PutEvents` | `*` | Publish custom event to trigger SOAR |

### `armageddon-soar-agent-role`

| Permission | Resource | Why |
|---|---|---|
| `dynamodb:GetItem` | `waf-correlation-findings` | Retrieve full finding (doorbell pattern) |
| `dynamodb:UpdateItem` | `waf-correlation-findings` | Mark finding as RESPONSE_COMPLETED |
| `dynamodb:PutItem` | `security-incidents` | Create new incident record |
| `dynamodb:GetItem` | `security-incidents` | Check for duplicate incident |
| `sns:Publish` | `critical-alert` topic | Send analyst notification |
| `bedrock:InvokeModel` | `*` | Generate analyst + manager summaries |

### `armageddon-executive-report-role`

| Permission | Resource | Why |
|---|---|---|
| `dynamodb:Scan` | All 3 tables | Read security data for report |
| `bedrock:InvokeModel` | `*` | Generate executive narrative |
| `s3:PutObject` | `executive-reports/*` prefix | Upload PDF and JSON |

---

## 8. DynamoDB Tables — What Gets Stored Where

### `waf-events` — WAF Block Event Telemetry

**Primary key:** `event_id` (string)
**Written by:** `waf-bedrock-analyzer`
**Read by:** `waf-threat-correlation-agent`

**Record structure:**
```json
{
  "event_id": "sha256-hash-of-cloudwatch-event-id",
  "event_epoch": 1785805222,
  "timestamp": "2026-08-03T23:00:00Z",
  "source_ip": "75.24.108.158",
  "country": "US",
  "action": "BLOCK",
  "method": "GET",
  "uri": "/prod/python",
  "args": "name=%3Cscript%3E...",
  "rule": "AWSManagedRulesCommonRuleSet",
  "rule_type": "MANAGED_RULE_GROUP"
}
```

**Why `event_epoch`:** DynamoDB `FilterExpression` needs numeric comparison
for time-window filtering. ISO timestamp strings cannot be compared mathematically.
`Attr("event_epoch").gte(minimum_epoch)` is how the correlation agent's
60-minute window works.

### `waf-correlation-findings` — Threat Findings

**Primary key:** `finding_id` (UUID string)
**Written by:** `waf-threat-correlation-agent`
**Read by:** `soar-response-agent`, `executive-dashboard-agent`

**Record structure:**
```json
{
  "finding_id": "0c18ca79-be6a-4ed2-aaf9-ebd3ab5e0cdc",
  "created_at": "2026-08-03T23:30:00Z",
  "severity": "MEDIUM",
  "risk_score": 30,
  "status": "OPEN",
  "primary_source_ip": "75.24.108.158",
  "primary_target": "/prod/python",
  "event_count": 14,
  "window_start": "2026-08-03T22:30:00Z",
  "window_end": "2026-08-03T23:30:00Z",
  "bedrock_report": "Threat Classification: ...",
  "evidence": { ... full evidence package ... }
}
```

**Status lifecycle:** `OPEN` → `RESPONSE_COMPLETED`

### `security-incidents` — SOAR Incident Records

**Primary key:** `incident_id` (string — always `INC-{finding_id}`)
**Written by:** `soar-response-agent`
**Read by:** `executive-dashboard-agent`

**Record structure:**
```json
{
  "incident_id": "INC-0c18ca79-be6a-4ed2-aaf9-ebd3ab5e0cdc",
  "finding_id": "0c18ca79-be6a-4ed2-aaf9-ebd3ab5e0cdc",
  "severity": "MEDIUM",
  "playbook": "NOTIFY_ANALYST",
  "incident_created": true,
  "notification_sent": true,
  "sns_message_id": "c4d28704-...",
  "bedrock_summary_generated": true,
  "human_review_required": true
}
```

### `token-tracking` — Cognito Token Tracking (Class 7)

**Primary key:** `token_id` (string)
**Written by:** `get_token.py` (when user authenticates)
**Read by:** `unused-token-detector`

---

## 9. EventBridge — How Severity Routing Works

### Two Different EventBridge Services

| Service | Terraform Resource | Type | Used For |
|---|---|---|---|
| EventBridge Rules | `aws_cloudwatch_event_rule` | Event-driven | Route findings by severity |
| EventBridge Scheduler | `aws_scheduler_schedule` | Time-based | Run detector every 5 min |

### Custom Event Format

The correlation agent publishes this event when severity >= MEDIUM:

```json
{
  "source": "seir.waf.correlation",
  "detail-type": "WAF Threat Finding Created",
  "detail": {
    "finding_id": "uuid",
    "severity": "HIGH",
    "risk_score": 75
  },
  "EventBusName": "default"
}
```

### Routing Rules

| Rule | Event Pattern Match | Targets |
|---|---|---|
| `waf-medium-high-finding-rule` | severity = MEDIUM or HIGH | soar-response-agent Lambda |
| `waf-critical-finding-rule` | severity = CRITICAL | soar-response-agent Lambda + critical-alert SNS |

**Why two targets for CRITICAL:**
CRITICAL findings page the engineer instantly via SNS (fires at the edge of EventBridge
before Lambda even starts) AND trigger the full SOAR workflow. The analyst gets
paged immediately while the Lambda creates the detailed incident ticket.

---

## 10. First-Time Deployment

### Step 1 — Clone and set up

```bash
git clone https://github.com/Queuefour97/armageddon_lab12ab.git
cd armageddon_lab12ab

# Create terraform.tfvars (gitignored — never committed)
echo 'alert_email = "your-email@gmail.com"' > terraform.tfvars
```

### Step 2 — Build ReportLab layer (REQUIRED before apply)

```bash
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
ls -lh build/reportlab_layer.zip
# Expected: ~13M
```

### Step 3 — Deploy

```bash
terraform init
terraform plan 2>&1 | tee plan_output.txt
# Review plan — should show ~77 resources to add

terraform apply 2>&1 | tee apply_output.txt
# Type 'yes' when prompted
```

### Step 4 — Note the outputs

```bash
terraform output
```

Key outputs to note:
- `api_gateway_python_url` — use for all curl tests
- `api_gateway_node_url` — alternate endpoint
- `executive_report_bucket` — S3 bucket name

---

## 11. Post-Deployment Checklist

Run these after EVERY `terraform apply`:

```bash
# 1. Check SNS confirmation email and click "Confirm subscription"
#    Without this, SNS silently drops all notifications

# 2. Verify WAF logging is attached
aws wafv2 list-web-acls --scope REGIONAL \
  --query 'WebACLs[].{Name:Name,Id:Id}' --output table
# Note the new WAF ID then:
aws wafv2 get-logging-configuration \
  --resource-arn arn:aws:wafv2:us-east-1:ACCOUNT:regional/webacl/token-api-waf/WAF_ID \
  --query 'LoggingConfiguration.LogDestinationConfigs'
# Expected: ["arn:...log-group:aws-waf-logs-chewbacca"]

# 3. Verify Lambda env var
aws lambda get-function-configuration \
  --function-name waf-bedrock-analyzer \
  --query 'Environment.Variables.WAF_LOG_GROUP'
# Expected: "aws-waf-logs-chewbacca"

# 4. Get current API URL
terraform output api_gateway_python_url

# 5. Set as variable for testing
API_URL=$(terraform output -raw api_gateway_python_url)
echo $API_URL
```

---

## 12. Bring Stack Back Up After Destroy

```bash
cd ~/Documents/TheoWAF/class7/armageddon_12ab

# Step 1 — Build ReportLab layer (must rebuild every time)
mkdir -p /tmp/reportlab_layer/python/lib/python3.13/site-packages
python -m pip install reportlab==4.4.3 \
  --target /tmp/reportlab_layer/python/lib/python3.13/site-packages \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 3.13 \
  --only-binary=:all: \
  --upgrade
cd /tmp/reportlab_layer
python -m zipfile -c ~/Documents/TheoWAF/class7/armageddon_12ab/build/reportlab_layer.zip python/
cd ~/Documents/TheoWAF/class7/armageddon_12ab

# Step 2 — Apply
terraform init
terraform apply 2>&1 | tee apply_output.txt
# Type 'yes'

# Step 3 — Post-deploy checklist (see Section 11)
# Check email for SNS confirmation
# Verify WAF logging
# Verify Lambda env var
# Get new API URL

# Step 4 — Fix Cognito MFA (needed after every destroy/apply)
POOL_ID=$(aws cognito-idp list-user-pools --max-results 10 \
  --query 'UserPools[?Name==`cognito_pool`].Id' --output text)

aws cognito-idp set-user-pool-mfa-config \
  --user-pool-id $POOL_ID \
  --mfa-configuration OPTIONAL \
  --software-token-mfa-configuration Enabled=true

aws cognito-idp admin-set-user-password \
  --user-pool-id $POOL_ID \
  --username cognitouser1 \
  --password "BongoBeats1*" \
  --permanent

echo "Stack is ready"
```

---

## 13. How to Run Tests in AWS Console

### Running Lambda Tests in the AWS Console

1. Go to **AWS Console → Lambda → Functions**
2. Click on the Lambda function you want to test (e.g. `waf-threat-correlation-agent`)
3. Click the **Test** tab
4. Click **Create new test event**
5. Give it a name (e.g. `test-correlation`)
6. Paste the test event JSON (see below for each Lambda)
7. Click **Save**
8. Click **Test** button
9. Expand **Execution results** to see the output
10. Click **Function logs** tab to see the full CloudWatch output

### Test Events for Each Lambda

**waf-bedrock-analyzer:**
```json
{}
```
(No input needed — Lambda reads from CloudWatch automatically)

**waf-threat-correlation-agent:**
```json
{}
```
(No input needed — Lambda scans DynamoDB automatically)

**soar-response-agent (MEDIUM severity):**
```json
{
  "version": "0",
  "id": "test-event-console",
  "detail-type": "WAF Threat Finding Created",
  "source": "seir.waf.correlation",
  "account": "975598471165",
  "time": "2026-08-04T00:00:00Z",
  "region": "us-east-1",
  "resources": [],
  "detail": {
    "finding_id": "PASTE_FINDING_ID_HERE",
    "severity": "MEDIUM",
    "risk_score": 30
  }
}
```

**soar-response-agent (HIGH severity using test data):**
```json
{
  "version": "0",
  "id": "test-high-console",
  "detail-type": "WAF Threat Finding Created",
  "source": "seir.waf.correlation",
  "account": "975598471165",
  "time": "2026-08-04T00:00:00Z",
  "region": "us-east-1",
  "resources": [],
  "detail": {
    "finding_id": "7ea476d0-1fea-4ff0-a95a-6377faac5cb4",
    "severity": "HIGH",
    "risk_score": 75
  }
}
```

**executive-dashboard-agent:**
```json
{
  "report_period_hours": 24
}
```

### Viewing CloudWatch Logs in Console

1. Go to **CloudWatch → Log groups**
2. Find `/aws/lambda/FUNCTION_NAME`
3. Click the most recent log stream
4. Look for the Bedrock output between the `=====` markers

---

## 14. Complete Test Plan with Commands and Expected Outputs

### Setup — Run Before All Tests

```bash
cd ~/Documents/TheoWAF/class7/armageddon_12ab
API_URL=$(terraform output -raw api_gateway_python_url)
echo "API URL: $API_URL"
```

---

### Test 1 — XSS Attack Block

```bash
curl --ssl-no-revoke -I \
  "${API_URL}?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
```

**Expected:**
```
HTTP/1.1 403 Forbidden
x-amzn-ErrorType: ForbiddenException
```

**What `%3Cscript%3E` means:** URL-encoded `<script>`. Git Bash interprets `<` and `>`
as shell redirect operators so they must be encoded.

---

### Test 2 — SQL Injection Block

```bash
curl --ssl-no-revoke -I \
  "${API_URL}?name=%27%20OR%201%3D1--"
```

**Expected:** `HTTP/1.1 403 Forbidden`

**Decode:** `%27` = `'`, `%20` = space, `%3D` = `=` → payload is `' OR 1=1--`

---

### Test 3 — Rate Limiting (DDoS Simulation)

First get a JWT token (tokens expire in 15 minutes — run immediately):

```bash
# Get Cognito Pool ID
POOL_ID=$(aws cognito-idp list-user-pools --max-results 10 \
  --query 'UserPools[?Name==`cognito_pool`].Id' --output text)
echo $POOL_ID

# Get Client ID
aws cognito-idp list-user-pool-clients \
  --user-pool-id $POOL_ID \
  --query 'UserPoolClients[].ClientId' --output text

# Run auth script
python src/coolrunnings_get_easy_token.py
# Enter Client ID, Region: us-east-1, Username: cognitouser1, Password: BongoBeats1*
# Copy the ID Token

TOKEN="paste-id-token-here"
```

Run 150 parallel requests:
```bash
for i in {1..150}; do
  curl --ssl-no-revoke -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: $TOKEN" \
  "${API_URL}?name=Chewbacca" &
done | tee test3_parallel.txt
wait

grep -c "200" test3_parallel.txt
grep -c "403" test3_parallel.txt
```

**Expected:** Mix of 200 and 403 — 403s appear after rate limit threshold is exceeded.

**Gotcha:** Sequential requests (no `&`) are too slow to trigger the rate limit.
Must run in parallel. If all return 200, the requests spread beyond the 5-minute window.
If all return 403, your IP was already rate-limited from a previous test.
Wait 5 minutes for the rate limit window to reset.

---

### Test 4 — WAF Bedrock Analyzer

First generate WAF events:
```bash
for i in {1..10}; do
  curl --ssl-no-revoke -o /dev/null -w "%{http_code}\n" \
  "${API_URL}?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
done

sleep 30  # Wait for WAF to flush logs to CloudWatch
```

Then invoke the analyzer:
```bash
aws lambda invoke --function-name waf-bedrock-analyzer response_waf.json
cat response_waf.json
```

**Expected:**
```json
{"statusCode": 200, "body": "{\"message\": \"WAF event processing completed.\",
  \"events_found\": 10, \"events_stored\": 10, \"events_analyzed\": 10, \"events_failed\": 0}"}
```

**If events_found is 0:** Check WAF logging configuration (see Gotcha #4).

---

### Test 5 — Threat Correlation Agent

```bash
aws lambda invoke --function-name waf-threat-correlation-agent response_correlation.json
cat response_correlation.json
```

**Expected:**
```json
{"statusCode": 200, "body": "{\"message\": \"Threat correlation completed.\",
  \"finding_created\": true,
  \"finding_id\": \"UUID-HERE\",
  \"events_correlated\": 10,
  \"severity\": \"MEDIUM\",
  \"risk_score\": 35,
  \"primary_source_ip\": \"YOUR-IP\"}"}
```

**Save the finding_id** — you need it for Test 6.

**If events_found is 0:** Records in waf-events are missing `event_epoch` field.
This means they were written by the old Class 7 analyzer code.
Generate fresh events and run waf-bedrock-analyzer again.

---

### Test 6 — SOAR Agent (MEDIUM Severity)

Replace `FINDING_ID` with the value from Test 5:

```bash
FINDING_ID="paste-finding-id-from-test-5"

MSYS_NO_PATHCONV=1 aws lambda invoke \
  --function-name soar-response-agent \
  --payload "{\"version\":\"0\",\"id\":\"test\",\"detail-type\":\"WAF Threat Finding Created\",\"source\":\"seir.waf.correlation\",\"account\":\"975598471165\",\"time\":\"2026-08-04T00:00:00Z\",\"region\":\"us-east-1\",\"resources\":[],\"detail\":{\"finding_id\":\"$FINDING_ID\",\"severity\":\"MEDIUM\",\"risk_score\":35}}" \
  --cli-binary-format raw-in-base64-out \
  response_soar.json
cat response_soar.json
```

**Expected:**
```json
{"statusCode": 200, "body": "{\"incident_created\": true,
  \"severity\": \"MEDIUM\",
  \"playbook\": \"NOTIFY_ANALYST\",
  \"notification_sent\": true,
  \"bedrock_summary_generated\": true,
  \"human_review_required\": true}"}
```

Check email for SNS notification.

**If workflow_skipped:** Finding already processed. Either use a new finding_id
from running Test 5 again, or run `terraform apply` to reset the test finding.

---

### Test 7 — SOAR Agent (HIGH Severity)

Uses the pre-seeded test finding from `14-test-data.tf`:

```bash
MSYS_NO_PATHCONV=1 aws lambda invoke \
  --function-name soar-response-agent \
  --payload '{"version":"0","id":"test-high","detail-type":"WAF Threat Finding Created","source":"seir.waf.correlation","account":"975598471165","time":"2026-08-04T00:00:00Z","region":"us-east-1","resources":[],"detail":{"finding_id":"7ea476d0-1fea-4ff0-a95a-6377faac5cb4","severity":"HIGH","risk_score":75}}' \
  --cli-binary-format raw-in-base64-out \
  response_soar_high.json
cat response_soar_high.json
```

**Expected:** `"playbook": "CREATE_AND_ESCALATE_INCIDENT"`

**If workflow_skipped:** Run `terraform apply` to reset the test finding to OPEN status.

---

### Test 8 — Executive Report (Lab 12b)

```bash
MSYS_NO_PATHCONV=1 aws lambda invoke \
  --function-name executive-dashboard-agent \
  --payload '{"report_period_hours": 24}' \
  --cli-binary-format raw-in-base64-out \
  response_12b.json
cat response_12b.json
```

**Expected:**
```json
{"statusCode": 200, "body": "{\"message\": \"Executive security report generated and published.\",
  \"report_id\": \"executive-security-TIMESTAMP\",
  \"overall_security_posture\": \"ELEVATED\",
  \"bedrock_used\": true,
  \"artifacts\": {\"pdf\": {\"size_bytes\": 6339}, \"json\": {\"size_bytes\": 7481}}}"}
```

Download the PDF:
```bash
aws s3 ls s3://chewbacca-s3-975598471165/executive-reports/ --recursive
aws s3 cp s3://chewbacca-s3-975598471165/executive-reports/2026/08/04/pdf/ . --recursive
```

---

### Test 9 — EventBridge Rules Active

```bash
aws events list-rules \
  --query 'Rules[?contains(Name, `waf`)].{Name:Name,State:State}' \
  --output table
```

**Expected:** Both rules show `ENABLED`.

---

### Test 10 — SNS Subscription Confirmed

```bash
aws sns list-subscriptions-by-topic \
  --topic-arn arn:aws:sns:us-east-1:975598471165:critical-alert \
  --query 'Subscriptions[].{Protocol:Protocol,Status:SubscriptionArn}' \
  --output table
```

**Expected:** Status shows full ARN (not `PendingConfirmation`).

---

### Test 11 — DynamoDB Record Counts

```bash
echo "=== WAF Events ===" && \
aws dynamodb scan --table-name waf-events --select COUNT && \
echo "=== Correlation Findings ===" && \
aws dynamodb scan --table-name waf-correlation-findings --select COUNT && \
echo "=== Security Incidents ===" && \
aws dynamodb scan --table-name security-incidents --select COUNT && \
echo "=== Token Tracking ===" && \
aws dynamodb scan --table-name token-tracking --select COUNT
```

**Expected:** Count > 0 for waf-events, waf-correlation-findings, security-incidents.

---

### Test 12 — Terraform State Clean

```bash
terraform plan 2>&1 | tee final_plan.txt
```

**Expected:** `No changes. Your infrastructure matches the configuration.`

---

## 15. How to Find Key Values

### Get Current API Gateway URL

```bash
terraform output api_gateway_python_url
# Or:
aws apigateway get-rest-apis \
  --query 'items[?name==`lambda-rest-api`].{id:id,name:name}' \
  --output table
```

### Get Current WAF ID

```bash
aws wafv2 list-web-acls --scope REGIONAL \
  --query 'WebACLs[].{Name:Name,Id:Id}' --output table
```

### Get Cognito Pool ID

```bash
aws cognito-idp list-user-pools --max-results 10 \
  --query 'UserPools[?Name==`cognito_pool`].{Name:Name,Id:Id}' \
  --output table
```

### Get Cognito Client ID

```bash
aws cognito-idp list-user-pool-clients \
  --user-pool-id POOL_ID \
  --query 'UserPoolClients[].{Name:ClientName,Id:ClientId}' \
  --output table
```

### Get Latest Finding ID

```bash
aws dynamodb scan \
  --table-name waf-correlation-findings \
  --filter-expression "#s = :open" \
  --expression-attribute-names '{"#s":"status"}' \
  --expression-attribute-values '{":open":{"S":"OPEN"}}' \
  --query 'Items[].{finding_id:finding_id.S,severity:severity.S,status:status.S}'
```

### Get All Finding IDs

```bash
aws dynamodb scan \
  --table-name waf-correlation-findings \
  --query 'Items[].{id:finding_id.S,severity:severity.S,status:status.S}' \
  --output table
```

### Get Security Incidents

```bash
aws dynamodb scan \
  --table-name security-incidents \
  --query 'Items[].{id:incident_id.S,severity:severity.S,playbook:playbook.S}' \
  --output table
```

### Get WAF Events Count by Source IP

```bash
aws dynamodb scan \
  --table-name waf-events \
  --query 'Items[].source_ip.S' \
  --output text | tr '\t' '\n' | sort | uniq -c | sort -rn
```

### Check Lambda Environment Variables

```bash
aws lambda get-function-configuration \
  --function-name waf-bedrock-analyzer \
  --query 'Environment.Variables'

aws lambda get-function-configuration \
  --function-name waf-threat-correlation-agent \
  --query 'Environment.Variables'

aws lambda get-function-configuration \
  --function-name soar-response-agent \
  --query 'Environment.Variables'
```

### Check WAF Logging Configuration

```bash
WAF_ID=$(aws wafv2 list-web-acls --scope REGIONAL \
  --query 'WebACLs[?Name==`token-api-waf`].Id' --output text)

aws wafv2 get-logging-configuration \
  --resource-arn arn:aws:wafv2:us-east-1:975598471165:regional/webacl/token-api-waf/$WAF_ID \
  --query 'LoggingConfiguration.LogDestinationConfigs'
```

### List S3 Executive Reports

```bash
aws s3 ls s3://chewbacca-s3-975598471165/executive-reports/ --recursive
```

---

## 16. Troubleshooting Guide — Gotchas and Fixes

### Gotcha 1 — Stale S3 Lock (Terraform)

**Symptom:** `Error acquiring the state lock — PreconditionFailed`

**Cause:** A previous `terraform apply` was interrupted mid-run.

**Fix:**
```bash
terraform force-unlock LOCK_ID
# Or delete the lock file:
MSYS_NO_PATHCONV=1 aws s3 rm s3://BUCKET/PATH/statefile.tfstate.tflock
```

---

### Gotcha 2 — Resources Already Exist (409 Conflict)

**Symptom:** `ResourceConflictException: Function already exist` during apply.

**Cause:** Previous interrupted apply created resources not recorded in state.

**Fix:** Import the existing resource into state:
```bash
terraform import aws_lambda_function.waf_bedrock_analyzer waf-bedrock-analyzer
terraform import aws_dynamodb_table.waf_events waf-events
terraform import aws_cloudwatch_log_group.waf_analyzer_logs /aws/lambda/waf-bedrock-analyzer
```

---

### Gotcha 3 — Bedrock Legacy Model

**Symptom:** `ResourceNotFoundException: Access denied. This Model is marked by provider as Legacy`

**Cause:** `anthropic.claude-3-haiku-20240307-v1:0` requires active use. After 30 days
without use, access is revoked.

**Fix:**
```bash
aws lambda update-function-configuration \
  --function-name FUNCTION_NAME \
  --environment "Variables={...,BEDROCK_MODEL_ID=us.anthropic.claude-haiku-4-5-20251001-v1:0}"
```

**Permanent fix:** Make sure all Lambda env vars in `.tf` files use
`us.anthropic.claude-haiku-4-5-20251001-v1:0`.

---

### Gotcha 4 — WAF Analyzer Finds 0 Events

**Symptom:** `events_found: 0` even after generating WAF block events.

**Causes and fixes:**

**Cause A — Wrong WAF_LOG_GROUP:**
```bash
aws lambda get-function-configuration \
  --function-name waf-bedrock-analyzer \
  --query 'Environment.Variables.WAF_LOG_GROUP'
# Must be: "aws-waf-logs-chewbacca"
# If wrong: update manually
aws lambda update-function-configuration \
  --function-name waf-bedrock-analyzer \
  --environment "Variables={WAF_LOG_GROUP=aws-waf-logs-chewbacca,...}"
```

**Cause B — WAF not logging (after destroy/apply):**
```bash
# Check if logging is configured
WAF_ID=$(aws wafv2 list-web-acls --scope REGIONAL \
  --query 'WebACLs[?Name==`token-api-waf`].Id' --output text)

aws wafv2 get-logging-configuration \
  --resource-arn arn:aws:wafv2:us-east-1:975598471165:regional/webacl/token-api-waf/$WAF_ID

# If error: WAF logging not configured — Terraform should handle this
# If wrong log group: terraform apply to fix
```

**Cause C — Didn't wait long enough:**
WAF takes 1-5 minutes to flush logs to CloudWatch. Always `sleep 30` after
generating events before invoking the analyzer.

---

### Gotcha 5 — Correlation Agent Finds 0 Events

**Symptom:** `events_found: 0` from correlation agent.

**Cause:** Records in `waf-events` are missing `event_epoch` field.
These are old Class 7 records written before the field was added.

**Fix:** Generate fresh events and run the analyzer again to write new records
with `event_epoch`. Old records without this field are invisible to the
time-window filter.

---

### Gotcha 6 — DynamoDB Float Type Error

**Symptom:** `Float types are not supported. Use Decimal types instead.`

**Cause:** Python floats cannot be written to DynamoDB directly.

**Fix:** The `native_to_decimal()` function in `waf_threat_correlation_agent.py`
converts all floats to `Decimal`. If you see this error, verify the function
exists and is called before `put_item()`.

---

### Gotcha 7 — Cognito MFA_SETUP After Destroy

**Symptom:** `[ERROR] Logic Error: Unsupported or unexpected Cognito challenge: MFA_SETUP`

**Cause:** After destroy/apply, Cognito user pool is recreated and `cognitouser1`
has no TOTP device enrolled but pool requires MFA.

**Fix:**
```bash
POOL_ID=$(aws cognito-idp list-user-pools --max-results 10 \
  --query 'UserPools[?Name==`cognito_pool`].Id' --output text)

aws cognito-idp set-user-pool-mfa-config \
  --user-pool-id $POOL_ID \
  --mfa-configuration OPTIONAL \
  --software-token-mfa-configuration Enabled=true

aws cognito-idp admin-set-user-password \
  --user-pool-id $POOL_ID \
  --username cognitouser1 \
  --password "BongoBeats1*" \
  --permanent
```

---

### Gotcha 8 — SNS PendingConfirmation

**Symptom:** Tests pass but no email arrives.

**Cause:** After every destroy/apply, AWS sends a new SNS confirmation email.
Until you click "Confirm subscription", SNS silently drops all messages.

**Fix:** Check your Gmail for email from `no-reply@sns.amazonaws.com` and click
"Confirm subscription".

**Verify subscription status:**
```bash
aws sns list-subscriptions-by-topic \
  --topic-arn arn:aws:sns:us-east-1:975598471165:critical-alert \
  --query 'Subscriptions[].SubscriptionArn'
# If shows "PendingConfirmation" — check email and click link
# If shows full ARN — subscription is active
```

---

### Gotcha 9 — API Gateway URL Changes After Destroy

**Symptom:** `curl: (6) Could not resolve host: OLD_ID.execute-api...`

**Cause:** API Gateway gets a new random ID after every destroy/apply.

**Fix:**
```bash
terraform output api_gateway_python_url
# Always use this to get the current URL
# Set as variable:
API_URL=$(terraform output -raw api_gateway_python_url)
```

---

### Gotcha 10 — SOAR Agent Returns workflow_skipped

**Symptom:** `{"message": "Finding is already in status RESPONSE_COMPLETED."}`

**Cause:** The finding was already processed by a previous SOAR agent invocation.
The idempotency check prevents reprocessing.

**Fix Option A — Get a new finding:**
```bash
# Run correlation agent again to create a new finding
aws lambda invoke --function-name waf-threat-correlation-agent response_correlation.json
cat response_correlation.json
# Use the new finding_id
```

**Fix Option B — Reset the test finding:**
```bash
terraform apply
# Terraform resets the test finding (14-test-data.tf) back to OPEN status
```

---

### Gotcha 11 — ReportLab Layer Not Found

**Symptom:** `Runtime.ImportModuleError: Unable to import module 'executive_dashboard_agent': No module named 'reportlab'`

**Cause:** `build/reportlab_layer.zip` doesn't exist or wasn't uploaded as a layer.

**Fix:** Rebuild the layer and redeploy:
```bash
mkdir -p /tmp/reportlab_layer/python/lib/python3.13/site-packages
python -m pip install reportlab==4.4.3 \
  --target /tmp/reportlab_layer/python/lib/python3.13/site-packages \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 3.13 \
  --only-binary=:all: \
  --upgrade
cd /tmp/reportlab_layer
python -m zipfile -c ~/Documents/TheoWAF/class7/armageddon_12ab/build/reportlab_layer.zip python/
cd ~/Documents/TheoWAF/class7/armageddon_12ab
terraform apply
```

---

### Gotcha 12 — Rate Limit Test Returns All 200

**Symptom:** All 150 sequential requests return 200.

**Cause:** Sequential requests are too slow — they spread beyond the 5-minute
rate limit window.

**Fix:** Use parallel requests with `&`:
```bash
for i in {1..150}; do
  curl --ssl-no-revoke -s -o /dev/null -w "%{http_code}\n" \
  -H "Authorization: $TOKEN" \
  "${API_URL}?name=Chewbacca" &
done | tee test3_parallel.txt
wait
```

---

### Gotcha 13 — Rate Limit Test Returns All 403

**Symptom:** All 150 parallel requests return 403 immediately.

**Cause:** Your IP is already rate-limited from a previous test run.

**Fix:** Wait 5 minutes for the rate limit window to expire, then try again.

---

## 17. Destroy and Cost Management

### Destroy Everything

```bash
cd ~/Documents/TheoWAF/class7/armageddon_12ab
terraform destroy 2>&1 | tee destroy_output.txt
# Type 'yes' when prompted
```

**Expected:** `Destroy complete! Resources: 77 destroyed.`

### Cost Estimate While Running

| Service | Estimated Cost |
|---|---|
| WAF Web ACL | ~$5/month |
| Lambda | ~$0 (free tier covers lab scale) |
| API Gateway | ~$0.01/day |
| DynamoDB (on-demand) | ~$0 at lab scale |
| Bedrock (Claude Haiku) | ~$0.001 per analysis |
| EventBridge | ~$0 at lab scale |
| S3 | ~$0 at lab scale |
| CloudWatch Logs | ~$0.50/GB ingested |

**Tip:** Destroy when not actively using to avoid WAF charges.

---

## 18. Push Updates to GitHub

### After making changes to Terraform or code files:

```bash
cd ~/Documents/TheoWAF/class7/armageddon_12ab

# Check what changed
git status
git diff

# Add specific files
git add FILENAME.tf
# Or add everything:
git add .

# Commit with descriptive message
git commit -m "Description of what changed and why"

# Push
git push
```

### Common commit messages:

```bash
git commit -m "Fix WAF_LOG_GROUP env var to point to correct log group"
git commit -m "Add Query and UpdateItem permissions to correlation agent IAM role"
git commit -m "Update Bedrock model ID to active inference profile"
git commit -m "Add test results for lab 12a and 12b deliverables"
```

---

## 19. Key Design Decisions — Why We Did It This Way

### Why separate IAM roles per Lambda?
Least-privilege principle. If `waf-bedrock-analyzer` is compromised, the attacker
can only read CloudWatch logs and write to `waf-events`. They cannot access
`security-incidents`, publish to SNS, or invoke EventBridge. Each Lambda's blast
radius is limited to exactly what it needs.

### Why deterministic risk scoring instead of AI?
Bedrock generates the narrative but NEVER decides the risk score or playbook.
Python code calculates scores using transparent, auditable math. The same inputs
always produce the same output — critical for security systems where you need
to explain decisions to auditors and compliance teams.

### Why EventBridge Rules instead of direct Lambda invocation?
The correlation agent doesn't need to know about the SOAR agent. EventBridge
provides loose coupling — adding a new response (Slack, PagerDuty, JIRA ticket)
only requires a new EventBridge target, not a code change to the correlation agent.

### Why the "doorbell pattern" in SOAR agent?
The EventBridge event contains only `finding_id`. The SOAR Lambda retrieves
the authoritative record from DynamoDB. This prevents attackers from injecting
fake low-severity payloads into EventBridge to bypass security escalation.

### Why `INC-{finding_id}` as incident ID?
EventBridge has at-least-once delivery — it may deliver the same event twice.
The deterministic incident ID plus a conditional `PutItem` prevents duplicate
incidents on retry.

### Why `event_epoch` as integer?
DynamoDB `FilterExpression` requires numeric comparisons for time-window filtering.
ISO timestamp strings cannot be compared mathematically. The integer Unix timestamp
allows `Attr("event_epoch").gte(minimum_epoch)`.

### Why `us.` prefix on Bedrock model IDs?
Newer Anthropic models require cross-region inference profiles. Direct model IDs
without this prefix are LEGACY and become inaccessible after 30 days without use.

### Why the `bool` check before `int` in `native_to_decimal()`?
Python's `bool` is a subclass of `int`. `isinstance(True, int)` returns `True`.
Without the bool check first, `True` becomes `Decimal("True")` which crashes.

---

## 20. Differences from Original Class 7 Lab

| Item | Class 7 Original | ArmageddonLab 12ab | Why Changed |
|---|---|---|---|
| Bedrock model | `anthropic.claude-3-haiku-20240307-v1:0` | `us.anthropic.claude-haiku-4-5-20251001-v1:0` | Original is LEGACY |
| WAF log group | `/aws/waf/chewbacca-waf` | `aws-waf-logs-chewbacca` | AWS requires `aws-waf-logs-` prefix |
| WAF logging | Manual CLI setup | `aws_wafv2_web_acl_logging_configuration` in Terraform | Survives destroy/apply |
| EventBridge | `aws_cloudwatch_event_rule` only | Both Rules + Scheduler | Rules = event-driven, Scheduler = time-based |
| Lambda roles | Single `chewbacca_lambda_role` | Separate role per Lambda | Least privilege |
| `logs:FilterLogEvents` | Scoped to specific ARN | `Resource = "*"` | Specific ARN breaks on config change |
| `save_to_dynamodb` | Outside for loop (bug) | Inside for loop | Only saved last event |
| `call_bedrock` | Outside for loop (bug) | Inside for loop | Only analyzed last event |
| Python groups parsing | `claims.get("cognito:groups", [])` | `.split(",")` | API GW passes groups as string |
| waf_role.json | Had placeholders + comments | Valid JSON with real ARNs | Comments caused MalformedPolicyDocument |
| `event_epoch` field | Missing | Added | Required for time-window correlation |
| `source_ip` field | `client_ip` | `source_ip` | Matches correlation agent expectations |
| Node.js runtime | `nodejs24.x` | `nodejs22.x` | Provider doesn't support 24.x |
| Python runtime | `python3.14` | `python3.13` | Provider doesn't support 3.14 |
| `code_sha256` attribute | Present | Removed | Not valid in this provider version |

---

*ArmageddonLab 12a & 12b — Jorune Simpkins — August 2026*
*Repository: https://github.com/Queuefour97/armageddon_lab12ab*
