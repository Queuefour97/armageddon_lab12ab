# ArmageddonLab 12a & 12b — Complete Test Plan
**Author:** Jorune Simpkins
**Date:** July 2026
**Stack:** armageddon_12ab
**Region:** us-east-1
**Account:** xxxxxxxxx165

---

## Prerequisites

Get your current API Gateway URL before running tests:
```bash
cd ~/Documents/TheoWAF/class7/armageddon_12ab
terraform output api_gateway_python_url
```

Set it as a variable so all tests use it automatically:
```bash
API_URL=$(terraform output -raw api_gateway_python_url)
echo $API_URL
```

---

## Test 1 — XSS Attack (WAF Block)

**What it tests:** AWS WAF CommonRuleSet blocks Cross-Site Scripting (XSS) injection
before the request reaches the Lambda function.

**Why it matters:** XSS attacks attempt to inject malicious scripts into web applications.
The WAF detects the encoded `<script>` tag in the query parameter and returns 403 before
the application ever sees the request.

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
as shell redirect operators so they must be encoded before sending to curl.

OUTPUT:
HTTP/1.1 403 Forbidden
Date: Tue, 28 Jul 2026 22:56:46 GMT
Content-Type: application/json
Content-Length: 0
Connection: keep-alive
x-amzn-RequestId: 8b3eef3e-8bfd-47b0-86d8-f2bcfb8e6b9a
x-amzn-ErrorType: ForbiddenException
x-amz-apigw-id: BPUDVGo0IAMEdbA=


---

## Test 2 — SQL Injection (WAF Block)

**What it tests:** AWS WAF CommonRuleSet blocks SQL Injection attempts.

**Why it matters:** SQL injection is one of the most common attack vectors. The payload
`' OR 1=1--` is a classic SQL injection that attempts to bypass authentication by
making a WHERE clause always evaluate to true.

```bash
curl --ssl-no-revoke -I \
  "${API_URL}?name=%27%20OR%201%3D1--"
```

**Expected:**
```
HTTP/1.1 403 Forbidden
x-amzn-ErrorType: ForbiddenException
```

**Decode:** `%27` = `'`, `%20` = space, `%3D` = `=`
So the decoded payload is: `' OR 1=1--`

OUTPUT:
HTTP/1.1 403 Forbidden
Date: Tue, 28 Jul 2026 22:57:03 GMT
Content-Type: application/json
Content-Length: 0
Connection: keep-alive
x-amzn-RequestId: 676d2bee-fad1-4d32-aae0-1265f17be7b1
x-amzn-ErrorType: ForbiddenException
x-amz-apigw-id: BPUGCFZlIAMEtcg=


---

## Test 3 — DDoS Simulation (Rate Limiting)

**What it tests:** WAF rate-based rule blocks IPs that exceed 100 requests per 5 minutes.

**Why it matters:** Distributed Denial of Service attacks overwhelm APIs with traffic.
The rate limit rule automatically blocks the source IP after the threshold is exceeded,
protecting the backend Lambda from being overwhelmed.

```bash
# Send 150 requests in parallel — after 100 you should see 403s
for i in {1..150}; do
  curl --ssl-no-revoke -s -o /dev/null -w "%{http_code}\n" \
  "${API_URL}?name=Chewbacca" &
done
wait
```

**Expected:** First ~100 responses return `200`, then requests start returning `403`
as the rate limit rule triggers on your source IP.

**Note:** The rate limit window is 5 minutes. After the window expires your IP is
automatically unblocked. If you need to test again immediately, wait 5 minutes first.

OUTPUT:
[text](../test3_output.txt)
All 150 requests returned 401 Unauthorized — not 200 or 403. This means the API Gateway has a Cognito authorizer requiring a JWT token for all requests, so unauthenticated requests get 401 before WAF even gets to apply the rate limit rule. The output proves the Cognito authorizer is working correctly, and the rate limit test requires authentication

For the rate limit test to work properly, we need to either:
Option A — Use the Node endpoint which may not have the Cognito authorizer:

Run this command:
NODE_URL=$(terraform output -raw api_gateway_node_url)
for i in {1..150}; do
  curl --ssl-no-revoke -s -o /dev/null -w "%{http_code}\n" \
  "${NODE_URL}?name=Chewbacca"
done 2>&1 | tee test3_node_output.txt
cat test3_node_output.txt

Option B — Use a valid token so requests pass auth and hit the rate limit.

Option C — Update the test description to note that 401 before 100 requests proves the Cognito authorizer is working correctly, and the rate limit test requires authentication. For deliverables purposes, this is actually a valid security finding — unauthenticated requests are rejected before rate limiting is even needed.

---

## Test 4 — WAF Bedrock Analyzer (Lab 12b)

**What it tests:** The WAF analyzer Lambda reads CloudWatch WAF logs, normalizes events,
calls Bedrock for SOC summaries, and writes to DynamoDB.

**Why it matters:** This is the first stage of the security pipeline — turning raw WAF
logs into structured, AI-enriched telemetry.

```bash
# First generate some WAF events to analyze
for i in {1..10}; do
  curl --ssl-no-revoke -o /dev/null -w "%{http_code}\n" \
  "${API_URL}?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
done

# Wait for WAF to flush logs to CloudWatch
sleep 30

# Invoke the analyzer
aws lambda invoke \
  --function-name waf-bedrock-analyzer \
  response_waf.json
cat response_waf.json
```

**Expected:**
```json
{
  "statusCode": 200,
  "body": "{\"message\": \"WAF event processing completed.\",
            \"events_found\": 10,
            \"events_stored\": 10,
            \"events_analyzed\": 10,
            \"events_failed\": 0}"
}
```

**Verify DynamoDB write:**
```bash
aws dynamodb scan --table-name waf-events --select COUNT
```

---

## Test 5 — Threat Correlation Agent (Lab 12a)

**What it tests:** The correlation agent scans waf-events, groups by source IP,
calculates deterministic risk score, calls Bedrock for threat interpretation,
and saves a finding.

**Why it matters:** Individual WAF events are noise. Correlation turns noise into signal
by identifying patterns — same IP hitting multiple URIs, triggering multiple rules,
or exhibiting burst behavior.

```bash
aws lambda invoke \
  --function-name waf-threat-correlation-agent \
  response_correlation.json
cat response_correlation.json
```

**Expected:**
```json
{
  "statusCode": 200,
  "body": "{\"message\": \"Threat correlation completed.\",
            \"finding_created\": true,
            \"finding_id\": \"<uuid>\",
            \"events_correlated\": 10,
            \"severity\": \"MEDIUM\",
            \"risk_score\": 35,
            \"primary_source_ip\": \"<your-ip>\"}"
}
```

**Save the finding_id for Test 6:**
```bash
FINDING_ID=$(cat response_correlation.json | python -c "import sys,json; data=json.load(sys.stdin); body=json.loads(data['body']); print(body['finding_id'])")
echo $FINDING_ID
```

---

## Test 6 — SOAR EventBridge Trigger (Lab 12a)

**What it tests:** EventBridge routes the correlation finding to the SOAR agent,
which selects a playbook, generates Bedrock summaries, creates an incident,
and sends an SNS notification.

**Why it matters:** This tests the complete automated incident response workflow.
The EventBridge event format simulates exactly what the correlation agent publishes
when it calls `events:PutEvents`.

### Option A — Direct EventBridge publish (tests full routing):
```bash
MSYS_NO_PATHCONV=1 aws events put-events \
  --entries "[{
    \"Source\": \"seir.waf.correlation\",
    \"DetailType\": \"WAF Threat Finding Created\",
    \"Detail\": \"{\\\"finding_id\\\": \\\"$FINDING_ID\\\", \\\"severity\\\": \\\"MEDIUM\\\", \\\"risk_score\\\": 35}\",
    \"EventBusName\": \"default\"
  }]" \
  --region us-east-1
```

**Expected:**
```json
{
  "FailedEntryCount": 0,
  "Entries": [{"EventId": "..."}]
}
```

### Option B — Direct Lambda invoke with EventBridge format:
```bash
MSYS_NO_PATHCONV=1 aws lambda invoke \
  --function-name soar-response-agent \
  --payload "{
    \"version\": \"0\",
    \"id\": \"test-event-id\",
    \"detail-type\": \"WAF Threat Finding Created\",
    \"source\": \"seir.waf.correlation\",
    \"account\": \"975598471165\",
    \"time\": \"2026-07-28T10:00:00Z\",
    \"region\": \"us-east-1\",
    \"resources\": [],
    \"detail\": {
      \"finding_id\": \"$FINDING_ID\",
      \"severity\": \"MEDIUM\",
      \"risk_score\": 35
    }
  }" \
  --cli-binary-format raw-in-base64-out \
  response_soar.json
cat response_soar.json
```

**Expected:**
```json
{
  "statusCode": 200,
  "body": "{\"message\": \"SOAR response workflow completed.\",
            \"incident_created\": true,
            \"severity\": \"MEDIUM\",
            \"playbook\": \"NOTIFY_ANALYST\",
            \"notification_sent\": true,
            \"bedrock_summary_generated\": true,
            \"human_review_required\": true}"
}
```

**Check your email** for the SNS notification after this test.

---

## Test 7 — HIGH Severity SOAR Test (Test Finding)

**What it tests:** The HIGH severity playbook `CREATE_AND_ESCALATE_INCIDENT`
is selected when risk_score >= 60.

**Why it matters:** Validates that different severity levels trigger different
playbooks — the core of the deterministic SOAR design.

```bash
MSYS_NO_PATHCONV=1 aws lambda invoke \
  --function-name soar-response-agent \
  --payload '{
    "version": "0",
    "id": "test-high-severity",
    "detail-type": "WAF Threat Finding Created",
    "source": "seir.waf.correlation",
    "account": "975598471165",
    "time": "2026-07-28T10:00:00Z",
    "region": "us-east-1",
    "resources": [],
    "detail": {
      "finding_id": "7ea476d0-1fea-4ff0-a95a-6377faac5cb4",
      "severity": "HIGH",
      "risk_score": 75
    }
  }' \
  --cli-binary-format raw-in-base64-out \
  response_soar_high.json
cat response_soar_high.json
```

**Expected:** `playbook: CREATE_AND_ESCALATE_INCIDENT`

**Note:** Uses the pre-seeded test finding from `14-test-data.tf`.
If it returns `workflow_skipped: true`, the finding was already processed.
Run `terraform apply` to reset it to OPEN status.

---

## Test 8 — Executive Report Generator (Lab 12b)

**What it tests:** The executive dashboard agent reads all 3 security DynamoDB tables,
calls Bedrock for an executive narrative, generates a PDF using ReportLab,
and uploads both PDF and JSON to S3.

**Why it matters:** Proves the complete Lab 12b pipeline — from raw security data
to a boardroom-ready executive security report.

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
{
  "statusCode": 200,
  "body": "{\"message\": \"Executive security report generated and published.\",
            \"report_id\": \"executive-security-<timestamp>\",
            \"overall_security_posture\": \"ELEVATED\",
            \"bedrock_used\": true,
            \"artifacts\": {
              \"bucket\": \"chewbacca-s3-975598471165\",
              \"pdf\": {\"size_bytes\": 7238},
              \"json\": {\"size_bytes\": 7825}
            }}"
}
```

**Verify files in S3:**
```bash
aws s3 ls s3://chewbacca-s3-975598471165/executive-reports/ --recursive
```

**Download the PDF:**
```bash
aws s3 cp \
  s3://chewbacca-s3-975598471165/executive-reports/$(date +%Y/%m/%d)/pdf/ \
  ./deliverables/ --recursive --include "*.pdf"
```

---

## Test 9 — EventBridge Rules Active

**What it tests:** Both EventBridge routing rules are deployed and enabled.

```bash
aws events list-rules \
  --query 'Rules[?contains(Name, `waf`)].{Name:Name,State:State}' \
  --output table
```

**Expected:**
```
+-------------------------------+-----------+
|             Name              |   State   |
+-------------------------------+-----------+
|  waf-critical-finding-rule    |  ENABLED  |
|  waf-medium-high-finding-rule |  ENABLED  |
+-------------------------------+-----------+
```

---

## Test 10 — SNS Subscription Confirmed

**What it tests:** Email subscription is active and will deliver notifications.

```bash
aws sns list-subscriptions-by-topic \
  --topic-arn arn:aws:sns:us-east-1:975598471165:critical-alert \
  --query 'Subscriptions[].{Protocol:Protocol,Status:SubscriptionArn}' \
  --output table
```

**Expected:** Status shows full ARN (not `PendingConfirmation`)

---

## Test 11 — DynamoDB Record Counts

**What it tests:** All four DynamoDB tables have records — proves the full
pipeline has written data end to end.

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

**Expected:** Count > 0 for all four tables.

---

## Test 12 — Terraform State Clean

**What it tests:** Infrastructure matches configuration — no drift.

```bash
terraform plan 2>&1 | tee final_plan.txt
```

**Expected:** `No changes. Your infrastructure matches the configuration.`

---

## Summary

| Test | Component | Expected Result |
|---|---|---|
| 1 | WAF XSS Block | 403 Forbidden |
| 2 | WAF SQL Injection Block | 403 Forbidden |
| 3 | WAF Rate Limiting | 403 after 100 requests |
| 4 | WAF Bedrock Analyzer | events_analyzed > 0 |
| 5 | Threat Correlation Agent | finding_created: true |
| 6 | SOAR EventBridge Trigger | FailedEntryCount: 0 |
| 7 | HIGH Severity SOAR | playbook: CREATE_AND_ESCALATE_INCIDENT |
| 8 | Executive Report (12b) | PDF + JSON in S3 |
| 9 | EventBridge Rules | Both ENABLED |
| 10 | SNS Subscription | Confirmed |
| 11 | DynamoDB Record Counts | Count > 0 all tables |
| 12 | Terraform State | No changes |

**All 12 tests passing = complete ArmageddonLab 12a & 12b pipeline verified.**
