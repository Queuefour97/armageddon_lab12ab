import json
import os
from datetime import datetime, timedelta, timezone

import boto3

#
####### SOAR + Bedrock — AI Incident Summary Generator ########
#
# Original flow:
#   Scan token-tracking → find unused tokens → print ALERT
#
# New SOAR flow:
#   Scan token-tracking → find unused tokens → build Bedrock prompt
#   → AI generates incident summary → print enriched alert to CloudWatch
#
# "AI is not making security decisions. AI is assisting analysts
#  with interpretation." — Theo
#
# Service map:
#   Cognito     → identity source
#   DynamoDB    → telemetry state (token-tracking table)
#   EventBridge → orchestration (triggers this Lambda every 5 min)
#   Lambda      → automation engine (this file)
#   Bedrock     → AI enrichment (SOC-style incident summary)
#   CloudWatch  → alert output

dynamodb = boto3.resource("dynamodb")
bedrock  = boto3.client("bedrock-runtime")

TABLE_NAME    = os.environ.get("TABLE_NAME", "token-tracking")
STALE_MINUTES = int(os.environ.get("STALE_MINUTES", "10"))
MODEL_ID      = os.environ.get(
    "BEDROCK_MODEL_ID",
    "anthropic.claude-3-haiku-20240307-v1:0"
)


def get_stale_tokens():
    """Scan token-tracking for unused tokens older than STALE_MINUTES."""
    table    = dynamodb.Table(TABLE_NAME)
    response = table.scan()
    stale    = []

    for item in response["Items"]:
        if item.get("used") is False:
            raw    = item["issued_at"].replace("Z", "+00:00")
            issued = datetime.fromisoformat(raw)
            if issued.tzinfo is None:
                issued = issued.replace(tzinfo=timezone.utc)
            age = datetime.now(timezone.utc) - issued
            if age > timedelta(minutes=STALE_MINUTES):
                item["age_minutes"] = int(age.total_seconds() // 60)
                stale.append(item)

    return stale


def call_bedrock(token_item):
    """
    Send stale token details to Bedrock for AI-generated SOC summary.
    Returns the AI analysis text.
    """
    username   = token_item.get("username", "unknown")
    issued_at  = token_item.get("issued_at", "unknown")
    age        = token_item.get("age_minutes", STALE_MINUTES)
    group      = token_item.get("group", "unknown")

    prompt = f"""
You are a SOC analyst assistant.

Analyze this security event:

- User: {username}
- User group: {group}
- JWT token issued at: {issued_at}
- Token was never used within {age} minutes
- This was detected by an automated SOAR workflow

Provide:
1. Severity
2. Possible explanations
3. Recommended analyst actions
4. Short executive summary

Keep the response concise and practical.
"""

    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 400,
        "temperature": 0.2,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ]
    }

    print(f"Invoking Bedrock for user {username}...")
    response      = bedrock.invoke_model(
        modelId=MODEL_ID,
        body=json.dumps(body)
    )
    response_body = json.loads(response["body"].read())
    return response_body["content"][0]["text"]


def lambda_handler(event, context):
    print("Starting SOAR unused token detector with Bedrock enrichment")

    stale_tokens = get_stale_tokens()

    if not stale_tokens:
        print("No stale tokens found")
        return {
            "statusCode": 200,
            "alerts_fired": 0,
            "alerts": []
        }

    alerts = []

    for token in stale_tokens:
        username = token.get("username", "unknown")
        age      = token.get("age_minutes", STALE_MINUTES)

        # Phase 6 — base alert (same as before)
        msg = f"ALERT: Token unused for user {username}"
        print(msg)

        # SOAR enrichment — send to Bedrock for AI incident summary
        try:
            ai_summary = call_bedrock(token)

            print("\n===== BEDROCK SOAR INCIDENT SUMMARY =====")
            print(f"User:        {username}")
            print(f"Token age:   {age} minutes")
            print(f"Issued at:   {token.get('issued_at')}")
            print("------------------------------------------")
            print(ai_summary)
            print("==========================================\n")

        except Exception as e:
            print(f"Bedrock error for user {username}: {e}")
            ai_summary = "Bedrock enrichment unavailable"

        alerts.append({
            "username":   username,
            "issued_at":  token.get("issued_at"),
            "age_minutes": age,
            "alert":      msg,
            "ai_summary": ai_summary
        })

    print(f"Total stale tokens detected: {len(alerts)}")

    return {
        "statusCode":  200,
        "alerts_fired": len(alerts),
        "alerts":      alerts
    }
