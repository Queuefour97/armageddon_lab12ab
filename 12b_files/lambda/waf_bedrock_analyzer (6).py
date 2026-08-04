import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError


# ============================================================
# AWS clients
# ============================================================

logs_client = boto3.client("logs")
bedrock_client = boto3.client("bedrock-runtime")
dynamodb = boto3.resource("dynamodb")


# ============================================================
# Environment variables
# ============================================================

WAF_LOG_GROUP = os.environ["WAF_LOG_GROUP"]
DYNAMODB_TABLE = os.environ["DYNAMODB_TABLE"]

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "anthropic.claude-3-haiku-20240307-v1:0",
)

LOOKBACK_MINUTES = int(os.environ.get("LOOKBACK_MINUTES", "10"))
MAX_LOG_EVENTS = int(os.environ.get("MAX_LOG_EVENTS", "25"))

waf_events_table = dynamodb.Table(DYNAMODB_TABLE)


# ============================================================
# CloudWatch log retrieval
# ============================================================

def get_recent_waf_events() -> list[dict[str, Any]]:
    """Read recent WAF JSON records from the configured log group."""

    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=LOOKBACK_MINUTES)

    start_time_ms = int(start.timestamp() * 1000)
    end_time_ms = int(now.timestamp() * 1000)

    print(
        f"Reading WAF logs from {WAF_LOG_GROUP} "
        f"for the previous {LOOKBACK_MINUTES} minute(s)."
    )

    response = logs_client.filter_log_events(
        logGroupName=WAF_LOG_GROUP,
        startTime=start_time_ms,
        endTime=end_time_ms,
        limit=MAX_LOG_EVENTS,
    )

    waf_events: list[dict[str, Any]] = []

    for cloudwatch_event in response.get("events", []):
        message = cloudwatch_event.get("message")

        if not message:
            print("Skipping CloudWatch event with no message.")
            continue

        try:
            waf_event = json.loads(message)
        except json.JSONDecodeError:
            print("Skipping non-JSON CloudWatch log entry.")
            continue

        if "httpRequest" not in waf_event:
            print("Skipping record that does not contain httpRequest.")
            continue

        # Preserve CloudWatch metadata for deterministic event IDs.
        waf_event["_cloudwatch_event_id"] = cloudwatch_event.get("eventId")
        waf_event["_cloudwatch_timestamp"] = cloudwatch_event.get("timestamp")

        waf_events.append(waf_event)

    print(f"Retrieved {len(waf_events)} valid WAF event(s).")

    return waf_events


# ============================================================
# Event normalization
# ============================================================

def convert_waf_timestamp(timestamp_ms: Any) -> str:
    """Convert the WAF millisecond timestamp to ISO-8601 UTC."""

    try:
        timestamp_seconds = int(timestamp_ms) / 1000

        return datetime.fromtimestamp(
            timestamp_seconds,
            tz=timezone.utc,
        ).isoformat()

    except (TypeError, ValueError, OSError):
        return datetime.now(timezone.utc).isoformat()


def create_event_id(waf_event: dict[str, Any]) -> str:
    """
    Create a repeatable event ID.

    Using a deterministic ID prevents the same CloudWatch record from
    being stored repeatedly when scheduled lookback windows overlap.
    """

    cloudwatch_event_id = waf_event.get("_cloudwatch_event_id")

    if cloudwatch_event_id:
        return str(cloudwatch_event_id)

    event_material = json.dumps(
        {
            "timestamp": waf_event.get("timestamp"),
            "action": waf_event.get("action"),
            "terminatingRuleId": waf_event.get("terminatingRuleId"),
            "httpRequest": waf_event.get("httpRequest"),
        },
        sort_keys=True,
        default=str,
    )

    return hashlib.sha256(event_material.encode("utf-8")).hexdigest()


def summarize_waf_event(
    waf_event: dict[str, Any],
) -> dict[str, Any]:
    """Normalize a raw WAF event into a smaller security record."""

    http_request = waf_event.get("httpRequest", {})

    timestamp_ms = waf_event.get(
        "timestamp",
        waf_event.get("_cloudwatch_timestamp"),
    )

    timestamp_iso = convert_waf_timestamp(timestamp_ms)
    event_epoch = int(
        datetime.fromisoformat(timestamp_iso).timestamp()
    )

    return {
        "event_id": create_event_id(waf_event),
        "timestamp": timestamp_iso,
        "event_epoch": event_epoch,
        "action": waf_event.get("action", "UNKNOWN"),
        "terminating_rule_id": waf_event.get(
            "terminatingRuleId",
            "UNKNOWN",
        ),
        "terminating_rule_type": waf_event.get(
            "terminatingRuleType",
            "UNKNOWN",
        ),
        "web_acl_id": waf_event.get("webaclId", "UNKNOWN"),
        "client_ip": http_request.get("clientIp", "UNKNOWN"),
        "country": http_request.get("country", "UNKNOWN"),
        "method": http_request.get("httpMethod", "UNKNOWN"),
        "uri": http_request.get("uri", "UNKNOWN"),
        "args": http_request.get("args", ""),
        "headers": http_request.get("headers", [])[:10],
    }


# ============================================================
# DynamoDB persistence
# ============================================================

def save_to_dynamodb(
    waf_summary: dict[str, Any],
) -> bool:
    """Store the normalized WAF event without overwriting duplicates."""

    event_id = waf_summary["event_id"]

    item = {
        "event_id": event_id,
        "timestamp": waf_summary["timestamp"],
        "event_epoch": waf_summary["event_epoch"],
        "source_ip": waf_summary["client_ip"],
        "country": waf_summary["country"],
        "uri": waf_summary["uri"],
        "method": waf_summary["method"],
        "args": waf_summary["args"],
        "action": waf_summary["action"],
        "rule": waf_summary["terminating_rule_id"],
        "rule_type": waf_summary["terminating_rule_type"],
        "web_acl_id": waf_summary["web_acl_id"],
    }

    print(
        f"Saving WAF event {event_id} "
        f"for source IP {waf_summary['client_ip']}."
    )

    try:
        waf_events_table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(event_id)",
        )

        print("Successfully saved event to DynamoDB.")
        return True

    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")

        if error_code == "ConditionalCheckFailedException":
            print(
                f"Event {event_id} already exists. "
                "Skipping duplicate record."
            )
            return False

        raise


# ============================================================
# Bedrock analysis
# ============================================================

def call_bedrock(
    waf_summary: dict[str, Any],
) -> str:
    """Ask Bedrock to create a concise SOC incident summary."""

    prompt = f"""
You are a SOC analyst assistant.

Analyze the following normalized AWS WAF security event.

Event:
{json.dumps(waf_summary, indent=2, default=str)}

Return the response using exactly these headings:

Severity:
Possible Attack Type:
Why This Was Flagged:
Recommended Analyst Actions:
Short Executive Summary:

Requirements:
- Base your answer only on the supplied event.
- Do not claim that an exploit succeeded.
- Clearly distinguish observed facts from possible explanations.
- Keep the response concise and practical.
""".strip()

    request_body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 500,
        "temperature": 0.2,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": prompt,
                    }
                ],
            }
        ],
    }

    print(
        f"Invoking Bedrock model {BEDROCK_MODEL_ID} "
        f"for event {waf_summary['event_id']}."
    )

    response = bedrock_client.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=json.dumps(request_body),
    )

    response_body = json.loads(response["body"].read())

    content = response_body.get("content", [])

    if not content:
        raise ValueError(
            "Bedrock returned no content in the response."
        )

    summary_text = content[0].get("text")

    if not summary_text:
        raise ValueError(
            "Bedrock response did not contain summary text."
        )

    print("Bedrock invocation successful.")

    return summary_text


# ============================================================
# Lambda handler
# ============================================================

def lambda_handler(
    event: dict[str, Any],
    context: Any,
) -> dict[str, Any]:
    """Process recent WAF events."""

    print("=" * 60)
    print("Starting WAF Bedrock Analyzer")
    print("=" * 60)

    try:
        waf_events = get_recent_waf_events()

    except (ClientError, BotoCoreError) as error:
        print(f"CloudWatch Logs error: {error}")

        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "message": "Unable to read WAF logs.",
                    "error": str(error),
                }
            ),
        }

    if not waf_events:
        print("No recent WAF events found.")

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "No recent WAF events found.",
                    "events_found": 0,
                    "events_stored": 0,
                    "events_analyzed": 0,
                }
            ),
        }

    stored_count = 0
    analyzed_count = 0
    failed_count = 0

    for waf_event in waf_events:
        try:
            waf_summary = summarize_waf_event(waf_event)

            print("\nStructured WAF Event:")
            print(
                json.dumps(
                    waf_summary,
                    indent=2,
                    default=str,
                )
            )

            was_stored = save_to_dynamodb(waf_summary)

            if was_stored:
                stored_count += 1

            ai_summary = call_bedrock(waf_summary)
            analyzed_count += 1

            print("\n===== BEDROCK SOC SUMMARY =====")
            print(ai_summary)
            print("================================\n")

        except (ClientError, BotoCoreError) as error:
            failed_count += 1
            print(f"AWS service error: {error}")

        except Exception as error:
            failed_count += 1
            print(
                f"Unexpected error while processing WAF event: "
                f"{type(error).__name__}: {error}"
            )

    result = {
        "message": "WAF event processing completed.",
        "events_found": len(waf_events),
        "events_stored": stored_count,
        "events_analyzed": analyzed_count,
        "events_failed": failed_count,
    }

    print("Processing result:")
    print(json.dumps(result, indent=2))

    return {
        "statusCode": 200 if failed_count == 0 else 207,
        "body": json.dumps(result),
    }
