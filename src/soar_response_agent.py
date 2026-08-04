#!/usr/bin/env python3

import json
import os
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError


# ============================================================
# AWS clients
# ============================================================

dynamodb = boto3.resource("dynamodb")
bedrock_client = boto3.client("bedrock-runtime")
sns_client = boto3.client("sns")


# ============================================================
# Environment variables
# ============================================================

CORRELATION_FINDINGS_TABLE = os.environ[
    "CORRELATION_FINDINGS_TABLE"
]

SECURITY_INCIDENTS_TABLE = os.environ[
    "SECURITY_INCIDENTS_TABLE"
]

SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID",
    "anthropic.claude-3-haiku-20240307-v1:0",
)

ENABLE_BEDROCK = (
    os.environ.get("ENABLE_BEDROCK", "true").lower()
    == "true"
)

findings_table = dynamodb.Table(
    CORRELATION_FINDINGS_TABLE
)

incidents_table = dynamodb.Table(
    SECURITY_INCIDENTS_TABLE
)


# ============================================================
# Playbooks
# ============================================================

PLAYBOOKS = {
    "LOW": {
        "name": "RECORD_ONLY",
        "notify": False,
        "create_incident": True,
        "priority": 4,
        "description": (
            "Record the finding for historical analysis. "
            "No immediate analyst notification is required."
        ),
    },
    "MEDIUM": {
        "name": "NOTIFY_ANALYST",
        "notify": True,
        "create_incident": True,
        "priority": 3,
        "description": (
            "Create an incident and notify the security "
            "operations team for review."
        ),
    },
    "HIGH": {
        "name": "CREATE_AND_ESCALATE_INCIDENT",
        "notify": True,
        "create_incident": True,
        "priority": 2,
        "description": (
            "Create a high-priority incident and escalate "
            "the finding to the security operations team."
        ),
    },
    "CRITICAL": {
        "name": "REQUEST_URGENT_REVIEW",
        "notify": True,
        "create_incident": True,
        "priority": 1,
        "description": (
            "Create a critical incident and request urgent "
            "human review. No containment action is performed."
        ),
    },
}


# ============================================================
# General helpers
# ============================================================

def utc_now() -> str:
    """Return the current UTC time in ISO-8601 format."""

    return datetime.now(timezone.utc).isoformat()


def decimal_to_native(value: Any) -> Any:
    """Convert DynamoDB Decimal values to Python numbers."""

    if isinstance(value, list):
        return [
            decimal_to_native(item)
            for item in value
        ]

    if isinstance(value, dict):
        return {
            key: decimal_to_native(item)
            for key, item in value.items()
        }

    if isinstance(value, Decimal):
        if value % 1 == 0:
            return int(value)

        return float(value)

    return value


def normalize_severity(value: Any) -> str:
    """Validate and normalize a severity value."""

    severity = str(value or "LOW").upper()

    if severity not in PLAYBOOKS:
        print(
            f"Unknown severity '{severity}'. "
            "Defaulting to LOW."
        )

        return "LOW"

    return severity


# ============================================================
# EventBridge event parsing
# ============================================================

def extract_finding_id(
    event: dict[str, Any],
) -> str:
    """
    Extract the finding ID from an EventBridge event.

    Expected EventBridge structure:

    {
        "source": "seir.waf.correlation",
        "detail-type": "WAF Threat Finding Created",
        "detail": {
            "finding_id": "..."
        }
    }

    Direct Lambda tests may provide finding_id at the top level.
    """

    detail = event.get("detail", {})

    finding_id = (
        detail.get("finding_id")
        or event.get("finding_id")
    )

    if not finding_id:
        raise ValueError(
            "The event does not contain finding_id."
        )

    return str(finding_id)


# ============================================================
# Finding retrieval and validation
# ============================================================

def get_finding(
    finding_id: str,
) -> dict[str, Any]:
    """Retrieve the complete correlation finding."""

    print(f"Retrieving finding {finding_id}.")

    response = findings_table.get_item(
        Key={
            "finding_id": finding_id,
        },
        ConsistentRead=True,
    )

    finding = response.get("Item")

    if not finding:
        raise ValueError(
            f"Finding {finding_id} does not exist."
        )

    return decimal_to_native(finding)


def validate_finding(
    finding: dict[str, Any],
) -> None:
    """Validate that the finding can enter the SOAR workflow."""

    required_fields = [
        "finding_id",
        "severity",
        "created_at",
        "bedrock_report",
    ]

    missing_fields = [
        field
        for field in required_fields
        if not finding.get(field)
    ]

    if missing_fields:
        raise ValueError(
            "Finding is missing required fields: "
            + ", ".join(missing_fields)
        )

    current_status = str(
        finding.get("status", "OPEN")
    ).upper()

    completed_statuses = {
        "RESPONSE_COMPLETED",
        "ESCALATED",
        "CLOSED",
        "RESOLVED",
    }

    if current_status in completed_statuses:
        raise AlreadyProcessedError(
            f"Finding is already in status "
            f"{current_status}."
        )


class AlreadyProcessedError(Exception):
    """Raised when a finding has already been processed."""


# ============================================================
# Playbook selection
# ============================================================

def select_playbook(
    finding: dict[str, Any],
) -> dict[str, Any]:
    """
    Select a response playbook deterministically.

    Bedrock does not select the playbook.
    """

    severity = normalize_severity(
        finding.get("severity")
    )

    playbook = {
        **PLAYBOOKS[severity],
        "severity": severity,
    }

    print(
        f"Selected playbook {playbook['name']} "
        f"for severity {severity}."
    )

    return playbook


# ============================================================
# Bedrock informational enrichment
# ============================================================

def build_finding_context(
    finding: dict[str, Any],
    playbook: dict[str, Any],
) -> dict[str, Any]:
    """Create a compact context object for Bedrock."""

    evidence = finding.get("evidence", {})

    return {
        "finding_id": finding.get("finding_id"),
        "created_at": finding.get("created_at"),
        "severity": playbook["severity"],
        "risk_score": finding.get("risk_score"),
        "primary_source_ip": finding.get(
            "primary_source_ip"
        ),
        "primary_target": finding.get(
            "primary_target"
        ),
        "event_count": finding.get(
            "event_count"
        ),
        "correlation_report": finding.get(
            "bedrock_report"
        ),
        "deterministic_findings": evidence.get(
            "deterministic_findings",
            [],
        ),
        "selected_playbook": {
            "name": playbook["name"],
            "description": playbook[
                "description"
            ],
        },
    }


def call_bedrock(
    finding_context: dict[str, Any],
) -> dict[str, Any]:
    """
    Generate informational response material.

    Bedrock explains and formats the response.
    It does not authorize or perform containment.
    """

    prompt = f"""
You are assisting a Security Operations Center.

A deterministic SOAR workflow has already selected the response
playbook. You must not change the severity, risk score, evidence,
or selected playbook.

Threat finding:
{json.dumps(finding_context, indent=2, default=str)}

Create a response using exactly these headings:

Incident Title:
SOC Alert:
Manager Summary:
Analyst Investigation Checklist:
Why This Playbook Was Selected:
Limitations and Unknowns:

Requirements:
- Base the response only on the supplied evidence.
- Separate observed facts from possible interpretations.
- Do not claim that an exploit succeeded.
- Do not claim that the source IP is malicious unless the evidence
  explicitly proves that.
- Do not recommend automatic IP blocking, account disabling,
  credential revocation, or destructive containment.
- State clearly that a human analyst must review the finding.
- Keep the output concise and operationally useful.
""".strip()

    request_body = {
        "anthropic_version": (
            "bedrock-2023-05-31"
        ),
        "max_tokens": 900,
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
        f"Invoking Bedrock model "
        f"{BEDROCK_MODEL_ID}."
    )

    response = bedrock_client.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=json.dumps(request_body),
    )

    response_body = json.loads(
        response["body"].read()
    )

    content = response_body.get("content", [])

    if not content:
        raise ValueError(
            "Bedrock returned no response content."
        )

    response_text = content[0].get("text")

    if not response_text:
        raise ValueError(
            "Bedrock response contained no text."
        )

    print("Bedrock SOAR summary generated.")

    return {
        "generated": True,
        "model_id": BEDROCK_MODEL_ID,
        "text": response_text,
    }


def create_fallback_summary(
    finding_context: dict[str, Any],
) -> dict[str, Any]:
    """
    Create a deterministic fallback if Bedrock is disabled
    or unavailable.
    """

    severity = finding_context["severity"]
    finding_id = finding_context["finding_id"]
    source_ip = (
        finding_context.get("primary_source_ip")
        or "unknown"
    )
    target = (
        finding_context.get("primary_target")
        or "unknown"
    )
    event_count = (
        finding_context.get("event_count")
        or 0
    )
    playbook = finding_context[
        "selected_playbook"
    ]["name"]

    text = f"""
Incident Title:
{severity} WAF Threat Finding {finding_id}

SOC Alert:
The threat-correlation workflow identified {event_count} related
WAF event(s). The primary observed source IP was {source_ip}, and
the primary target was {target}.

Manager Summary:
A {severity.lower()}-severity correlation finding requires review
under playbook {playbook}.

Analyst Investigation Checklist:
1. Review the correlated WAF events.
2. Confirm the source IP and targeted resources.
3. Review API Gateway and application logs.
4. Check related authentication activity.
5. Document analyst conclusions.

Why This Playbook Was Selected:
The deterministic workflow selected {playbook} based on the
stored severity.

Limitations and Unknowns:
This summary does not prove successful exploitation. Human review
is required.
""".strip()

    return {
        "generated": False,
        "model_id": None,
        "text": text,
    }


# ============================================================
# Incident creation
# ============================================================

def build_incident_id(
    finding_id: str,
) -> str:
    """
    Build a deterministic incident ID.

    This helps prevent duplicate incidents when EventBridge
    retries delivery.
    """

    return f"INC-{finding_id}"


def create_incident(
    finding: dict[str, Any],
    playbook: dict[str, Any],
    response_summary: dict[str, Any],
) -> tuple[str, bool]:
    """
    Create the incident record.

    Returns:
        incident_id
        True if newly created, False if already present
    """

    finding_id = finding["finding_id"]
    incident_id = build_incident_id(finding_id)
    now = utc_now()

    incident = {
        "incident_id": incident_id,
        "finding_id": finding_id,
        "created_at": now,
        "updated_at": now,
        "severity": playbook["severity"],
        "priority": playbook["priority"],
        "status": "OPEN",
        "assigned_team": "SOC",
        "playbook": playbook["name"],
        "playbook_description": playbook[
            "description"
        ],
        "primary_source_ip": finding.get(
            "primary_source_ip",
            "UNKNOWN",
        ),
        "primary_target": finding.get(
            "primary_target",
            "UNKNOWN",
        ),
        "event_count": finding.get(
            "event_count",
            0,
        ),
        "risk_score": finding.get(
            "risk_score",
            0,
        ),
        "analyst_summary": response_summary[
            "text"
        ],
        "bedrock_summary_generated": (
            response_summary["generated"]
        ),
        "bedrock_model_id": (
            response_summary["model_id"]
            or "NONE"
        ),
        "containment_performed": False,
        "human_review_required": True,
    }

    try:
        incidents_table.put_item(
            Item=incident,
            ConditionExpression=(
                "attribute_not_exists(incident_id)"
            ),
        )

        print(
            f"Created security incident "
            f"{incident_id}."
        )

        return incident_id, True

    except ClientError as error:
        error_code = error.response.get(
            "Error",
            {},
        ).get("Code")

        if (
            error_code
            == "ConditionalCheckFailedException"
        ):
            print(
                f"Incident {incident_id} already "
                "exists. Reusing existing incident."
            )

            return incident_id, False

        raise


# ============================================================
# SNS notification
# ============================================================

def publish_notification(
    finding: dict[str, Any],
    incident_id: str,
    playbook: dict[str, Any],
    response_summary: dict[str, Any],
) -> str | None:
    """Publish an informational SOC notification."""

    if not playbook["notify"]:
        print(
            f"Playbook {playbook['name']} does "
            "not require an SNS notification."
        )

        return None

    severity = playbook["severity"]

    subject = (
        f"[{severity}] WAF Security Incident "
        f"{incident_id}"
    )

    message = {
        "incident_id": incident_id,
        "finding_id": finding["finding_id"],
        "severity": severity,
        "risk_score": finding.get(
            "risk_score"
        ),
        "playbook": playbook["name"],
        "source_ip": finding.get(
            "primary_source_ip"
        ),
        "target": finding.get(
            "primary_target"
        ),
        "event_count": finding.get(
            "event_count"
        ),
        "human_review_required": True,
        "containment_performed": False,
        "analyst_summary": response_summary[
            "text"
        ],
    }

    response = sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject[:100],
        Message=json.dumps(
            message,
            indent=2,
            default=str,
        ),
        MessageAttributes={
            "severity": {
                "DataType": "String",
                "StringValue": severity,
            },
            "playbook": {
                "DataType": "String",
                "StringValue": playbook[
                    "name"
                ],
            },
        },
    )

    message_id = response.get("MessageId")

    print(
        f"Published SNS notification "
        f"{message_id}."
    )

    return message_id


# ============================================================
# Finding workflow update
# ============================================================

def update_finding_status(
    finding_id: str,
    incident_id: str,
    playbook: dict[str, Any],
    sns_message_id: str | None,
) -> None:
    """Mark the finding as processed by the SOAR workflow."""

    now = utc_now()

    expression_values = {
        ":response_status": (
            "RESPONSE_COMPLETED"
        ),
        ":incident_id": incident_id,
        ":playbook": playbook["name"],
        ":processed_at": now,
        ":sns_message_id": (
            sns_message_id or "NOT_SENT"
        ),
        ":open_status": "OPEN",
    }

    findings_table.update_item(
        Key={
            "finding_id": finding_id,
        },
        UpdateExpression=(
            "SET #status = :response_status, "
            "incident_id = :incident_id, "
            "response_playbook = :playbook, "
            "response_processed_at = :processed_at, "
            "sns_message_id = :sns_message_id"
        ),
        ConditionExpression=(
            "attribute_not_exists(#status) "
            "OR #status = :open_status"
        ),
        ExpressionAttributeNames={
            "#status": "status",
        },
        ExpressionAttributeValues=(
            expression_values
        ),
    )

    print(
        f"Updated finding {finding_id} to "
        "RESPONSE_COMPLETED."
    )


# ============================================================
# Lambda handler
# ============================================================

def lambda_handler(
    event: dict[str, Any],
    context: Any,
) -> dict[str, Any]:
    """Process a correlated threat finding."""

    print("=" * 60)
    print("Starting SOAR Response Agent")
    print("=" * 60)

    print("Received event:")
    print(
        json.dumps(
            event,
            indent=2,
            default=str,
        )
    )

    try:
        finding_id = extract_finding_id(event)

        finding = get_finding(finding_id)

        print("Retrieved finding:")
        print(
            json.dumps(
                finding,
                indent=2,
                default=str,
            )
        )

        validate_finding(finding)

        playbook = select_playbook(finding)

        finding_context = build_finding_context(
            finding=finding,
            playbook=playbook,
        )

        if ENABLE_BEDROCK:
            try:
                response_summary = call_bedrock(
                    finding_context
                )

            except Exception as bedrock_error:
                print(
                    "Bedrock enrichment failed. "
                    "Using deterministic fallback."
                )
                print(
                    f"Bedrock error: "
                    f"{type(bedrock_error).__name__}: "
                    f"{bedrock_error}"
                )

                response_summary = (
                    create_fallback_summary(
                        finding_context
                    )
                )

        else:
            print(
                "Bedrock enrichment is disabled. "
                "Using deterministic fallback."
            )

            response_summary = (
                create_fallback_summary(
                    finding_context
                )
            )

        print("\n===== SOAR RESPONSE SUMMARY =====")
        print(response_summary["text"])
        print("=================================\n")

        incident_id, incident_created = (
            create_incident(
                finding=finding,
                playbook=playbook,
                response_summary=response_summary,
            )
        )

        sns_message_id = publish_notification(
            finding=finding,
            incident_id=incident_id,
            playbook=playbook,
            response_summary=response_summary,
        )

        update_finding_status(
            finding_id=finding_id,
            incident_id=incident_id,
            playbook=playbook,
            sns_message_id=sns_message_id,
        )

        result = {
            "message": (
                "SOAR response workflow completed."
            ),
            "finding_id": finding_id,
            "incident_id": incident_id,
            "incident_created": incident_created,
            "severity": playbook["severity"],
            "playbook": playbook["name"],
            "notification_sent": (
                sns_message_id is not None
            ),
            "sns_message_id": sns_message_id,
            "bedrock_summary_generated": (
                response_summary["generated"]
            ),
            "containment_performed": False,
            "human_review_required": True,
        }

        print("SOAR workflow result:")
        print(
            json.dumps(
                result,
                indent=2,
                default=str,
            )
        )

        return {
            "statusCode": 200,
            "body": json.dumps(result),
        }

    except AlreadyProcessedError as error:
        print(str(error))

        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": str(error),
                    "workflow_skipped": True,
                }
            ),
        }

    except (
        ClientError,
        BotoCoreError,
    ) as error:
        print(
            f"AWS service error: "
            f"{type(error).__name__}: {error}"
        )

        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "message": (
                        "SOAR workflow failed because "
                        "an AWS service returned an error."
                    ),
                    "error": str(error),
                }
            ),
        }

    except Exception as error:
        print(
            f"Unexpected SOAR error: "
            f"{type(error).__name__}: {error}"
        )

        return {
            "statusCode": 500,
            "body": json.dumps(
                {
                    "message": (
                        "SOAR response workflow failed."
                    ),
                    "error": str(error),
                }
            ),
        }
