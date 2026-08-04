
Purpose of soar_response_agent.py

        Receive a threat-finding event from EventBridge.
        Retrieve the complete finding from DynamoDB.
        Validate that the finding has not already been processed.
        Select a deterministic response playbook.
        Ask Bedrock to create analyst and management summaries.
        Create an incident record.
        Publish an SNS notification.
        Update the original finding’s workflow status.


Main responsibilities

1. Retrieve and validate the finding

The EventBridge event should contain only routing information.

Agent should retrieve the complete record from: waf-correlation-findings using finding_id.

This ensures the agent operates on the full stored evidence rather than trusting a small event payload.

It should verify:

    the finding exists
    status is still OPEN
    it has not already been processed
    severity is valid
    required evidence is present

2. Select a playbook

The playbook selection should be deterministic.

Example:


| Severity | Playbook                                              |
| -------- | ----------------------------------------------------- |
| Low      | Record only                                           |
| Medium   | Notify analyst                                        |
| High     | Notify and create incident                            |
| Critical | Notify, create incident, request containment approval |


SOAR execution record
Required DynamoDB tables

        waf-correlation-findings
        Primary key: finding_id
        
        security-incidents
        Primary key: incident_id



Required environment variables

        CORRELATION_FINDINGS_TABLE=waf-correlation-findings
        SECURITY_INCIDENTS_TABLE=security-incidents
        SNS_TOPIC_ARN=<SNS topic ARN>
        BEDROCK_MODEL_ID=anthropic.claude-3-haiku-20240307-v1:0
        ENABLE_BEDROCK=true

Expected EventBridge input

        {
          "version": "0",
          "id": "example-event-id",
          "detail-type": "WAF Threat Finding Created",
          "source": "seir.waf.correlation",
          "account": "123456789012",
          "time": "2026-07-14T20:10:00Z",
          "region": "us-east-1",
          "resources": [],
          "detail": {
            "finding_id": "7ea476d0-1fea-4ff0-a95a-6377faac5cb4",
            "severity": "HIGH",
            "risk_score": 75
          }
        }


EventBridge events use a standard JSON envelope with fields such as source, detail-type, and detail; this agent uses only detail.finding_id for routing, then retrieves the authoritative finding from DynamoDB.

Required IAM actions

        {
          "Effect": "Allow",
          "Action": [
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "sns:Publish",
            "bedrock:InvokeModel"
          ],
          "Resource": "*"
        }

How would you implement:

        logs:CreateLogStream
        logs:PutLogEvents
        events:PutEvents


These map directly to the agent’s responsibilities: retrieve the finding, create the incident, update workflow state, publish the notification, and request informational Bedrock inference. Bedrock model invocation requires bedrock:InvokeModel; DynamoDB’s resource interface supports retrieving, writing, and modifying table items.


The deterministic incident ID: INC-<finding_id> makes the workflow idempotent when EventBridge retries the same finding. The conditional DynamoDB write prevents an existing incident from being replaced accidentally. DynamoDB supports conditional puts for this exact create-only pattern.