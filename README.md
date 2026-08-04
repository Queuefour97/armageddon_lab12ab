      WAF Telemetry
         ↓
      Threat Correlation Agent
         ↓
      Finding stored
         ↓
      EventBridge custom event
         ↓
      SOAR Response Agent
         ├── Get finding
         ├── Validate status
         ├── Select playbook
         ├── Generate Bedrock summaries
         ├── Send SNS notification
         ├── Create incident record
         └── Update finding status
                  ↓
           Human analyst review
                  ↓
         Future containment workflow



            AWS WAF
               ↓
            CloudWatch Logs
               ↓
            WAF Bedrock Analyzer
               ↓
            DynamoDB: waf-events
               ↓
            Threat Correlation Agent
               ↓
            DynamoDB: waf-correlation-findings
            - waf_correlation-findings
            - Primary key: finding_id

            -security-incidents
            - Primary key: incident_id

               ↓
            EventBridge Custom Event
            -Main Responsibilities
                1. Retrieve and validate the finding
                2. Select a Playbook
                Severity Playbook
                Low Record only
                Medium Notify analyst
                High Notify and create incident
                Critical Notify, create incident, request containment approval


                payload

               ↓
            SOAR Response Agent
               ├── Validate finding
               ├── Select response playbook
               ├── Send notifications
               ├── Create response record
               ├── Request human approval when needed
               └── Perform approved containment actions

               Todo IAM
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


               Here is my detailed evaluation of the architecture, the EventBridge strategy, and the Python code, broken down into the "Aha!" moments you should take away from this.

1. The Architectural Triumphs (The "Why")
	A. Zero-Trust for Event Payloads
	Notice how the EventBridge event only contains a tiny 	routing key: "finding_id": "7ea476...".
	The Junior Way: Passing the entire threat report (IPs, 	logs, risk scores) inside the EventBridge event.
	The Senior Way (Your Mentor): EventBridge is just the "doorbell." When it rings, the Lambda walks over to the filing cabinet (DynamoDB waf-correlation-findings) and pulls the authoritative record using ConsistentRead=True. This prevents attackers (or buggy upstream systems) from spoofing EventBridge events with fake, low-severity payloads to bypass security checks.
B. The "Deterministic Brain, AI Voice" Pattern
This is the most critical concept in this entire script. The AI does not make decisions.
The Python dictionary PLAYBOOKS deterministically decides what happens based on severity (Low = Record, Medium = Notify, High = Escalate).
Bedrock is only called in call_bedrock() to write the report (build_finding_context).
The prompt explicitly handcuffs the AI: "You must not change the severity... Do not recommend automatic IP blocking... State clearly that a human analyst must review." This ensures the AI can never hallucinate a destructive action (like deleting a production database) based on a misunderstanding of the logs.
C. Bulletproof Idempotency
EventBridge guarantees at-least-once delivery, meaning it might send the same event twice if a Lambda times out.
The mentor uses build_incident_id() to create INC-<finding_id>.
When writing to the security-incidents table, they use ConditionExpression="attribute_not_exists(incident_id)".
If EventBridge retries, the PutItem fails gracefully with a ConditionalCheckFailedException, the code catches it, and says "Incident already exists. Reusing." Zero duplicate tickets are ever created.
2. Python Code Highlights (The "How")
Your mentor's Python code is incredibly clean and implements several advanced patterns that you will want to add to your personal playbook:
	A. The Ultimate "Golden Rule" Fallback
	Remember how we discussed that "AI failure must not 	block security"? Look at the lambda_handler and 	create_fallback_summary().
	If ENABLE_BEDROCK is false, or if the Bedrock API 	throws a timeout/throttling error, the code catches it 	and instantly generates a hardcoded, deterministic 	text summary. The incident is still created, the SOC 	is still notified, and the finding is still closed. 	The AI is a luxury; the workflow is a necessity.
B. DynamoDB Decimal Handling
DynamoDB returns all numbers as Python Decimal objects, which crash the standard json.dumps() function. The decimal_to_native() helper recursively walks through the dictionary and converts Decimals back to standard Python ints and floats. This is a mandatory utility for any Python/DynamoDB project.
C. Custom Exceptions for Control Flow
The AlreadyProcessedError is a brilliant use of custom exceptions. If validate_finding() sees that the status is already CLOSED or ESCALATED, it raises this error. The lambda_handler catches it at the very bottom and returns a 200 OK (not a 500 error!) with a message saying "workflow_skipped". This prevents CloudWatch from lighting up with false-red errors for events that were simply processed twice.
 D. SNS Message Attributes
When publishing to SNS, the mentor includes MessageAttributes for severity and playbook. This allows downstream systems (like an SNS-to-Slack Lambda, or an email filter) to route the message dynamically (e.g., "If severity == CRITICAL, page the on-call engineer; otherwise, just post to the #soc-alerts Slack channel").
3. The EventBridge Strategy
	The mentor split the EventBridge rules into two:
		Medium/High Rule: Routes only to the soar-		response-agent Lambda.
		Critical Rule: Routes to the soar-response-		agent Lambda AND directly to a critical-alert 		SNS topic.

Why do this?
Lambda execution takes time (querying DB, calling Bedrock, writing to DB, sending SNS). If a CRITICAL threat (like an active ransomware deployment) hits the system, you don't want to wait 10 seconds for the Lambda to finish its paperwork before the on-call engineer gets paged. By attaching the SNS topic directly to the EventBridge rule for Critical events, the alert fires instantly at the edge, while the Lambda works on the detailed ticket in the background.

Summary: What You Will Learn When You Build This
When you eventually tackle this phase, you are going to level up in the following areas:

State Machines: Moving a record from OPEN -> RESPONSE_COMPLETED across two different DynamoDB tables.
Advanced DynamoDB: Using ConditionExpression for create-only logic and handling Decimal types.
Defensive Prompting: Learning how to write prompts that restrict an LLM from taking unauthorized actions.
Resilience: Building a system that functions perfectly even if the AI service goes offline.

This is a phenomenal blueprint. You have completely absorbed the "Detection -> Enrichment -> Response" SOAR lifecycle.


Allows waf to talk to cloudwatch
},
        #Later
        #{
         # "Effect": "Allow",
         # "Action": [
         #   "events:PutEvents"
          # ],
        # "Resource": "*"
        #},
      {
        "Effect": "Allow",
        "Action": [
          "dynamodb:PutItem"
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ],
        "Resource": "arn:aws:dynamodb:<region>:<account-id>:table/waf-events"
      }
    ]
  }