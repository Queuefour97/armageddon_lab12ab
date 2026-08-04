
waf_bedrock_analyzer.py

This Lambda:

Reads recent WAF logs from CloudWatch.
Normalizes each WAF event.
Stores the normalized event in DynamoDB.
Sends the individual event to Bedrock.
Writes the Bedrock incident summary to CloudWatch.


waf_threat_correlation_agent.py

This Lambda:

Reads normalized WAF events from DynamoDB.
Selects events from a configurable time window.
Calculates deterministic statistics.
Scores suspicious source IPs.
Sends the correlated evidence to Bedrock.
Stores the final threat finding in a second DynamoDB table.
Writes the complete report to CloudWatch.


Required environment variables
waf_bedrock_analyzer.py

    WAF_LOG_GROUP
    DYNAMODB_TABLE
    BEDROCK_MODEL_ID
    LOOKBACK_MINUTES
    MAX_LOG_EVENTS

waf_threat_correlation_agent.py

    WAF_EVENTS_TABLE
    CORRELATION_FINDINGS_TABLE
    BEDROCK_MODEL_ID
    CORRELATION_WINDOW_MINUTES
    MINIMUM_EVENT_COUNT
    MAX_EVENTS
    ADMIN_URI_KEYWORDS

The second script assumes two DynamoDB tables:

    waf-events
    waf-correlation-findings

The first table stores normalized evidence. The second stores the correlation agent’s conclusions.
