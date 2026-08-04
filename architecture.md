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
               ↓
            EventBridge Custom Event
               ↓
            SOAR Response Agent
               ├── Validate finding
               ├── Select response playbook
               ├── Send notifications
               ├── Create response record
               ├── Request human approval when needed
               └── Perform approved containment actions