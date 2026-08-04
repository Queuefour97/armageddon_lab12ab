# =============================================================
# 6-waf.tf — WAF Web ACL for the Chewbacca Token Tracking API
# =============================================================
#
# What this WAF protects:
#   Client → WAF → API Gateway (lambda-rest-api)
#              ↓             ↓
#        api_lambda_node   api_lambda_python
#              ↓
#         token-tracking (DynamoDB)
#
# The WAF sits in front of the API Gateway REST stage "prod"
# and filters every request BEFORE it reaches your Lambdas.
# Rules run in priority order — lowest number runs first.
# =============================================================


# -------------------------------------------------------------
# RESOURCE: aws_wafv2_web_acl
# This is the Web ACL (Access Control List) — the container
# that holds all your WAF rules. Think of it as the rulebook.
# -------------------------------------------------------------

resource "aws_wafv2_web_acl" "token_api_waf" {

  # Name visible in the AWS WAF console.
  # Descriptive so you remember this protects the token API.
  name = "token-api-waf"

  # REGIONAL = protects resources inside a region (API Gateway,
  # ALB, AppSync). The alternative is CLOUDFRONT, which only
  # works with CloudFront distributions and must be deployed
  # in us-east-1. Since your API Gateway is REGIONAL in 4-rest-api.tf,
  # this must also be REGIONAL.
  scope = "REGIONAL"

  # Default action when NO rules match the request.
  # ALLOW passes the request through to API Gateway.
  # The rules below will BLOCK the bad stuff before it gets here.
  default_action {
    allow {}
  }


  # -----------------------------------------------------------
  # RULE 1: AWS Common Rule Set  (priority 1 — runs first)
  # -----------------------------------------------------------
  # This is AWS's pre-built rule group covering the OWASP Top 10:
  #   - XSS (Cross-Site Scripting)        → protects your /node and /python endpoints
  #   - SQL Injection                      → relevant if Lambda queries DynamoDB with user input
  #   - Path traversal (../../etc/passwd)
  #   - Oversized request bodies
  #   - Bad HTTP methods
  #
  # Why it matters for YOUR stack:
  # Your Python Lambda writes user-supplied data into DynamoDB
  # (token_id, username). Without this rule, an attacker could
  # try to inject malicious input through your API Gateway endpoints.
  # -----------------------------------------------------------

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1

    # override_action applies to MANAGED rule groups only.
    # "none {}" means run the rules exactly as AWS configured them
    # (block what they say to block). The alternative is "count {}"
    # which lets everything through but logs hits — useful for testing
    # before going live, but not what you want in production.
    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        # AWS's official name for the common rule group.
        # You cannot change this — it's a lookup key in AWS's library.
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    # visibility_config controls CloudWatch metrics for this rule.
    # These metrics show up in CloudWatch under AWS/WAFV2.
    visibility_config {
      cloudwatch_metrics_enabled = true
      # metric_name is what you'll search for in CloudWatch.
      # Keeping it readable makes debugging easier.
      metric_name              = "CommonRuleSetMetric"
      sampled_requests_enabled = true # Stores sample blocked requests for review
    }
  }


  # -----------------------------------------------------------
  # RULE 2: Known Bad Inputs  (priority 2)
  # -----------------------------------------------------------
  # Blocks request patterns tied to specific CVEs and exploits:
  #   - Log4Shell (Log4j RCE — CVE-2021-44228)
  #   - SSRF (Server-Side Request Forgery) probes
  #   - JavaDeserializationExploits
  #
  # Why it matters for YOUR stack:
  # Your Node.js Lambda (nodejs24.x) could be vulnerable to
  # Log4Shell-style payloads injected via query strings or headers.
  # The ?name= query param in your output URLs is an open input
  # surface — this rule blocks known exploit patterns sent there.
  # -----------------------------------------------------------

  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsMetric"
      sampled_requests_enabled   = true
    }
  }


  # -----------------------------------------------------------
  # RULE 3: Rate Limiting  (priority 3)
  # -----------------------------------------------------------
  # Blocks any single IP that sends more than 100 requests
  # in a 5-minute rolling window.
  #
  # Why it matters for YOUR stack:
  # Your Cognito pool issues tokens and your DynamoDB table tracks
  # them. Without rate limiting, an attacker can hammer your
  # /python endpoint to brute-force credentials or flood your
  # DynamoDB table with fake token records — both of which cost
  # you money and degrade availability.
  #
  # 100 requests / 5 min is a reasonable lab threshold.
  # In production you'd tune this based on expected traffic.
  # -----------------------------------------------------------

  rule {
    name     = "RateLimitPerIP"
    priority = 3

    # Custom rules use "action" not "override_action".
    # override_action is only for managed rule groups (Rules 1 & 2).
    action {
      block {}
    }

    statement {
      rate_based_statement {
        # AWS evaluates this over a 5-minute window automatically.
        # 100 is the minimum allowed value.
        limit = 100

        # Count requests per source IP address.
        # Other options: FORWARDED_IP (for requests behind a proxy),
        # HTTP_METHOD, HEADER, etc.
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitPerIPMetric"
      sampled_requests_enabled   = true
    }
  }


  # -----------------------------------------------------------
  # RULE 4: Amazon IP Reputation List  (priority 4)
  # -----------------------------------------------------------
  # Blocks IPs that AWS has flagged as malicious based on their
  # own threat intelligence — bots, scanners, known bad actors.
  #
  # Why it matters for YOUR stack:
  # Your API endpoints are public (authorization = "NONE" in
  # 4-rest-api.tf). That means anyone on the internet can hit
  # them. This rule drops known bad IPs before they even touch
  # your Lambda cold-start budget.
  # -----------------------------------------------------------

  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 4

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSIPReputationMetric"
      sampled_requests_enabled   = true
    }
  }


  # -----------------------------------------------------------
  # Top-level visibility_config (required — covers the whole ACL)
  # -----------------------------------------------------------
  # This is the catch-all metric for the entire WAF, not just
  # individual rules. It tracks total requests evaluated by
  # this Web ACL regardless of which rule matched.
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "TokenApiWafMetric"
    sampled_requests_enabled   = true
  }

  tags = {
    Managedby = "Terraform"
  }
}


# -------------------------------------------------------------
# RESOURCE: aws_wafv2_web_acl_association
# This is the wire that connects the WAF to your API Gateway.
# Without this, the WAF exists but protects nothing.
#
# resource_arn points to your REST API stage "prod" defined
# in 4-rest-api.tf as aws_api_gateway_stage.rest_api_stage.
# That is the correct v1 REST API resource — NOT
# aws_apigatewayv2_stage which is for HTTP APIs (v2).
# -------------------------------------------------------------

resource "aws_wafv2_web_acl_association" "token_api_waf_association" {
  # The ARN of the thing being protected.
  # This comes directly from your existing stage in 4-rest-api.tf.
  resource_arn = aws_api_gateway_stage.rest_api_stage.arn

  # The ARN of the WAF Web ACL defined above.
  web_acl_arn = aws_wafv2_web_acl.token_api_waf.arn
}

# WAF Logging Configuration

resource "aws_cloudwatch_log_group" "waf_logs_chewbacca" {
  name = "aws-waf-logs-chewbacca" # Note: Log group name must be prefixed with aws-waf-logs e.g. aws-waf-logs-example-firehose, aws-waf-logs-example-log-group, or aws-waf-logs-example-bucket.
  retention_in_days = 7
}

# WAFv2 Web ACL Logging Configuration
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/wafv2_web_acl_logging_configuration#with-cloudwatch-log-group-and-managed-cloudwatch-log-resource-policy

resource "aws_wafv2_web_acl_logging_configuration" "waf_logging" {
# (Required) Configuration block that allows you to associate Amazon Kinesis Data Firehose, Cloudwatch Log log group, or S3 bucket Amazon Resource Names (ARNs) with the web ACL, log group name must be prefixed with aws-waf-logs e.g. aws-waf-logs-example-firehose, aws-waf-logs-example-log-group, or aws-waf-logs-example-bucket.
   log_destination_configs = [
      aws_cloudwatch_log_group.waf_logs_chewbacca.arn
   ]

     resource_arn = aws_wafv2_web_acl.token_api_waf.arn
     depends_on   = [aws_cloudwatch_log_group.waf_logs_chewbacca]

 }