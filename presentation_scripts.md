# ArmageddonLab 12a & 12b — Presentation Scripts
**Author:** Jorune Simpkins
**Date:** August 2026

---

# VERSION 1 — Upper Management Presentation
## "Explain It Like I'm 5" — Business Audience

**Time:** 3-5 minutes
**Audience:** Non-technical managers, executives, business stakeholders
**Goal:** Show business value, risk reduction, cost savings

---

### Opening

"Thank you for the opportunity to present. I want to show you something I built
that protects our API from attackers — automatically, 24 hours a day, 7 days a
week, without anyone having to watch a screen."

---

### The Problem (Simple Version)

"Imagine your business has a front door. Every day, thousands of people walk up
to that door. Most of them are customers. But some of them are criminals trying
to break in.

Right now, without this system, you'd need a security guard standing at that
door 24/7, manually checking every single person. That's expensive, slow, and
the guard gets tired.

What I built is like hiring an entire security team that never sleeps, never
takes a break, and gets smarter every time someone tries to break in."

---

### What It Does (The Simple Explanation)

"My system has four jobs:

**Job 1 — The Bouncer (AWS WAF)**
The first thing anyone hits when they try to access our system is a bouncer.
This bouncer knows every criminal technique in the book — SQL injection, cross-
site scripting, known bad actors. If anything looks suspicious, it's blocked
instantly. No human has to do anything.

During my testing, I sent 150 requests in under 30 seconds simulating a DDoS
attack. The system blocked all of them automatically.

**Job 2 — The Detective (Correlation Agent)**
When the bouncer blocks someone, my detective takes notes. If the same person
keeps trying different doors, the detective figures that out — even if each
individual attempt looks minor. It calculates a threat score and decides how
serious the situation is.

**Job 3 — The Incident Commander (SOAR Agent)**
Based on how serious the threat is, the incident commander takes action
automatically. Low threat? Just log it. Medium threat? Notify the analyst.
High threat? Create an incident ticket and escalate immediately. Critical?
Page the on-call engineer instantly and create the full incident report
at the same time.

**Job 4 — The Executive Briefer (Dashboard)**
Every 24 hours, the system generates a PDF report — like this one — that
summarizes everything that happened. How many attacks were blocked. How
serious they were. What was done about them. Ready for management review."

---

### The Business Value

"Before this system, responding to a security incident required:
- A human analyst to notice something was wrong
- Manual investigation to understand the threat
- Time to write up an incident report
- Time to notify the right people

This could take hours. With my system:
- Detection happens in seconds
- Investigation is automated by AI
- Incident report is generated automatically
- Notifications are sent instantly

**The result:** We went from hours to seconds for initial threat response.
And we did it with zero additional headcount."

---

### The Numbers

"During my testing today:
- 10 XSS attacks — blocked in milliseconds ✅
- SQL injection attempts — blocked instantly ✅
- 150 rapid-fire requests (simulated DDoS) — blocked after threshold ✅
- Threat correlation — detected the pattern automatically ✅
- Incident report — generated and emailed within 30 seconds ✅
- Executive PDF report — produced covering the last 24 hours ✅"

---

### Closing

"What I've built is a security operations center in code. It runs on Amazon Web
Services, it costs less than a cup of coffee per day at lab scale, and it never
takes a day off.

The most important thing is this: when an attack happens, a human analyst
receives a complete, AI-generated incident report — not just an alert saying
'something is wrong.' They have the context they need to make a decision
immediately.

I'm happy to answer any questions."

---
---

# VERSION 2 — Technical Audience Presentation
## Job Interview / Peer Review Script

**Time:** 10-15 minutes
**Audience:** Senior engineers, hiring managers, technical leads, DevOps teams
**Goal:** Demonstrate depth of knowledge, architecture decisions, production thinking

---

### Opening

"I want to walk you through a multi-tier AWS security pipeline I built as part
of my cloud engineering training. I'll cover the architecture, the key design
decisions, the bugs I found and fixed, and what I'd do differently at scale.

The repo is live at github.com/Queuefour97/armageddon_lab12ab if you want to
follow along."

---

### Architecture Overview

"The pipeline has five tiers:

**Tier 1 — Edge Protection**
AWS WAF v2 with four managed and custom rules. Priority ordering matters here —
CommonRuleSet fires before the rate limit rule so a single XSS request gets
blocked by the rule match, not counted against the rate limit. This prevents
false positives on the rate counter.

**Tier 2 — Event Collection**
A Lambda reads WAF block events from CloudWatch using `FilterLogEvents`. I
store normalized events in DynamoDB with an integer `event_epoch` field — not
an ISO timestamp string. This is critical because DynamoDB's `FilterExpression`
requires numeric comparison for time-window queries. You can't do math on a
string.

**Tier 3 — Threat Correlation**
A second Lambda scans the event table using a 60-minute sliding window,
groups events by source IP, and calculates a deterministic risk score in pure
Python. I made a deliberate choice here — Bedrock generates the human-readable
narrative, but it never touches the scoring logic. The score is transparent,
auditable, and reproducible. Same inputs always produce the same score.

**Tier 4 — SOAR Automation**
The correlation agent publishes a custom event to EventBridge using
`events:PutEvents`. Two rules route by severity — MEDIUM/HIGH to the SOAR
Lambda, CRITICAL simultaneously to the SOAR Lambda AND an SNS topic. The
simultaneous fan-out on critical findings means the on-call engineer gets
paged at the edge of EventBridge before the Lambda even cold-starts.

The SOAR agent uses what I call the doorbell pattern — the EventBridge event
contains only a `finding_id`, not the full payload. The Lambda retrieves the
authoritative record from DynamoDB with `ConsistentRead=True`. This prevents
payload injection — an attacker who can put events on EventBridge can't
downgrade a CRITICAL finding to LOW by injecting a fake payload.

Incident IDs are deterministic: `INC-{finding_id}`. EventBridge has
at-least-once delivery, so idempotency is not optional. The conditional
`put_item` prevents duplicate incidents on retry.

**Tier 5 — Reporting**
A third Lambda generates executive PDF reports using ReportLab. I deliver this
as a Lambda Layer because ReportLab isn't in the standard runtime. The layer
had to be compiled for `manylinux2014_x86_64` — Windows binaries don't run
on Lambda Linux. I used `--platform` flag in pip install to get the right
architecture."

---

### Infrastructure as Code

"Everything is Terraform. I use 15 numbered `.tf` files — numbered for human
readability, though Terraform reads them all simultaneously regardless of name.

A few interesting Terraform patterns I implemented:

**Dynamic S3 bucket naming:**
```hcl
bucket = "chewbacca-s3-${data.aws_caller_identity.current.account_id}"
```
This makes the code portable across accounts without hardcoding.

**Sensitive variable handling:**
```hcl
variable "alert_email" {
  type      = string
  sensitive = true
}
```
The email address lives in `terraform.tfvars` which is gitignored. The plan
output shows `(sensitive value)` instead of the actual email.

**WAF logging configuration:**
I learned the hard way that `logs:FilterLogEvents` with a scoped resource ARN
breaks when the WAF logging configuration changes between applies. Changed it
to `Resource = "*"` — more permissive but operationally stable."

---

### Bugs Found and Fixed

"Let me talk about the bugs I found in the original code — because finding
and fixing them is more interesting than clean code.

**Bug 1 — The for-loop bug:**
The original `waf_bedrock_analyzer.py` had `save_to_dynamodb()` and
`call_bedrock()` called OUTSIDE the for loop. So it processed 10 events,
threw away 9, and only saved and analyzed the last one. Fixed by moving both
calls inside the loop.

**Bug 2 — DynamoDB Decimal type:**
Python floats can't be written to DynamoDB. I wrote a `native_to_decimal()`
function that recursively converts the entire item before `put_item`. The
critical detail: the `bool` check must come before the `int` check because
Python's `bool` is a subclass of `int`. `isinstance(True, int)` returns `True`,
so without the bool check first, `True` becomes `Decimal('True')` which crashes.

**Bug 3 — Cognito groups as string:**
API Gateway passes `cognito:groups` as a comma-separated string, not a Python
list. `claims.get('cognito:groups', [])` returns a string, not an empty list.
Membership checks fail silently. Fixed with `.split(',')`.

**Bug 4 — Legacy Bedrock model:**
`anthropic.claude-3-haiku-20240307-v1:0` is legacy. After 30 days without use,
AWS revokes access. Newer models require cross-region inference profiles — the
`us.` prefix. Changed all model IDs to `us.anthropic.claude-haiku-4-5-20251001-v1:0`."

---

### IAM Design

"I gave each Lambda its own dedicated role. This took more code but matters
operationally.

The WAF analyzer role has `logs:FilterLogEvents` with `Resource = "*"`. I
originally scoped it to the specific log group ARN, but that breaks when the
WAF logging configuration changes — the ARN in the IAM policy no longer matches
the actual log group being used. Production lesson: sometimes `*` is the more
correct choice.

The correlation agent needs `events:PutEvents` which my classmate's version was
missing. Without it the SOAR agent never fires — EventBridge never gets the
event. The Lambda succeeds silently, the incident is never created.

The SOAR agent has `dynamodb:UpdateItem` on the findings table to mark findings
as `RESPONSE_COMPLETED`. Without it you get `AccessDeniedException` on the
status update even though the incident was already created."

---

### What I'd Do Differently at Scale

"Three things I'd change for production:

**1. CloudWatch Subscription Filter instead of polling:**
Right now the WAF analyzer is invoked manually or on a schedule. At scale I'd
add a CloudWatch Logs subscription filter that triggers the Lambda automatically
when WAF writes a new log batch. Latency goes from minutes to seconds.

**2. DynamoDB Streams for the correlation trigger:**
The correlation agent currently polls. Adding a DynamoDB Stream on `waf-events`
would trigger the correlation Lambda on every new write from the analyzer.
True event-driven pipeline, no polling delay.

**3. GSI on `waf-events` for time-range queries:**
Currently using `Scan` with a `FilterExpression` on `event_epoch`. At scale
this scans the entire table and filters in Lambda. A GSI with `event_epoch` as
the sort key would let me `Query` instead of `Scan` — orders of magnitude
faster and cheaper.

**4. Snyk + Jenkins CI/CD:**
I'd add Snyk scanning for IaC misconfigurations and vulnerable dependencies,
and Jenkins to run the test suite automatically on every commit. The 12 tests
I have now would become automated assertions in a pipeline."

---

### Testing

"I wrote a 12-test plan covering the full pipeline:

Tests 1-3 prove WAF is actually blocking — XSS, SQL injection, and rate limiting.
For the rate limit test I had to use parallel requests with `&` in bash — sequential
requests spread beyond the 5-minute window and never hit the threshold.

Tests 4-5 prove the telemetry pipeline — events stored in DynamoDB with all
required fields including `event_epoch`.

Tests 6-7 prove SOAR determinism — MEDIUM triggers `NOTIFY_ANALYST`, HIGH
triggers `CREATE_AND_ESCALATE_INCIDENT`. The playbook selection is pure Python,
not AI. I can prove this by reading the code.

Test 8 proves the Lab 12b reporting pipeline — PDF generated by ReportLab
via Lambda Layer and uploaded to S3.

Tests 9-12 prove infrastructure state — EventBridge rules enabled, SNS
confirmed, DynamoDB counts non-zero, Terraform shows no drift."

---

### Closing

"The thing I'm most proud of isn't the pipeline working — it's understanding
why each piece is there and what breaks when it's missing.

I can tell you why `event_epoch` is an integer and not a string. I can tell you
why the SOAR agent uses a doorbell pattern. I can tell you why `bool` must be
checked before `int`. I can tell you why `logs:FilterLogEvents` needs `Resource`
set to `*`. I learned these things by hitting the errors and tracing them back
to root cause.

That's what I'd bring to your team — not just the ability to follow a lab
guide, but the ability to debug a production system at 2am when something
breaks in a way nobody anticipated.

Happy to go deeper on any part of this — the Terraform, the Python, the IAM
design, or the architectural trade-offs."

---

*ArmageddonLab 12a & 12b — Jorune Simpkins — August 2026*
