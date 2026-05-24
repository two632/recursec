"""Serverless security knowledge base.

Attack patterns for serverless/FaaS environments:
1. Function Injection — event data injection, environment manipulation
2. IAM & Permission Escalation — over-privileged roles, cross-function abuse
3. Cold Start & Resource Abuse — denial of wallet, crypto mining
4. Data Flow Attacks — event source poisoning, output manipulation
5. Serverless-Specific Persistence — layer backdoors, trigger abuse
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


class ServerlessAttackType(str, Enum):
    FUNCTION_INJECTION = "function_injection"
    IAM_ESCALATION = "iam_escalation"
    RESOURCE_ABUSE = "resource_abuse"
    DATA_FLOW = "data_flow"
    PERSISTENCE = "persistence"


@dataclass
class ServerlessPattern:
    """A serverless attack pattern."""
    name: str = ""
    attack_type: ServerlessAttackType = ServerlessAttackType.FUNCTION_INJECTION
    description: str = ""
    detection_strategies: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    cloud_providers: list[str] = field(default_factory=list)
    severity: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.attack_type.value,
            "severity": self.severity,
            "providers": self.cloud_providers,
        }


SERVERLESS_PATTERNS: list[ServerlessPattern] = [
    ServerlessPattern(
        name="Function Injection",
        attack_type=ServerlessAttackType.FUNCTION_INJECTION,
        description=(
            "Injecting malicious payloads via event data that gets "
            "processed by Lambda/Cloud Functions: command injection "
            "through API Gateway events, S3 object names, SQS messages."
        ),
        detection_strategies=[
            "Analyze function handlers for unsanitized event data usage",
            "Check if event.body/event.queryStringParameters used in os.system()",
            "Test S3 trigger functions with malicious object key names",
            "Test SQS/SNS triggered functions with crafted message payloads",
            "Check for template injection in event data rendered to responses",
            "Verify input validation on all event source data",
            "Test API Gateway request mapping templates for injection",
            "Check if function code uses eval/exec on event data",
        ],
        indicators=[
            "Function handler passes event data to shell commands",
            "No input validation on event source data",
            "S3 object key used in file operations without sanitization",
            "SQS message body parsed and executed as code",
            "API Gateway event data in template rendering",
            "Environment variables set from event data",
        ],
        tools=["serverless-goat", "sls-dev-tools", "aws-cli",
               "semgrep", "bandit"],
        commands=[
            "aws lambda invoke --function-name target --payload '{\"cmd\":\"id\"}' out.json",
            "semgrep --config p/serverless . --lang python",
            "bandit -r . -t B602,B603,B604,B605",
            "aws s3 cp malicious.txt 's3://bucket/;id;.txt'",
            "aws sqs send-message --queue-url <url> --message-body '{\"exploit\":\"$(whoami)\"}'",
        ],
        cloud_providers=["AWS Lambda", "Azure Functions", "GCP Cloud Functions"],
        severity="critical",
    ),
    ServerlessPattern(
        name="IAM & Permission Escalation",
        attack_type=ServerlessAttackType.IAM_ESCALATION,
        description=(
            "Exploiting over-privileged IAM roles attached to serverless "
            "functions to escalate privileges, access other resources, "
            "or pivot to other services within the cloud account."
        ),
        detection_strategies=[
            "Audit Lambda execution role permissions (least privilege?)",
            "Check if function role has admin or wildcard policies",
            "Test if function can create new IAM users/roles",
            "Check for cross-account role assumption from function",
            "Verify resource-based policies on function invocation",
            "Check if function role can read secrets/SSM parameters",
            "Test lateral movement to other services (RDS, S3, DynamoDB)",
            "Verify function URL authentication type (IAM vs NONE)",
        ],
        indicators=[
            "Lambda role with AdministratorAccess policy",
            "IAM policy with Action: '*' and Resource: '*'",
            "Function can create IAM users or access keys",
            "Cross-account role trust policy too permissive",
            "Function URL with auth type NONE (public access)",
            "Lambda role can read all SSM parameters and secrets",
        ],
        tools=["prowler", "scoutsuite", "pacu", "cloudfox",
               "enumerate-iam"],
        commands=[
            "aws iam get-role --role-name <lambda_role>",
            "aws iam list-attached-role-policies --role-name <lambda_role>",
            "pacu --exec lambda__enum",
            "cloudfox aws lambda --profile <profile>",
            "prowler aws --check extra769,extra7170",
            "aws lambda get-function-url-config --function-name <func>",
        ],
        cloud_providers=["AWS Lambda", "Azure Functions", "GCP Cloud Functions"],
        severity="critical",
    ),
    ServerlessPattern(
        name="Cold Start & Resource Abuse",
        attack_type=ServerlessAttackType.RESOURCE_ABUSE,
        description=(
            "Abusing serverless resource allocation: denial-of-wallet "
            "attacks driving up costs, crypto mining in function "
            "execution, reserved concurrency exhaustion."
        ),
        detection_strategies=[
            "Check function timeout and memory configuration limits",
            "Monitor for abnormal invocation counts (DoW attack)",
            "Analyze function duration patterns for crypto mining",
            "Check reserved concurrency vs unreserved account limits",
            "Monitor for outbound connections to mining pools",
            "Verify cost alerts and budget alarms are configured",
            "Check for recursive function invocations (infinite loop)",
            "Monitor /tmp directory usage for suspicious artifacts",
        ],
        indicators=[
            "Function invocation count spike (1000x normal)",
            "Function duration at max timeout consistently",
            "Outbound connections to crypto mining pools",
            "Function writing executables to /tmp",
            "Reserved concurrency at account limit",
            "Monthly Lambda cost significantly higher than baseline",
        ],
        tools=["aws-cli", "cloudwatch", "cost-explorer"],
        commands=[
            "aws lambda get-function-configuration --function-name <func>",
            "aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Invocations --period 3600",
            "aws ce get-cost-and-usage --time-period Start=<start>,End=<end> --metrics BlendedCost --filter '{\"Dimensions\":{\"Key\":\"SERVICE\",\"Values\":[\"AWS Lambda\"]}}'",
            "aws lambda list-functions --query 'Functions[?Timeout>=`300`]'",
            "aws lambda get-account-settings",
        ],
        cloud_providers=["AWS Lambda", "Azure Functions", "GCP Cloud Functions"],
        severity="high",
    ),
    ServerlessPattern(
        name="Data Flow Attacks",
        attack_type=ServerlessAttackType.DATA_FLOW,
        description=(
            "Attacking serverless data flows: event source poisoning, "
            "output manipulation in step functions, dead letter queue "
            "data exfiltration, and cross-service data injection."
        ),
        detection_strategies=[
            "Trace data flow through event-driven architecture",
            "Check if S3 event notifications can be hijacked",
            "Verify DLQ messages are not accessible to unauthorized users",
            "Analyze Step Functions for state manipulation points",
            "Check if API Gateway response mapping modifies data",
            "Verify EventBridge rules cannot be modified by functions",
            "Test if function output is used unsanitized by downstream",
            "Check for SSRF via function-to-function calls",
        ],
        indicators=[
            "S3 event notifications pointing to attacker functions",
            "DLQ messages containing sensitive data",
            "Step Function state output trusted without validation",
            "EventBridge rules modifiable by function execution role",
            "Function output injected into SQL/NoSQL queries downstream",
            "Cross-function SSRF via internal service endpoints",
        ],
        tools=["aws-cli", "sls-dev-tools", "xray"],
        commands=[
            "aws s3api get-bucket-notification-configuration --bucket <bucket>",
            "aws sqs receive-message --queue-url <dlq_url> --max-number-of-messages 10",
            "aws stepfunctions describe-execution --execution-arn <arn>",
            "aws events list-rules",
            "aws xray get-trace-summaries --start-time <start> --end-time <end>",
        ],
        cloud_providers=["AWS Lambda", "Azure Functions", "GCP Cloud Functions"],
        severity="high",
    ),
    ServerlessPattern(
        name="Serverless Persistence",
        attack_type=ServerlessAttackType.PERSISTENCE,
        description=(
            "Establishing persistence in serverless environments: "
            "Lambda layer backdoors, trigger manipulation, version/alias "
            "pinning, and extension-based persistence."
        ),
        detection_strategies=[
            "Audit Lambda layers for unauthorized code",
            "Check for unauthorized event source mappings",
            "Monitor for function code updates outside CI/CD",
            "Check Lambda extensions for suspicious behavior",
            "Verify function versions and aliases are expected",
            "Check for unauthorized Lambda@Edge deployments",
            "Monitor for new API Gateway stages or endpoints",
            "Check for cron-triggered functions running persistence",
        ],
        indicators=[
            "Lambda layer added outside normal deployment process",
            "New event source mappings on existing functions",
            "Function code updated via direct API call (not CI/CD)",
            "Lambda extension sending data to external endpoints",
            "New function alias pointing to modified version",
            "CloudWatch Events rule triggering unknown function",
        ],
        tools=["prowler", "cloudfox", "aws-cli", "steampipe"],
        commands=[
            "aws lambda list-layers",
            "aws lambda get-layer-version --layer-name <name> --version-number <v>",
            "aws lambda list-event-source-mappings",
            "aws lambda list-versions-by-function --function-name <func>",
            "aws events list-targets-by-rule --rule <rule>",
            "aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateFunctionCode",
        ],
        cloud_providers=["AWS Lambda", "Azure Functions", "GCP Cloud Functions"],
        severity="high",
    ),
]


def build_serverless_prompt(
    focus_type: ServerlessAttackType | None = None,
    max_patterns: int = 5,
) -> str:
    """Build LLM prompt with serverless security knowledge."""
    lines = ["## Serverless Security Knowledge\n"]

    patterns = SERVERLESS_PATTERNS
    if focus_type:
        patterns = [p for p in patterns if p.attack_type == focus_type]

    for pattern in patterns[:max_patterns]:
        lines.append(f"### {pattern.name} [{pattern.severity}]")
        lines.append(pattern.description)
        lines.append(f"\nProviders: {', '.join(pattern.cloud_providers)}")
        lines.append("\nDetection:")
        for strategy in pattern.detection_strategies[:4]:
            lines.append(f"  - {strategy}")
        lines.append("\nIndicators:")
        for indicator in pattern.indicators[:3]:
            lines.append(f"  - {indicator}")
        lines.append("\nCommands:")
        for cmd in pattern.commands[:3]:
            lines.append(f"  $ {cmd}")
        lines.append("")

    return "\n".join(lines)
