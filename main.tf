terraform {
  required_version = ">= 1.3"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {}

# --------------------------------------------------------------------------- #
# Variables
# --------------------------------------------------------------------------- #

variable "dry_run" {
  description = "When true, the Lambda only lists resources it would delete. Set to \"false\" to actually delete."
  type        = bool
  default     = true
}

variable "schedule_expression" {
  description = "EventBridge schedule for the cleanup. An empty value disables scheduling."
  type        = string
  default     = "rate(24 hours)"
}

variable "protect_tag_keys" {
  description = "Comma-separated tag keys that cause a resource to be left untouched when present."
  type        = string
  default     = "keep,protected,do-not-delete"
}

variable "stop_ec2" {
  description = "When true, running EC2 instances are stopped instead of terminated."
  type        = bool
  default     = true
}

variable "notification_email" {
  description = "Email address that receives the cleanup report. An empty value disables SNS notifications."
  type        = string
  default     = ""
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds."
  type        = number
  default     = 900
}

# security guard for deploying the Lambda
variable "deploy_lambda" {
  description = "Guard: the cleanup Lambda and its schedule/permissions are only deployed when this is true."
  type        = bool
  default     = false
}

# --------------------------------------------------------------------------- #
# Lambda packaging
# --------------------------------------------------------------------------- #

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/src"
  output_path = "${path.module}/build/cleanup.zip"
}

# --------------------------------------------------------------------------- #
# IAM
# --------------------------------------------------------------------------- #

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cleanup" {
  name               = "sandbox-cleanup-lambda"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

# Logging to CloudWatch.
resource "aws_iam_role_policy_attachment" "logs" {
  role       = aws_iam_role.cleanup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Permissions required for cleanup. The broad access is intentional because the
# purpose is to wipe an entire sandbox account. Use ONLY in sandbox accounts.
data "aws_iam_policy_document" "cleanup" {
  statement {
    sid    = "DescribeEverything"
    effect = "Allow"
    actions = [
      "ec2:Describe*",
      "elasticloadbalancing:Describe*",
      "rds:Describe*",
      "ecs:List*",
      "ecs:Describe*",
      "eks:List*",
      "eks:Describe*",
      "elasticache:Describe*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DeleteBillableResources"
    effect = "Allow"
    actions = [
      "ec2:TerminateInstances",
      "ec2:StopInstances",
      "ec2:DeleteVolume",
      "ec2:ReleaseAddress",
      "ec2:DisassociateAddress",
      "ec2:DeleteNatGateway",
      "ec2:DeregisterImage",
      "ec2:DeleteSnapshot",
      "elasticloadbalancing:DeleteLoadBalancer",
      "elasticloadbalancing:DescribeTags",
      "rds:DeleteDBInstance",
      "rds:DeleteDBCluster",
      "rds:ModifyDBInstance",
      "rds:ModifyDBCluster",
      "ecs:DeleteService",
      "ecs:DeleteCluster",
      "ecs:UpdateService",
      "ecs:StopTask",
      "eks:DeleteNodegroup",
      "eks:DeleteCluster",
      "eks:DeleteFargateProfile",
      "elasticache:DeleteCacheCluster",
      "elasticache:DeleteReplicationGroup",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "cleanup" {
  name   = "sandbox-cleanup-permissions"
  role   = aws_iam_role.cleanup.id
  policy = data.aws_iam_policy_document.cleanup.json
}

# Allow the Lambda to publish the cleanup report to SNS.
data "aws_iam_policy_document" "notify" {
  count = var.notification_email == "" ? 0 : 1

  statement {
    sid       = "PublishCleanupReport"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.report[0].arn]
  }
}

resource "aws_iam_role_policy" "notify" {
  count  = var.notification_email == "" ? 0 : 1
  name   = "sandbox-cleanup-notify"
  role   = aws_iam_role.cleanup.id
  policy = data.aws_iam_policy_document.notify[0].json
}

# --------------------------------------------------------------------------- #
# Notifications (SNS)
# --------------------------------------------------------------------------- #

resource "aws_sns_topic" "report" {
  count = var.notification_email == "" ? 0 : 1
  name  = "sandbox-cleanup-report"
}

resource "aws_sns_topic_subscription" "report_email" {
  count     = var.notification_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.report[0].arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# --------------------------------------------------------------------------- #
# Lambda
# --------------------------------------------------------------------------- #

resource "aws_lambda_function" "cleanup" {
  count            = var.deploy_lambda ? 1 : 0
  function_name    = "sandbox-cleanup"
  role             = aws_iam_role.cleanup.arn
  handler          = "cleanup.handler"
  runtime          = "python3.12"
  timeout          = var.lambda_timeout
  memory_size      = 256
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      DRY_RUN          = var.dry_run ? "true" : "false"
      PROTECT_TAG_KEYS = var.protect_tag_keys
      STOP_EC2         = var.stop_ec2 ? "true" : "false"
      SNS_TOPIC_ARN    = var.notification_email == "" ? "" : aws_sns_topic.report[0].arn
    }
  }
}

resource "aws_cloudwatch_log_group" "cleanup" {
  count             = var.deploy_lambda ? 1 : 0
  name              = "/aws/lambda/${aws_lambda_function.cleanup[0].function_name}"
  retention_in_days = 14
}

# --------------------------------------------------------------------------- #
# Scheduling (EventBridge)
# --------------------------------------------------------------------------- #

resource "aws_cloudwatch_event_rule" "schedule" {
  count               = var.schedule_expression == "" ? 0 : 1
  name                = "sandbox-cleanup-schedule"
  schedule_expression = var.schedule_expression
}

resource "aws_cloudwatch_event_target" "schedule" {
  count     = var.deploy_lambda && var.schedule_expression != "" ? 1 : 0
  rule      = aws_cloudwatch_event_rule.schedule[0].name
  target_id = "sandbox-cleanup"
  arn       = aws_lambda_function.cleanup[0].arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  count         = var.deploy_lambda && var.schedule_expression != "" ? 1 : 0
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cleanup[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule[0].arn
}

# --------------------------------------------------------------------------- #
# Outputs
# --------------------------------------------------------------------------- #

output "lambda_function_name" {
  value = var.deploy_lambda ? aws_lambda_function.cleanup[0].function_name : null
}

output "dry_run" {
  value = var.dry_run
}

output "report_topic_arn" {
  value = var.notification_email == "" ? null : aws_sns_topic.report[0].arn
}
