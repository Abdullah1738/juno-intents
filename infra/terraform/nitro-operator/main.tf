provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

data "aws_caller_identity" "current" {}

locals {
  tags = merge(
    {
      "juno-intents" = "nitro-operator"
    },
    var.tags,
  )
}

data "aws_iam_policy_document" "assume_ec2" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "nitro_operator" {
  name               = "${var.name_prefix}-nitro-operator"
  assume_role_policy = data.aws_iam_policy_document.assume_ec2.json
  tags               = local.tags
}

resource "aws_iam_instance_profile" "nitro_operator" {
  name = "${var.name_prefix}-nitro-operator"
  role = aws_iam_role.nitro_operator.name
  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.nitro_operator.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "kms_key_policy" {
  statement {
    sid       = "EnableRootPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid    = "AllowNitroOperatorUseWithPCR0"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
    ]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.nitro_operator.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "kms:RecipientAttestation:PCR0"
      values   = var.allowed_pcr0
    }
  }
}

resource "aws_kms_key" "nitro_operator" {
  description         = "Juno Intents Nitro operator envelope key (Nitro Enclaves PCR0-restricted)"
  enable_key_rotation = true
  policy              = data.aws_iam_policy_document.kms_key_policy.json
  tags                = local.tags
}

resource "aws_kms_alias" "nitro_operator" {
  name          = "alias/${var.name_prefix}-nitro-operator"
  target_key_id = aws_kms_key.nitro_operator.key_id
}

data "aws_iam_policy_document" "kms_use" {
  statement {
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
    ]
    resources = [aws_kms_key.nitro_operator.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:RecipientAttestation:PCR0"
      values   = var.allowed_pcr0
    }
  }
}

resource "aws_iam_role_policy" "kms_use" {
  name   = "${var.name_prefix}-nitro-operator-kms"
  role   = aws_iam_role.nitro_operator.id
  policy = data.aws_iam_policy_document.kms_use.json
}

