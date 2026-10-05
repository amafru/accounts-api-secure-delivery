# Section 2 infrastructure. [T1] immutable tags and signing key custody, [T2] scoped pipeline identity.
# Not applied in this submission; written to be reviewable and scannable (see Section 4 Checkov rules).

resource "aws_kms_key" "image_signing" {
  description              = "accounts-api image signing key (private half never leaves KMS)"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P256"
  deletion_window_in_days  = 30
  policy                   = data.aws_iam_policy_document.signing_key.json
}

resource "aws_kms_alias" "image_signing" {
  name          = "alias/accounts-api-signing"
  target_key_id = aws_kms_key.image_signing.key_id
}

data "aws_iam_policy_document" "signing_key" {
  # Only the pipeline role may sign. Everyone else can read the public key at most.
  statement {
    sid       = "PipelineSignsOnly"
    actions   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.pipeline.arn]
    }
  }
  # Key administration is separate from key use (no kms:Sign for admins).
  statement {
    sid       = "AdminsManageButCannotSign"
    actions   = ["kms:Describe*", "kms:List*", "kms:Get*", "kms:ScheduleKeyDeletion", "kms:PutKeyPolicy"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/security-admin"]
    }
  }
}

resource "aws_ecr_repository" "accounts_api" {
  name                 = "accounts-api"
  image_tag_mutability = "IMMUTABLE"          # a tag, once pushed, can never be re-pointed

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
  }
}

resource "aws_iam_role" "pipeline" {
  name               = "accounts-api-pipeline"
  assume_role_policy = file("${path.module}/oidc-trust-policy.json")
}

resource "aws_iam_role_policy" "pipeline" {
  name = "push-and-sign"
  role = aws_iam_role.pipeline.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ecr:GetAuthorizationToken"]
        Resource = "*"                         # this action does not support resource scoping
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload", "ecr:PutImage", "ecr:BatchGetImage"
        ]
        Resource = aws_ecr_repository.accounts_api.arn
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Sign", "kms:GetPublicKey"]
        Resource = aws_kms_key.image_signing.arn
      }
    ]
  })
}
