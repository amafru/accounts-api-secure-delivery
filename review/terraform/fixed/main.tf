# Artefact (b) fixed. Defects and ranking: docs/section4-review-remediate.md. Threats: T3, T4, T1.
# Scanned, not applied. Security group and trail bucket are stubs at the bottom so the file validates on its own.
variable "rds_kms_key_arn" {
  type        = string
  description = "Customer-managed KMS key for RDS storage encryption"
}

variable "eks_pod_security_group_id" {
  type        = string
  description = "Security group attached to accounts-api pods (security-groups-for-pods)"
}

resource "aws_db_instance" "accounts" {
  identifier     = "accounts-prod"
  engine         = "postgres"
  instance_class = "db.r6g.large"
  username       = "postgres"

  # RDS creates and rotates the master password in Secrets Manager.
  # Nothing is stored in Terraform state, variables or the repo.
  manage_master_user_password = true

  publicly_accessible                 = false
  iam_database_authentication_enabled = true

  storage_encrypted = true
  kms_key_id        = var.rds_kms_key_arn

  backup_retention_period   = 14
  skip_final_snapshot       = false
  final_snapshot_identifier = "accounts-prod-final"
  deletion_protection       = true
}

resource "aws_security_group_rule" "db_ingress" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = var.eks_pod_security_group_id # only the accounts-api pods, no CIDR
  security_group_id        = aws_security_group.db.id
}

resource "aws_cloudtrail" "org" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
}

# Stub so `terraform validate` passes on its own (the real security group lives in the network layer).
resource "aws_security_group" "db" {
  name        = "accounts-db"
  description = "accounts database (stub)"
}

# Stub: the real trail bucket (with its own policy and encryption) lives in the logging account.
resource "aws_s3_bucket" "trail" {
  bucket = "example-accounts-cloudtrail"
}
