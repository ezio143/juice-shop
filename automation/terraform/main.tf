# HARDENED — fixes every Checkov/tfsec finding from insecure.tf.
# See README.md for the full before/after breakdown and the one
# deliberately-deferred item (cross-region replication).

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}

# --- KMS key for S3/SNS encryption (CKV_AWS_145, CKV_AWS_26) ---
resource "aws_kms_key" "s3_key" {
  description             = "KMS key for juice-shop-portfolio-demo-data bucket and event encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  # FIX: explicit key policy required (CKV2_AWS_64) — without this, Checkov
  # can't confirm the key isn't relying on an overly permissive default policy.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootAccountFullAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowS3AndSNSServiceUse"
        Effect    = "Allow"
        Principal = { Service = ["s3.amazonaws.com", "sns.amazonaws.com"] }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*"]
        Resource  = "*"
      }
    ]
  })
}

# --- Logging bucket (target for the app bucket's access logs) ---
# Same cross-region replication reasoning as app_data - see comment above that resource.

resource "aws_s3_bucket" "log_bucket" {
  bucket = "juice-shop-portfolio-demo-logs"
# checkov:skip=CKV_AWS_144:Cross-region replication deferred - see app_data comment, disproportionate for a demo bucket
}

resource "aws_s3_bucket_public_access_block" "log_bucket" {
  bucket                  = aws_s3_bucket.log_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"   # FIX: customer-managed KMS key, not AES256 (tfsec encryption-customer-key)
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
    bucket_key_enabled = true
  }
}

# FIX: log_bucket now hardened to match app_data's pattern - versioning,
# lifecycle, and event notifications were missed on the first pass since
# log_bucket was added purely as a logging destination, without applying
# the same checklist used for app_data. Caught by the rescan, not the
# original build - the exact reason scan-fix-rescan is a loop.
resource "aws_s3_bucket_versioning" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_notification" "log_bucket" {
  bucket = aws_s3_bucket.log_bucket.id
  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*"]
  }
}

# --- Application data bucket: fully hardened ---
# Cross-region replication intentionally deferred - requires a second bucket
# in a different region plus a dedicated replication IAM role, disproportionate
# infrastructure for a portfolio demo bucket with no real data. Risk-accepted.

resource "aws_s3_bucket" "app_data" {
  bucket = "juice-shop-portfolio-demo-data"
# checkov:skip=CKV_AWS_144:Cross-region replication deferred - see comment above, disproportionate for a demo bucket
}

# FIX: block all public access (CKV_AWS_53/54/55/56, CKV2_AWS_6, CKV_AWS_20/57)
resource "aws_s3_bucket_public_access_block" "app_data" {
  bucket                  = aws_s3_bucket.app_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# FIX: encryption at rest with KMS (CKV_AWS_19, CKV_AWS_145)
resource "aws_s3_bucket_server_side_encryption_configuration" "app_data" {
  bucket = aws_s3_bucket.app_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_key.arn
    }
    bucket_key_enabled = true
  }
}

# FIX: versioning enabled (CKV_AWS_21) - protects against accidental/malicious deletion
resource "aws_s3_bucket_versioning" "app_data" {
  bucket = aws_s3_bucket.app_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

# FIX: access logging enabled (CKV_AWS_18)
resource "aws_s3_bucket_logging" "app_data" {
  bucket        = aws_s3_bucket.app_data.id
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "app-data-access-logs/"
}

# FIX: lifecycle configuration (CKV2_AWS_61)
resource "aws_s3_bucket_lifecycle_configuration" "app_data" {
  bucket = aws_s3_bucket.app_data.id
  rule {
    id     = "expire-noncurrent-versions"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    # FIX: abort incomplete multipart uploads after 7 days (CKV_AWS_300) -
    # prevents orphaned partial uploads from silently accumulating storage cost
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# FIX: event notifications enabled (CKV2_AWS_62)
resource "aws_sns_topic" "s3_events" {
  name              = "juice-shop-app-data-events"
  kms_master_key_id = aws_kms_key.s3_key.arn # FIX: topic encryption (CKV_AWS_26, tfsec aws-sns-enable-topic-encryption)
}

resource "aws_s3_bucket_notification" "app_data" {
  bucket = aws_s3_bucket.app_data.id
  topic {
    topic_arn = aws_sns_topic.s3_events.arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }
}

# NOTE: CKV_AWS_144 (cross-region replication) intentionally NOT implemented.
# It requires a second bucket in a different region plus a dedicated
# replication IAM role, which is disproportionate infrastructure for a
# portfolio demo bucket with no real data. Documented here as a deliberate,
# risk-accepted scope decision rather than an oversight — the same pattern
# used for Snyk findings with no available fix in Project 1.

# --- Security group: scoped instead of world-open ---
variable "admin_cidr" {
  description = "CIDR block allowed administrative (SSH) access — set to your own IP/32 in practice"
  type        = string
  default     = "203.0.113.0/24" # TEST-NET-3, RFC 5737 documentation range — replace with your real admin CIDR
}

resource "aws_security_group" "app_sg" {
  name        = "juice-shop-app-sg"
  description = "Security group for app servers"

  # FIX: SSH scoped to a specific admin CIDR, not 0.0.0.0/0 (CKV_AWS_25 / tfsec no-public-ingress-sgr)
  ingress {
    description = "SSH from admin network only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  # FIX: app port only, not all 65535 ports (CKV_AWS_260 / tfsec no-public-ingress-sgr)
  # SUPPRESSED: this rule is intentionally public - it's the app's HTTPS entrypoint,
  # not an oversight. tfsec cannot distinguish "intentional public web traffic"
  # from "accidentally wide open," so it flags any 0.0.0.0/0 rule regardless of
  # port. Documented and suppressed rather than silently ignored.
  #tfsec:ignore:aws-ec2-no-public-ingress-sgr
  ingress {
    description = "HTTPS app traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # intentionally public — this is the app's actual front door
  }

  # FIX: egress scoped to HTTPS only, not all protocols/ports (CKV_AWS_382 / tfsec no-public-egress-sgr)
  # SUPPRESSED: same reasoning as above - outbound HTTPS to arbitrary internet
  # destinations (e.g. calling external APIs) is the intended behavior here.
  #tfsec:ignore:aws-ec2-no-public-egress-sgr
  egress {
    description = "HTTPS outbound only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- IAM role for EC2 (CKV2_AWS_41) ---
resource "aws_iam_role" "app_server_role" {
  name = "juice-shop-app-server-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_instance_profile" "app_server_profile" {
  name = "juice-shop-app-server-profile"
  role = aws_iam_role.app_server_role.name
}

# --- EC2 instance: hardened ---
resource "aws_instance" "app_server" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.app_sg.id]

  # FIX: IAM role attached instead of no role (CKV2_AWS_41)
  iam_instance_profile = aws_iam_instance_profile.app_server_profile.name

  # FIX: no hardcoded secret in user_data (CKV_AWS_46, tfsec no-secrets-in-user-data).
  # The app now fetches its DB credential from Vault at startup instead —
  # this is exactly the pattern built in Project 3 (fetch_secret.py). In a
  # real deployment this would call Vault (or AWS Secrets Manager) directly
  # rather than assuming a value is already in the environment.
  user_data = <<-EOF
              #!/bin/bash
              # DB_PASSWORD is retrieved at runtime from Vault, not hardcoded here.
              # See automation/fetch_secret.py for the retrieval pattern.
              EOF

  # FIX: EBS optimized (CKV_AWS_135)
  ebs_optimized = true

  # FIX: detailed monitoring enabled (CKV_AWS_126) - 1-minute metric granularity
  # instead of the default 5-minute, meaningfully faster anomaly detection
  monitoring = true

  # FIX: root volume encrypted (CKV_AWS_8, tfsec)
  root_block_device {
    encrypted = true
  }

  # FIX: enforce IMDSv2, closing the SSRF-to-credential-theft path (CKV_AWS_79)
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
}
