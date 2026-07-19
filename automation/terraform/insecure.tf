# INTENTIONALLY INSECURE — Checkov/tfsec scan-fix-rescan
# demonstration. Do not deploy as-is. See main.tf (fixed version) for the
# hardened equivalent, and README.md for the before/after writeup.

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

# --- S3 bucket: multiple issues ---
resource "aws_s3_bucket" "app_data" {
  bucket = "juice-shop-portfolio-demo-data"
}

resource "aws_s3_bucket_public_access_block" "app_data" {
  bucket = aws_s3_bucket.app_data.id

  block_public_acls       = false  # ISSUE: allows public ACLs
  block_public_policy     = false  # ISSUE: allows public bucket policies
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# ISSUE: no server-side encryption configured at all
# ISSUE: no versioning configured (no protection against accidental/malicious deletion)

# --- Security group: wide open ---
resource "aws_security_group" "app_sg" {
  name        = "juice-shop-app-sg"
  description = "Security group for app servers"

  ingress {
    description = "SSH from anywhere"          # ISSUE: SSH open to the entire internet
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "All ports open"             # ISSUE: unrestricted port range, open to internet
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# --- EC2 instance: hardcoded secret + no encryption ---
resource "aws_instance" "app_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  # ISSUE: hardcoded credential baked directly into IaC (exactly what
  # gitleaks/Vault in Project 3 are meant to prevent — but IaC-embedded
  # secrets are a distinct attack surface gitleaks alone won't always catch
  # if the pattern doesn't match a known secret format)
  user_data = <<-EOF
              #!/bin/bash
              export DB_PASSWORD="SuperSecret123!"
              EOF

  root_block_device {
    encrypted = false  # ISSUE: unencrypted root volume
  }

  vpc_security_group_ids = [aws_security_group.app_sg.id]

  # ISSUE: no IMDSv2 enforcement (metadata_options block omitted entirely) —
  # leaves the instance metadata service exposed to SSRF-style credential theft
}
