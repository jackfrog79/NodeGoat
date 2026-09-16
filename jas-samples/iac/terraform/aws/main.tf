# JAS IaC-scan demo fixture (AWS/Terraform). Not applied by any pipeline —
# fixture only, for JFrog Advanced Security IaC scanning to flag.
#
# Findings demonstrated (JFrog Misconfiguration Scans -> IaC):
#  - Overly-public access: S3 bucket with public-read ACL + public access
#    block disabled.
#  - Overly-public access: security group open to 0.0.0.0/0 on all ports.
#  - Admin-role overuse: IAM policy granting "*:*" on all resources.
#  - Hardcoded credentials: DB password literal in the resource.
#  - Missing encryption-at-rest: RDS instance with storage_encrypted = false.
#  - Disabled logging: CloudTrail trail with logging turned off.

provider "aws" {
  region = "us-east-1"
}

# Vulnerable: publicly readable bucket, no public access block.
resource "aws_s3_bucket" "reports" {
  bucket = "jas-demo-reports-bucket"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Vulnerable: ingress open to the entire internet on every port.
resource "aws_security_group" "wide_open" {
  name        = "jas-demo-wide-open"
  description = "Intentionally overly-permissive for JAS IaC demo"

  ingress {
    description = "Everything, from anywhere"
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Vulnerable: wildcard admin policy attached broadly.
resource "aws_iam_policy" "admin_everything" {
  name = "jas-demo-admin-everything"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# Vulnerable: hardcoded credential + unencrypted storage + disabled
# auto minor version upgrades.
resource "aws_db_instance" "app_db" {
  identifier                 = "jas-demo-db"
  engine                     = "postgres"
  instance_class             = "db.t3.micro"
  allocated_storage          = 20
  username                   = "admin"
  password                   = "SuperSecretP@ss123" # Vulnerable: hardcoded credential
  storage_encrypted          = false                # Vulnerable: no encryption at rest
  auto_minor_version_upgrade = false                # Vulnerable: disabled auto-upgrade
  skip_final_snapshot        = true
}

# Vulnerable: CloudTrail logging disabled.
resource "aws_cloudtrail" "audit" {
  name                   = "jas-demo-trail"
  s3_bucket_name         = aws_s3_bucket.reports.id
  is_multi_region_trail  = false
  enable_logging         = false # Vulnerable: disabled logging
}
