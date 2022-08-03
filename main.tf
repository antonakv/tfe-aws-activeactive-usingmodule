locals {
  friendly_name_prefix = random_string.friendly_name.id
}

resource "random_string" "friendly_name" {
  length  = 4
  upper   = false
  numeric = false
  special = false
}

provider "aws" {
  region = "eu-central-1"
}

data "local_sensitive_file" "sslcert" {
  filename = var.ssl_cert_path
}

data "local_sensitive_file" "sslkey" {
  filename = var.ssl_key_path
}

data "local_sensitive_file" "sslchain" {
  filename = var.ssl_chain_path
}

data "local_sensitive_file" "sslfullchaincert" {
  filename = var.ssl_fullchain_cert_path
}

resource "aws_acm_certificate" "aws12" {
  private_key       = data.local_sensitive_file.sslkey.content
  certificate_body  = data.local_sensitive_file.sslcert.content
  certificate_chain = data.local_sensitive_file.sslchain.content
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_secretsmanager_secret" "license" {
  name = "${local.friendly_name_prefix}-license"
}

resource "aws_secretsmanager_secret_version" "license" {
  secret_id     = aws_secretsmanager_secret.license.id
  secret_binary = filebase64(var.tfe_license_path)
}

resource "aws_secretsmanager_secret" "vm_cert" {
  name = "${local.friendly_name_prefix}-cert"
}

resource "aws_secretsmanager_secret_version" "vm_cert" {
  secret_id     = aws_secretsmanager_secret.vm_cert.id
  secret_binary = filebase64(var.vm_cert_path)
}

resource "aws_secretsmanager_secret" "vm_key" {
  name = "${local.friendly_name_prefix}-key"
}

resource "aws_secretsmanager_secret_version" "vm_key" {
  secret_id     = aws_secretsmanager_secret.vm_key.id
  secret_binary = filebase64(var.vm_key_path)
}

module "kms" {
  source    = "../terraform-aws-terraform-enterprise/fixtures/kms"
  key_alias = "${local.friendly_name_prefix}-key"
}

/* module "tfe_node" {
  source                = "../terraform-aws-terraform-enterprise"
  friendly_name_prefix  = "aakulov"
  domain_name           = "akulov.cc"
  tfe_license_secret_id = aws_secretsmanager_secret_version.license.secret_id
  acm_certificate_arn   = aws_acm_certificate.aws12.arn
  kms_key_arn           = module.kms.key
  distribution          = var.distribution
} */

data "aws_ami" "rhel" {
  owners = ["309956199498"] # RedHat

  most_recent = true

  filter {
    name   = "name"
    values = ["RHEL-7.9_HVM-*-x86_64-*-Hourly2-GP2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

module "active_active" {
  source                      = "../terraform-aws-terraform-enterprise"
  acm_certificate_arn         = aws_acm_certificate.aws12.arn
  domain_name                 = var.domain_name
  friendly_name_prefix        = local.friendly_name_prefix
  tfe_license_secret_id       = aws_secretsmanager_secret_version.license.secret_id
  ami_id                      = data.aws_ami.rhel.id
  distribution                = "rhel"
  iact_subnet_list            = ["0.0.0.0/0"]
  iam_role_policy_arns        = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore", "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]
  instance_type               = "m5.8xlarge"
  kms_key_arn                 = module.kms.key
  load_balancing_scheme       = "PRIVATE_TCP"
  node_count                  = 2
  redis_encryption_at_rest    = true
  redis_encryption_in_transit = true
  redis_use_password_auth     = true
  tfe_subdomain               = var.tfe_subdomain
  tls_bootstrap_cert_pathname = "/var/lib/terraform-enterprise/certificate.pem"
  tls_bootstrap_key_pathname  = "/var/lib/terraform-enterprise/key.pem"
  vm_certificate_secret_id    = aws_secretsmanager_secret_version.vm_cert.secret_id
  vm_key_secret_id            = aws_secretsmanager_secret_version.vm_key.secret_id
}
