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

resource "aws_secretsmanager_secret" "aws12" {
  name = "${local.friendly_name_prefix}-license"
}

resource "aws_secretsmanager_secret_version" "aws12" {
  secret_id     = aws_secretsmanager_secret.aws12.id
  secret_binary = filebase64(var.tfe_license_path)
}

module "kms" {
  source    = "../terraform-aws-terraform-enterprise/fixtures/kms"
  key_alias = "${local.friendly_name_prefix}-key"
}

module "tfe_node" {
  source                = "../terraform-aws-terraform-enterprise"
  friendly_name_prefix  = "aakulov"
  domain_name           = "akulov.cc"
  tfe_license_secret_id = aws_secretsmanager_secret_version.aws12.secret_id
  acm_certificate_arn   = aws_acm_certificate.aws12.arn
  kms_key_arn           = module.kms.key
  distribution          = var.distribution
}
