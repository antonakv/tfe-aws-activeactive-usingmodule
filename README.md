# tfe-aws-activeactive-usingmodule
Install Prod External Services ( Redis + S3 + DB ) active-active installation AWS using module

This manual is dedicated to install Terraform Enterprise in the active-active mode

### Requirements

- Hashicorp terraform recent version installed
[Terraform installation manual](https://learn.hashicorp.com/tutorials/terraform/install-cli)

- git installed
[Git installation manual](https://git-scm.com/download/mac)

- Amazon AWS account credentials saved in .aws/credentials file
[Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

- Amazon AWS Session Manager Plugin installed
[Install the Session Manager plugin for the AWS CLI](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)

- SSL certificate and SSL key files for the corresponding domain name
[Certbot manual](https://certbot.eff.org/instructions)

- Created Amazon EC2 key pair for Linux instance
[Create a key pair using Amazon EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair)

- Amazon Route53 domain registered
[Register AWS Route53 domain](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/domain-register.html)

- Amazon Route53 domain zone created
[Creating a public hosted zone on AWS](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/CreatingHostedZone.html)

## Preparation 

- Clone git repository `hashicorp/terraform-aws-terraform-enterprise`

```bash
git clone git@github.com:hashicorp/terraform-aws-terraform-enterprise.git
```

Sample command output:

```bash
git clone git@github.com:hashicorp/terraform-aws-terraform-enterprise.git
Cloning into 'terraform-aws-terraform-enterprise'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 12 (delta 1), reused 3 (delta 0), pack-reused 0
Receiving objects: 100% (12/12), done.
Resolving deltas: 100% (1/1), done.
```

- Clone git repository `antonakv/tfe-aws-activeactive-usingmodule`

```bash
git clone git@github.com:antonakv/tfe-aws-activeactive-usingmodule.git
```

Sample command output:

```bash
git clone git@github.com:antonakv/tfe-aws-activeactive-usingmodule.git
Cloning into 'tfe-aws-activeactive-usingmodule'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 12 (delta 1), reused 3 (delta 0), pack-reused 0
Receiving objects: 100% (12/12), done.
Resolving deltas: 100% (1/1), done.
```

- Change folder to `tfe-aws-activeactive-usingmodule`

```bash
cd tfe-aws-activeactive-usingmodule
```

- Create file terraform.tfvars with following contents

```
domain_name             = "akulov.cc"
ssl_cert_path           = "/akulov.cc/cert.pem"
ssl_key_path            = "/akulov.cc/privkey.pem"
ssl_chain_path          = "/akulov.cc/chain.pem"
ssl_fullchain_cert_path = "/akulov.cc/fullchain.pem"
tfe_license_path        = "upload/license.rli"
distribution            = "rhel"
tfe_subdomain           = "tfe-xx"
tags                    = "aakulov"
vm_cert_path            = "/aakulov-aws-eu.pem"
vm_key_path             = "/aakulov-aws-eu.pub"
release_sequence        = 647
```

- Run the `terraform apply`

Expected result

```bash
% terraform apply
data.local_sensitive_file.sslcert: Reading...
data.local_sensitive_file.sslfullchaincert: Reading...
data.local_sensitive_file.sslkey: Reading...
data.local_sensitive_file.sslchain: Reading...
data.local_sensitive_file.sslcert: Read complete after 0s [id=03a1061535e45b575f310a070f77ab6ba7c314f0]
data.local_sensitive_file.sslchain: Read complete after 0s [id=35bea03aecd55ca4d525c6b0a45908a19c6986f9]
data.local_sensitive_file.sslkey: Read complete after 0s [id=c55e3e91058bd74118c719cdb13ae552d5b3347c]
data.local_sensitive_file.sslfullchaincert: Read complete after 0s [id=91d0d8e8bfce8b41db072fdc6f729ef5fc92acb8]
module.active_active.data.aws_region.current: Reading...
module.active_active.module.networking[0].data.aws_availability_zones.available: Reading...
module.active_active.data.aws_region.current: Read complete after 0s [id=eu-central-1]
data.aws_ami.rhel: Reading...
module.active_active.data.aws_ami.ubuntu: Reading...
module.active_active.module.service_accounts.data.aws_iam_policy_document.tfe_asg_discovery: Reading...
module.active_active.module.load_balancer[0].data.aws_route53_zone.tfe: Reading...
module.active_active.module.service_accounts.data.aws_iam_policy_document.instance_role: Reading...
module.active_active.module.service_accounts.data.aws_iam_policy_document.tfe_asg_discovery: Read complete after 0s [id=139118870]
module.active_active.module.service_accounts.data.aws_iam_policy_document.instance_role: Read complete after 0s [id=1903849331]
module.active_active.module.networking[0].data.aws_availability_zones.available: Read complete after 0s [id=eu-central-1]
module.active_active.module.networking[0].module.vpc_endpoints.data.aws_vpc_endpoint_service.this["ec2messages"]: Reading...
module.active_active.module.networking[0].module.vpc_endpoints.data.aws_vpc_endpoint_service.this["ec2"]: Reading...
module.active_active.module.networking[0].module.vpc_endpoints.data.aws_vpc_endpoint_service.this["kms"]: Reading...
module.active_active.module.networking[0].module.vpc_endpoints.data.aws_vpc_endpoint_service.this["s3"]: Reading...
module.active_active.module.networking[0].module.vpc_endpoints.data.aws_vpc_endpoint_service.this["ssm"]: Reading...
module.active_active.module.networking[0].module.vpc_endpoints.data.aws_vpc_endpoint_service.this["ssmmessages"]: Reading...
data.aws_ami.rhel: Read complete after 0s [id=ami-0a62e33b5dcf31c85]
module.active_active.data.aws_ami.ubuntu: Read complete after 0s [id=ami-06cac34c3836ff90b]
module.active_active.module.networking[0].module.vpc_endpoints.data.aws_vpc_endpoint_service.this["ssmmessages"]: Read complete after 0s [id=368186632]
module.active_active.module.networking[0].module.vpc_endpoints.data.aws_vpc_endpoint_service.this["kms"]: Read complete after 0s [id=3919227137]
module.active_active.module.networking[0].module.vpc_endpoints.data.aws_vpc_endpoint_service.this["ec2"]: Read complete after 0s [id=2086459523]
module.active_active.module.networking[0].module.vpc_endpoints.data.aws_vpc_endpoint_service.this["ec2messages"]: Read complete after 0s [id=3656651983]
module.active_active.module.networking[0].module.vpc_endpoints.data.aws_vpc_endpoint_service.this["ssm"]: Read complete after 0s [id=3588315509]
module.active_active.module.networking[0].module.vpc_endpoints.data.aws_vpc_endpoint_service.this["s3"]: Read complete after 0s [id=4172194041]
module.active_active.module.load_balancer[0].data.aws_route53_zone.tfe: Read complete after 2s [id=Z09465023NE5ESR8G9LQD]

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
 <= read (data resources)

Terraform will perform the following actions:

  # aws_acm_certificate.aws12 will be created
  + resource "aws_acm_certificate" "aws12" {
      + arn                       = (known after apply)
      + certificate_body          = (sensitive)
      + certificate_chain         = (sensitive)
      + domain_name               = (known after apply)
      + domain_validation_options = (known after apply)
      + id                        = (known after apply)
      + private_key               = (sensitive value)
      + status                    = (known after apply)
      + subject_alternative_names = (known after apply)
      + tags_all                  = (known after apply)
      + validation_emails         = (known after apply)
      + validation_method         = (known after apply)
    }

  # aws_secretsmanager_secret.license will be created
  + resource "aws_secretsmanager_secret" "license" {
      + arn                            = (known after apply)
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = (known after apply)
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 30
      + rotation_enabled               = (known after apply)
      + rotation_lambda_arn            = (known after apply)
      + tags_all                       = (known after apply)

      + replica {
          + kms_key_id         = (known after apply)
          + last_accessed_date = (known after apply)
          + region             = (known after apply)
          + status             = (known after apply)
          + status_message     = (known after apply)
        }

      + rotation_rules {
          + automatically_after_days = (known after apply)
        }
    }

  # aws_secretsmanager_secret.vm_cert will be created
  + resource "aws_secretsmanager_secret" "vm_cert" {
      + arn                            = (known after apply)
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = (known after apply)
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 30
      + rotation_enabled               = (known after apply)
      + rotation_lambda_arn            = (known after apply)
      + tags_all                       = (known after apply)

      + replica {
          + kms_key_id         = (known after apply)
          + last_accessed_date = (known after apply)
          + region             = (known after apply)
          + status             = (known after apply)
          + status_message     = (known after apply)
        }

      + rotation_rules {
          + automatically_after_days = (known after apply)
        }
    }

  # aws_secretsmanager_secret.vm_key will be created
  + resource "aws_secretsmanager_secret" "vm_key" {
      + arn                            = (known after apply)
      + force_overwrite_replica_secret = false
      + id                             = (known after apply)
      + name                           = (known after apply)
      + name_prefix                    = (known after apply)
      + policy                         = (known after apply)
      + recovery_window_in_days        = 30
      + rotation_enabled               = (known after apply)
      + rotation_lambda_arn            = (known after apply)
      + tags_all                       = (known after apply)

      + replica {
          + kms_key_id         = (known after apply)
          + last_accessed_date = (known after apply)
          + region             = (known after apply)
          + status             = (known after apply)
          + status_message     = (known after apply)
        }

      + rotation_rules {
          + automatically_after_days = (known after apply)
        }
    }

  # aws_secretsmanager_secret_version.license will be created
  + resource "aws_secretsmanager_secret_version" "license" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_binary  = (sensitive value)
      + secret_id      = (known after apply)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

  # aws_secretsmanager_secret_version.vm_cert will be created
  + resource "aws_secretsmanager_secret_version" "vm_cert" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_binary  = (sensitive value)
      + secret_id      = (known after apply)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

  # aws_secretsmanager_secret_version.vm_key will be created
  + resource "aws_secretsmanager_secret_version" "vm_key" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + secret_binary  = (sensitive value)
      + secret_id      = (known after apply)
      + version_id     = (known after apply)
      + version_stages = (known after apply)
    }

  # random_string.friendly_name will be created
  + resource "random_string" "friendly_name" {
      + id          = (known after apply)
      + length      = 4
      + lower       = true
      + min_lower   = 0
      + min_numeric = 0
      + min_special = 0
      + min_upper   = 0
      + number      = (known after apply)
      + numeric     = false
      + result      = (known after apply)
      + special     = false
      + upper       = false
    }

  # module.active_active.data.aws_kms_key.main will be read during apply
  # (config refers to values not yet known)
 <= data "aws_kms_key" "main" {
      + arn                        = (known after apply)
      + aws_account_id             = (known after apply)
      + creation_date              = (known after apply)
      + customer_master_key_spec   = (known after apply)
      + deletion_date              = (known after apply)
      + description                = (known after apply)
      + enabled                    = (known after apply)
      + expiration_model           = (known after apply)
      + id                         = (known after apply)
      + key_id                     = (known after apply)
      + key_manager                = (known after apply)
      + key_state                  = (known after apply)
      + key_usage                  = (known after apply)
      + multi_region               = (known after apply)
      + multi_region_configuration = (known after apply)
      + origin                     = (known after apply)
      + valid_to                   = (known after apply)
    }

  # module.kms.aws_kms_alias.main will be created
  + resource "aws_kms_alias" "main" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + name           = (known after apply)
      + name_prefix    = (known after apply)
      + target_key_arn = (known after apply)
      + target_key_id  = (known after apply)
    }

  # module.kms.aws_kms_key.main will be created
  + resource "aws_kms_key" "main" {
      + arn                                = (known after apply)
      + bypass_policy_lockout_safety_check = false
      + customer_master_key_spec           = "SYMMETRIC_DEFAULT"
      + deletion_window_in_days            = 7
      + description                        = "AWS KMS Customer-managed key to encrypt TFE and other resources"
      + enable_key_rotation                = false
      + id                                 = (known after apply)
      + is_enabled                         = true
      + key_id                             = (known after apply)
      + key_usage                          = "ENCRYPT_DECRYPT"
      + multi_region                       = (known after apply)
      + policy                             = (known after apply)
      + tags_all                           = (known after apply)
    }

  # module.active_active.module.database[0].aws_db_instance.postgresql will be created
  + resource "aws_db_instance" "postgresql" {
      + address                               = (known after apply)
      + allocated_storage                     = 20
      + allow_major_version_upgrade           = false
      + apply_immediately                     = true
      + arn                                   = (known after apply)
      + auto_minor_version_upgrade            = true
      + availability_zone                     = (known after apply)
      + backup_retention_period               = 0
      + backup_window                         = (known after apply)
      + ca_cert_identifier                    = (known after apply)
      + character_set_name                    = (known after apply)
      + copy_tags_to_snapshot                 = false
      + db_subnet_group_name                  = (known after apply)
      + delete_automated_backups              = true
      + deletion_protection                   = false
      + endpoint                              = (known after apply)
      + engine                                = "postgres"
      + engine_version                        = "12.8"
      + engine_version_actual                 = (known after apply)
      + hosted_zone_id                        = (known after apply)
      + id                                    = (known after apply)
      + identifier                            = (known after apply)
      + identifier_prefix                     = (known after apply)
      + instance_class                        = "db.m4.xlarge"
      + kms_key_id                            = (known after apply)
      + latest_restorable_time                = (known after apply)
      + license_model                         = (known after apply)
      + maintenance_window                    = (known after apply)
      + max_allocated_storage                 = 0
      + monitoring_interval                   = 0
      + monitoring_role_arn                   = (known after apply)
      + multi_az                              = true
      + name                                  = "espdtfe"
      + nchar_character_set_name              = (known after apply)
      + option_group_name                     = (known after apply)
      + parameter_group_name                  = (known after apply)
      + password                              = (sensitive value)
      + performance_insights_enabled          = false
      + performance_insights_kms_key_id       = (known after apply)
      + performance_insights_retention_period = (known after apply)
      + port                                  = 5432
      + publicly_accessible                   = false
      + replicas                              = (known after apply)
      + resource_id                           = (known after apply)
      + skip_final_snapshot                   = true
      + snapshot_identifier                   = (known after apply)
      + status                                = (known after apply)
      + storage_encrypted                     = true
      + storage_type                          = "gp2"
      + tags_all                              = (known after apply)
      + timezone                              = (known after apply)
      + username                              = "espdtfe"
      + vpc_security_group_ids                = (known after apply)
    }

  # module.active_active.module.database[0].aws_db_subnet_group.tfe will be created
  + resource "aws_db_subnet_group" "tfe" {
      + arn         = (known after apply)
      + description = "Managed by Terraform"
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = (known after apply)
      + subnet_ids  = (known after apply)
      + tags_all    = (known after apply)
    }

  # module.active_active.module.database[0].aws_security_group.postgresql will be created
  + resource "aws_security_group" "postgresql" {
      + arn                    = (known after apply)
      + description            = "The security group of the PostgreSQL deployment for TFE."
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # module.active_active.module.database[0].aws_security_group_rule.postgresql_egress will be created
  + resource "aws_security_group_rule" "postgresql_egress" {
      + cidr_blocks              = [
          + "10.0.32.0/20",
          + "10.0.48.0/20",
        ]
      + from_port                = 5432
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 5432
      + type                     = "egress"
    }

  # module.active_active.module.database[0].aws_security_group_rule.postgresql_ingress will be created
  + resource "aws_security_group_rule" "postgresql_ingress" {
      + cidr_blocks              = [
          + "10.0.32.0/20",
          + "10.0.48.0/20",
        ]
      + from_port                = 5432
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 5432
      + type                     = "ingress"
    }

  # module.active_active.module.database[0].aws_security_group_rule.postgresql_tfe_egress will be created
  + resource "aws_security_group_rule" "postgresql_tfe_egress" {
      + from_port                = 0
      + id                       = (known after apply)
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 0
      + type                     = "egress"
    }

  # module.active_active.module.database[0].aws_security_group_rule.postgresql_tfe_ingress will be created
  + resource "aws_security_group_rule" "postgresql_tfe_ingress" {
      + from_port                = 5432
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 5432
      + type                     = "ingress"
    }

  # module.active_active.module.database[0].random_string.postgresql_password will be created
  + resource "random_string" "postgresql_password" {
      + id          = (known after apply)
      + length      = 128
      + lower       = true
      + min_lower   = 0
      + min_numeric = 0
      + min_special = 0
      + min_upper   = 0
      + number      = true
      + numeric     = true
      + result      = (known after apply)
      + special     = false
      + upper       = true
    }

  # module.active_active.module.load_balancer[0].aws_lb.tfe_lb will be created
  + resource "aws_lb" "tfe_lb" {
      + arn                        = (known after apply)
      + arn_suffix                 = (known after apply)
      + desync_mitigation_mode     = "defensive"
      + dns_name                   = (known after apply)
      + drop_invalid_header_fields = false
      + enable_deletion_protection = false
      + enable_http2               = true
      + enable_waf_fail_open       = false
      + id                         = (known after apply)
      + idle_timeout               = 60
      + internal                   = false
      + ip_address_type            = (known after apply)
      + load_balancer_type         = "application"
      + name                       = (known after apply)
      + security_groups            = (known after apply)
      + subnets                    = (known after apply)
      + tags_all                   = (known after apply)
      + vpc_id                     = (known after apply)
      + zone_id                    = (known after apply)

      + subnet_mapping {
          + allocation_id        = (known after apply)
          + ipv6_address         = (known after apply)
          + outpost_id           = (known after apply)
          + private_ipv4_address = (known after apply)
          + subnet_id            = (known after apply)
        }
    }

  # module.active_active.module.load_balancer[0].aws_lb_listener.tfe_listener_443 will be created
  + resource "aws_lb_listener" "tfe_listener_443" {
      + arn               = (known after apply)
      + certificate_arn   = (known after apply)
      + id                = (known after apply)
      + load_balancer_arn = (known after apply)
      + port              = 443
      + protocol          = "HTTPS"
      + ssl_policy        = "ELBSecurityPolicy-2016-08"
      + tags_all          = (known after apply)

      + default_action {
          + order            = (known after apply)
          + target_group_arn = (known after apply)
          + type             = "forward"
        }
    }

  # module.active_active.module.load_balancer[0].aws_lb_listener.tfe_listener_80 will be created
  + resource "aws_lb_listener" "tfe_listener_80" {
      + arn               = (known after apply)
      + id                = (known after apply)
      + load_balancer_arn = (known after apply)
      + port              = 80
      + protocol          = "HTTP"
      + ssl_policy        = (known after apply)
      + tags_all          = (known after apply)

      + default_action {
          + order = (known after apply)
          + type  = "redirect"

          + redirect {
              + host        = "#{host}"
              + path        = "/#{path}"
              + port        = "443"
              + protocol    = "HTTPS"
              + query       = "#{query}"
              + status_code = "HTTP_301"
            }
        }
    }

  # module.active_active.module.load_balancer[0].aws_lb_target_group.tfe_tg_443 will be created
  + resource "aws_lb_target_group" "tfe_tg_443" {
      + arn                                = (known after apply)
      + arn_suffix                         = (known after apply)
      + connection_termination             = false
      + deregistration_delay               = "300"
      + id                                 = (known after apply)
      + lambda_multi_value_headers_enabled = false
      + load_balancing_algorithm_type      = (known after apply)
      + name                               = (known after apply)
      + port                               = 443
      + preserve_client_ip                 = (known after apply)
      + protocol                           = "HTTPS"
      + protocol_version                   = (known after apply)
      + proxy_protocol_v2                  = false
      + slow_start                         = 0
      + tags_all                           = (known after apply)
      + target_type                        = "instance"
      + vpc_id                             = (known after apply)

      + health_check {
          + enabled             = true
          + healthy_threshold   = 3
          + interval            = 30
          + matcher             = "200-399"
          + path                = "/_health_check"
          + port                = "traffic-port"
          + protocol            = "HTTPS"
          + timeout             = (known after apply)
          + unhealthy_threshold = 3
        }

      + stickiness {
          + cookie_duration = (known after apply)
          + cookie_name     = (known after apply)
          + enabled         = (known after apply)
          + type            = (known after apply)
        }
    }

  # module.active_active.module.load_balancer[0].aws_route53_record.tfe will be created
  + resource "aws_route53_record" "tfe" {
      + allow_overwrite = (known after apply)
      + fqdn            = (known after apply)
      + id              = (known after apply)
      + name            = "tfe-xx.akulov.cc"
      + type            = "A"
      + zone_id         = "Z09465023NE5ESR8G9LQD"

      + alias {
          + evaluate_target_health = true
          + name                   = (known after apply)
          + zone_id                = (known after apply)
        }
    }

  # module.active_active.module.load_balancer[0].aws_security_group.tfe_lb_allow will be created
  + resource "aws_security_group" "tfe_lb_allow" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # module.active_active.module.load_balancer[0].aws_security_group.tfe_outbound_allow will be created
  + resource "aws_security_group" "tfe_outbound_allow" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # module.active_active.module.load_balancer[0].aws_security_group_rule.tfe_lb_allow_inbound_http will be created
  + resource "aws_security_group_rule" "tfe_lb_allow_inbound_http" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Allow HTTP (port 80) traffic inbound to TFE LB"
      + from_port                = 80
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 80
      + type                     = "ingress"
    }

  # module.active_active.module.load_balancer[0].aws_security_group_rule.tfe_lb_allow_inbound_https will be created
  + resource "aws_security_group_rule" "tfe_lb_allow_inbound_https" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Allow HTTPS (port 443) traffic inbound to TFE LB"
      + from_port                = 443
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.active_active.module.load_balancer[0].aws_security_group_rule.tfe_outbound_allow_all will be created
  + resource "aws_security_group_rule" "tfe_outbound_allow_all" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + description              = "Allow all traffic outbound from TFE"
      + from_port                = 0
      + id                       = (known after apply)
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 0
      + type                     = "egress"
    }

  # module.active_active.module.networking[0].aws_security_group.ssm will be created
  + resource "aws_security_group" "ssm" {
      + arn                    = (known after apply)
      + description            = "The security group of Systems Manager for TFE."
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "10.0.32.0/20",
                  + "10.0.48.0/20",
                ]
              + description      = "Allow the ingress of HTTPS traffic from all private subnets."
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
        ]
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # module.active_active.module.object_storage[0].data.aws_iam_policy_document.tfe_data will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "tfe_data" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions   = [
              + "s3:GetBucketLocation",
              + "s3:ListBucket",
            ]
          + effect    = "Allow"
          + resources = [
              + (known after apply),
            ]
          + sid       = "AllowS3ListBucketData"

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "AWS"
            }
        }
      + statement {
          + actions   = [
              + "s3:DeleteObject",
              + "s3:GetObject",
              + "s3:PutObject",
            ]
          + effect    = "Allow"
          + resources = [
              + (known after apply),
            ]
          + sid       = "AllowS3ManagementData"

          + principals {
              + identifiers = [
                  + (known after apply),
                ]
              + type        = "AWS"
            }
        }
    }

  # module.active_active.module.object_storage[0].aws_s3_bucket.tfe_data_bucket will be created
  + resource "aws_s3_bucket" "tfe_data_bucket" {
      + acceleration_status         = (known after apply)
      + acl                         = "private"
      + arn                         = (known after apply)
      + bucket                      = (known after apply)
      + bucket_domain_name          = (known after apply)
      + bucket_regional_domain_name = (known after apply)
      + force_destroy               = true
      + hosted_zone_id              = (known after apply)
      + id                          = (known after apply)
      + region                      = (known after apply)
      + request_payer               = (known after apply)
      + tags_all                    = (known after apply)
      + website_domain              = (known after apply)
      + website_endpoint            = (known after apply)

      + server_side_encryption_configuration {
          + rule {
              + apply_server_side_encryption_by_default {
                  + kms_master_key_id = (known after apply)
                  + sse_algorithm     = "aws:kms"
                }
            }
        }

      + versioning {
          + enabled    = true
          + mfa_delete = false
        }
    }

  # module.active_active.module.object_storage[0].aws_s3_bucket_policy.tfe_data will be created
  + resource "aws_s3_bucket_policy" "tfe_data" {
      + bucket = (known after apply)
      + id     = (known after apply)
      + policy = (known after apply)
    }

  # module.active_active.module.object_storage[0].aws_s3_bucket_public_access_block.tfe_data will be created
  + resource "aws_s3_bucket_public_access_block" "tfe_data" {
      + block_public_acls       = true
      + block_public_policy     = true
      + bucket                  = (known after apply)
      + id                      = (known after apply)
      + ignore_public_acls      = true
      + restrict_public_buckets = true
    }

  # module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0] will be created
  + resource "aws_elasticache_replication_group" "redis" {
      + apply_immediately              = true
      + arn                            = (known after apply)
      + at_rest_encryption_enabled     = true
      + auth_token                     = (sensitive value)
      + auto_minor_version_upgrade     = true
      + automatic_failover_enabled     = false
      + cluster_enabled                = (known after apply)
      + configuration_endpoint_address = (known after apply)
      + data_tiering_enabled           = (known after apply)
      + engine                         = "redis"
      + engine_version                 = "5.0.6"
      + engine_version_actual          = (known after apply)
      + global_replication_group_id    = (known after apply)
      + id                             = (known after apply)
      + kms_key_id                     = (known after apply)
      + maintenance_window             = (known after apply)
      + member_clusters                = (known after apply)
      + multi_az_enabled               = false
      + node_type                      = "cache.m4.large"
      + number_cache_clusters          = 1
      + parameter_group_name           = "default.redis5.0"
      + port                           = 6380
      + primary_endpoint_address       = (known after apply)
      + reader_endpoint_address        = (known after apply)
      + replication_group_description  = "The replication group of the Redis deployment for TFE."
      + replication_group_id           = (known after apply)
      + security_group_ids             = (known after apply)
      + security_group_names           = (known after apply)
      + snapshot_retention_limit       = 0
      + snapshot_window                = (known after apply)
      + subnet_group_name              = (known after apply)
      + tags_all                       = (known after apply)
      + transit_encryption_enabled     = true

      + cluster_mode {
          + num_node_groups         = (known after apply)
          + replicas_per_node_group = (known after apply)
        }
    }

  # module.active_active.module.redis[0].aws_elasticache_subnet_group.tfe[0] will be created
  + resource "aws_elasticache_subnet_group" "tfe" {
      + arn         = (known after apply)
      + description = "Managed by Terraform"
      + id          = (known after apply)
      + name        = (known after apply)
      + subnet_ids  = (known after apply)
      + tags_all    = (known after apply)
    }

  # module.active_active.module.redis[0].aws_security_group.redis[0] will be created
  + resource "aws_security_group" "redis" {
      + arn                    = (known after apply)
      + description            = "The security group of the Redis deployment for TFE."
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # module.active_active.module.redis[0].aws_security_group_rule.redis_egress[0] will be created
  + resource "aws_security_group_rule" "redis_egress" {
      + cidr_blocks              = [
          + "10.0.32.0/20",
          + "10.0.48.0/20",
        ]
      + from_port                = 6380
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 6380
      + type                     = "egress"
    }

  # module.active_active.module.redis[0].aws_security_group_rule.redis_ingress[0] will be created
  + resource "aws_security_group_rule" "redis_ingress" {
      + cidr_blocks              = [
          + "10.0.32.0/20",
          + "10.0.48.0/20",
        ]
      + from_port                = 6380
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 6380
      + type                     = "ingress"
    }

  # module.active_active.module.redis[0].aws_security_group_rule.redis_tfe_egress[0] will be created
  + resource "aws_security_group_rule" "redis_tfe_egress" {
      + from_port                = 0
      + id                       = (known after apply)
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 0
      + type                     = "egress"
    }

  # module.active_active.module.redis[0].aws_security_group_rule.redis_tfe_ingress[0] will be created
  + resource "aws_security_group_rule" "redis_tfe_ingress" {
      + from_port                = 6380
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 6380
      + type                     = "ingress"
    }

  # module.active_active.module.redis[0].random_id.redis_password[0] will be created
  + resource "random_id" "redis_password" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # module.active_active.module.service_accounts.data.aws_iam_policy_document.secretsmanager will be read during apply
  # (config refers to values not yet known)
 <= data "aws_iam_policy_document" "secretsmanager" {
      + id   = (known after apply)
      + json = (known after apply)

      + statement {
          + actions   = [
              + "secretsmanager:GetSecretValue",
            ]
          + effect    = "Allow"
          + resources = (known after apply)
          + sid       = "AllowSecretsManagerSecretAccess"
        }
    }

  # module.active_active.module.service_accounts.aws_iam_instance_profile.tfe will be created
  + resource "aws_iam_instance_profile" "tfe" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = (known after apply)
      + name_prefix = (known after apply)
      + path        = "/"
      + role        = (known after apply)
      + tags_all    = (known after apply)
      + unique_id   = (known after apply)
    }

  # module.active_active.module.service_accounts.aws_iam_policy.kms_policy will be created
  + resource "aws_iam_policy" "kms_policy" {
      + arn       = (known after apply)
      + id        = (known after apply)
      + name      = (known after apply)
      + path      = "/"
      + policy    = (known after apply)
      + policy_id = (known after apply)
      + tags_all  = (known after apply)
    }

  # module.active_active.module.service_accounts.aws_iam_role.instance_role will be created
  + resource "aws_iam_role" "instance_role" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                      + Sid       = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = (known after apply)
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # module.active_active.module.service_accounts.aws_iam_role_policy.secretsmanager[0] will be created
  + resource "aws_iam_role_policy" "secretsmanager" {
      + id     = (known after apply)
      + name   = (known after apply)
      + policy = (known after apply)
      + role   = (known after apply)
    }

  # module.active_active.module.service_accounts.aws_iam_role_policy.tfe_asg_discovery will be created
  + resource "aws_iam_role_policy" "tfe_asg_discovery" {
      + id     = (known after apply)
      + name   = (known after apply)
      + policy = jsonencode(
            {
              + Statement = [
                  + {
                      + Action   = "autoscaling:Describe*"
                      + Effect   = "Allow"
                      + Resource = "*"
                      + Sid      = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + role   = (known after apply)
    }

  # module.active_active.module.service_accounts.aws_iam_role_policy_attachment.kms_policy will be created
  + resource "aws_iam_role_policy_attachment" "kms_policy" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + role       = (known after apply)
    }

  # module.active_active.module.service_accounts.aws_iam_role_policy_attachment.misc["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"] will be created
  + resource "aws_iam_role_policy_attachment" "misc" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
      + role       = (known after apply)
    }

  # module.active_active.module.service_accounts.aws_iam_role_policy_attachment.misc["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"] will be created
  + resource "aws_iam_role_policy_attachment" "misc" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      + role       = (known after apply)
    }

  # module.active_active.module.settings.random_id.archivist_token will be created
  + resource "random_id" "archivist_token" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # module.active_active.module.settings.random_id.cookie_hash will be created
  + resource "random_id" "cookie_hash" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # module.active_active.module.settings.random_id.enc_password will be created
  + resource "random_id" "enc_password" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # module.active_active.module.settings.random_id.install_id will be created
  + resource "random_id" "install_id" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # module.active_active.module.settings.random_id.internal_api_token will be created
  + resource "random_id" "internal_api_token" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # module.active_active.module.settings.random_id.registry_session_encryption_key will be created
  + resource "random_id" "registry_session_encryption_key" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # module.active_active.module.settings.random_id.registry_session_secret_key will be created
  + resource "random_id" "registry_session_secret_key" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # module.active_active.module.settings.random_id.root_secret will be created
  + resource "random_id" "root_secret" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # module.active_active.module.settings.random_id.user_token will be created
  + resource "random_id" "user_token" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 16
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # module.active_active.module.settings.random_string.password will be created
  + resource "random_string" "password" {
      + id          = (known after apply)
      + length      = 16
      + lower       = true
      + min_lower   = 0
      + min_numeric = 0
      + min_special = 0
      + min_upper   = 0
      + number      = true
      + numeric     = true
      + result      = (known after apply)
      + special     = false
      + upper       = true
    }

  # module.active_active.module.vm.aws_autoscaling_group.tfe_asg will be created
  + resource "aws_autoscaling_group" "tfe_asg" {
      + arn                       = (known after apply)
      + availability_zones        = (known after apply)
      + default_cooldown          = (known after apply)
      + desired_capacity          = 2
      + force_delete              = false
      + force_delete_warm_pool    = false
      + health_check_grace_period = 1500
      + health_check_type         = "ELB"
      + id                        = (known after apply)
      + launch_configuration      = (known after apply)
      + max_size                  = 2
      + metrics_granularity       = "1Minute"
      + min_size                  = 2
      + name                      = (known after apply)
      + name_prefix               = (known after apply)
      + protect_from_scale_in     = false
      + service_linked_role_arn   = (known after apply)
      + tags                      = [
          + (known after apply),
        ]
      + target_group_arns         = (known after apply)
      + vpc_zone_identifier       = (known after apply)
      + wait_for_capacity_timeout = "10m"
    }

  # module.active_active.module.vm.aws_launch_configuration.tfe will be created
  + resource "aws_launch_configuration" "tfe" {
      + arn                         = (known after apply)
      + associate_public_ip_address = false
      + ebs_optimized               = (known after apply)
      + enable_monitoring           = true
      + iam_instance_profile        = (known after apply)
      + id                          = (known after apply)
      + image_id                    = "ami-0a62e33b5dcf31c85"
      + instance_type               = "m5.8xlarge"
      + key_name                    = (known after apply)
      + name                        = (known after apply)
      + name_prefix                 = (known after apply)
      + security_groups             = (known after apply)
      + user_data_base64            = (known after apply)

      + ebs_block_device {
          + delete_on_termination = true
          + device_name           = "xvdcc"
          + encrypted             = (known after apply)
          + iops                  = 3000
          + snapshot_id           = (known after apply)
          + throughput            = (known after apply)
          + volume_size           = 200
          + volume_type           = "io1"
        }

      + metadata_options {
          + http_endpoint               = "enabled"
          + http_put_response_hop_limit = 2
          + http_tokens                 = "optional"
        }

      + root_block_device {
          + delete_on_termination = true
          + encrypted             = true
          + iops                  = (known after apply)
          + throughput            = (known after apply)
          + volume_size           = 50
          + volume_type           = "gp2"
        }
    }

  # module.active_active.module.vm.aws_security_group.tfe_instance will be created
  + resource "aws_security_group" "tfe_instance" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags_all               = (known after apply)
      + vpc_id                 = (known after apply)
    }

  # module.active_active.module.vm.aws_security_group_rule.tfe_inbound will be created
  + resource "aws_security_group_rule" "tfe_inbound" {
      + from_port                = 0
      + id                       = (known after apply)
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + self                     = true
      + source_security_group_id = (known after apply)
      + to_port                  = 0
      + type                     = "ingress"
    }

  # module.active_active.module.vm.aws_security_group_rule.tfe_outbound will be created
  + resource "aws_security_group_rule" "tfe_outbound" {
      + cidr_blocks              = [
          + "0.0.0.0/0",
        ]
      + from_port                = 0
      + id                       = (known after apply)
      + protocol                 = "-1"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 0
      + type                     = "egress"
    }

  # module.active_active.module.vm.aws_security_group_rule.tfe_ui will be created
  + resource "aws_security_group_rule" "tfe_ui" {
      + cidr_blocks              = (known after apply)
      + from_port                = 443
      + id                       = (known after apply)
      + protocol                 = "tcp"
      + security_group_id        = (known after apply)
      + self                     = false
      + source_security_group_id = (known after apply)
      + to_port                  = 443
      + type                     = "ingress"
    }

  # module.active_active.module.networking[0].module.vpc.aws_default_security_group.this[0] will be created
  + resource "aws_default_security_group" "this" {
      + arn                    = (known after apply)
      + description            = (known after apply)
      + egress                 = (known after apply)
      + id                     = (known after apply)
      + ingress                = (known after apply)
      + name                   = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "tfe-dsg"
        }
      + tags_all               = {
          + "Name" = "tfe-dsg"
        }
      + vpc_id                 = (known after apply)
    }

  # module.active_active.module.networking[0].module.vpc.aws_eip.nat[0] will be created
  + resource "aws_eip" "nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags                 = {
          + "Name" = "tfe-nat-eip"
        }
      + tags_all             = {
          + "Name" = "tfe-nat-eip"
        }
      + vpc                  = true
    }

  # module.active_active.module.networking[0].module.vpc.aws_eip.nat[1] will be created
  + resource "aws_eip" "nat" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags                 = {
          + "Name" = "tfe-nat-eip"
        }
      + tags_all             = {
          + "Name" = "tfe-nat-eip"
        }
      + vpc                  = true
    }

  # module.active_active.module.networking[0].module.vpc.aws_internet_gateway.this[0] will be created
  + resource "aws_internet_gateway" "this" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = {
          + "Name" = "tfe-igw"
        }
      + tags_all = {
          + "Name" = "tfe-igw"
        }
      + vpc_id   = (known after apply)
    }

  # module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[0] will be created
  + resource "aws_nat_gateway" "this" {
      + allocation_id        = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Name" = "tfe-tgw"
        }
      + tags_all             = {
          + "Name" = "tfe-tgw"
        }
    }

  # module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[1] will be created
  + resource "aws_nat_gateway" "this" {
      + allocation_id        = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Name" = "tfe-tgw"
        }
      + tags_all             = {
          + "Name" = "tfe-tgw"
        }
    }

  # module.active_active.module.networking[0].module.vpc.aws_route.private_nat_gateway[0] will be created
  + resource "aws_route" "private_nat_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + nat_gateway_id         = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.active_active.module.networking[0].module.vpc.aws_route.private_nat_gateway[1] will be created
  + resource "aws_route" "private_nat_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + nat_gateway_id         = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.active_active.module.networking[0].module.vpc.aws_route.public_internet_gateway[0] will be created
  + resource "aws_route" "public_internet_gateway" {
      + destination_cidr_block = "0.0.0.0/0"
      + gateway_id             = (known after apply)
      + id                     = (known after apply)
      + instance_id            = (known after apply)
      + instance_owner_id      = (known after apply)
      + network_interface_id   = (known after apply)
      + origin                 = (known after apply)
      + route_table_id         = (known after apply)
      + state                  = (known after apply)

      + timeouts {
          + create = "5m"
        }
    }

  # module.active_active.module.networking[0].module.vpc.aws_route_table.private[0] will be created
  + resource "aws_route_table" "private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Name" = "tfe-rtb-private"
        }
      + tags_all         = {
          + "Name" = "tfe-rtb-private"
        }
      + vpc_id           = (known after apply)
    }

  # module.active_active.module.networking[0].module.vpc.aws_route_table.private[1] will be created
  + resource "aws_route_table" "private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Name" = "tfe-rtb-private"
        }
      + tags_all         = {
          + "Name" = "tfe-rtb-private"
        }
      + vpc_id           = (known after apply)
    }

  # module.active_active.module.networking[0].module.vpc.aws_route_table.public[0] will be created
  + resource "aws_route_table" "public" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = (known after apply)
      + tags             = {
          + "Name" = "tfe-rtb-public"
        }
      + tags_all         = {
          + "Name" = "tfe-rtb-public"
        }
      + vpc_id           = (known after apply)
    }

  # module.active_active.module.networking[0].module.vpc.aws_route_table_association.private[0] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.active_active.module.networking[0].module.vpc.aws_route_table_association.private[1] will be created
  + resource "aws_route_table_association" "private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.active_active.module.networking[0].module.vpc.aws_route_table_association.public[0] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.active_active.module.networking[0].module.vpc.aws_route_table_association.public[1] will be created
  + resource "aws_route_table_association" "public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # module.active_active.module.networking[0].module.vpc.aws_subnet.private[0] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-central-1a"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.32.0/20"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name" = "private"
        }
      + tags_all                                       = {
          + "Name" = "private"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.active_active.module.networking[0].module.vpc.aws_subnet.private[1] will be created
  + resource "aws_subnet" "private" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-central-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.48.0/20"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = false
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name" = "private"
        }
      + tags_all                                       = {
          + "Name" = "private"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.active_active.module.networking[0].module.vpc.aws_subnet.public[0] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-central-1a"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.0.0/20"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = true
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name" = "public"
        }
      + tags_all                                       = {
          + "Name" = "public"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.active_active.module.networking[0].module.vpc.aws_subnet.public[1] will be created
  + resource "aws_subnet" "public" {
      + arn                                            = (known after apply)
      + assign_ipv6_address_on_creation                = false
      + availability_zone                              = "eu-central-1b"
      + availability_zone_id                           = (known after apply)
      + cidr_block                                     = "10.0.16.0/20"
      + enable_dns64                                   = false
      + enable_resource_name_dns_a_record_on_launch    = false
      + enable_resource_name_dns_aaaa_record_on_launch = false
      + id                                             = (known after apply)
      + ipv6_cidr_block_association_id                 = (known after apply)
      + ipv6_native                                    = false
      + map_public_ip_on_launch                        = true
      + owner_id                                       = (known after apply)
      + private_dns_hostname_type_on_launch            = (known after apply)
      + tags                                           = {
          + "Name" = "public"
        }
      + tags_all                                       = {
          + "Name" = "public"
        }
      + vpc_id                                         = (known after apply)
    }

  # module.active_active.module.networking[0].module.vpc.aws_vpc.this[0] will be created
  + resource "aws_vpc" "this" {
      + arn                                  = (known after apply)
      + assign_generated_ipv6_cidr_block     = false
      + cidr_block                           = "10.0.0.0/16"
      + default_network_acl_id               = (known after apply)
      + default_route_table_id               = (known after apply)
      + default_security_group_id            = (known after apply)
      + dhcp_options_id                      = (known after apply)
      + enable_classiclink                   = (known after apply)
      + enable_classiclink_dns_support       = (known after apply)
      + enable_dns_hostnames                 = true
      + enable_dns_support                   = true
      + id                                   = (known after apply)
      + instance_tenancy                     = "default"
      + ipv6_association_id                  = (known after apply)
      + ipv6_cidr_block                      = (known after apply)
      + ipv6_cidr_block_network_border_group = (known after apply)
      + main_route_table_id                  = (known after apply)
      + owner_id                             = (known after apply)
      + tags                                 = {
          + "Name" = "tfe-vpc"
        }
      + tags_all                             = {
          + "Name" = "tfe-vpc"
        }
    }

  # module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2"] will be created
  + resource "aws_vpc_endpoint" "this" {
      + arn                   = (known after apply)
      + cidr_blocks           = (known after apply)
      + dns_entry             = (known after apply)
      + id                    = (known after apply)
      + network_interface_ids = (known after apply)
      + owner_id              = (known after apply)
      + policy                = (known after apply)
      + prefix_list_id        = (known after apply)
      + private_dns_enabled   = true
      + requester_managed     = (known after apply)
      + route_table_ids       = (known after apply)
      + security_group_ids    = (known after apply)
      + service_name          = "com.amazonaws.eu-central-1.ec2"
      + state                 = (known after apply)
      + subnet_ids            = (known after apply)
      + tags_all              = (known after apply)
      + vpc_endpoint_type     = "Interface"
      + vpc_id                = (known after apply)

      + timeouts {
          + create = "10m"
          + delete = "10m"
          + update = "10m"
        }
    }

  # module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2messages"] will be created
  + resource "aws_vpc_endpoint" "this" {
      + arn                   = (known after apply)
      + cidr_blocks           = (known after apply)
      + dns_entry             = (known after apply)
      + id                    = (known after apply)
      + network_interface_ids = (known after apply)
      + owner_id              = (known after apply)
      + policy                = (known after apply)
      + prefix_list_id        = (known after apply)
      + private_dns_enabled   = true
      + requester_managed     = (known after apply)
      + route_table_ids       = (known after apply)
      + security_group_ids    = (known after apply)
      + service_name          = "com.amazonaws.eu-central-1.ec2messages"
      + state                 = (known after apply)
      + subnet_ids            = (known after apply)
      + tags                  = {
          + "Name" = "tfe-ec2messages-vpc-endpoint"
        }
      + tags_all              = {
          + "Name" = "tfe-ec2messages-vpc-endpoint"
        }
      + vpc_endpoint_type     = "Interface"
      + vpc_id                = (known after apply)

      + timeouts {
          + create = "10m"
          + delete = "10m"
          + update = "10m"
        }
    }

  # module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["kms"] will be created
  + resource "aws_vpc_endpoint" "this" {
      + arn                   = (known after apply)
      + cidr_blocks           = (known after apply)
      + dns_entry             = (known after apply)
      + id                    = (known after apply)
      + network_interface_ids = (known after apply)
      + owner_id              = (known after apply)
      + policy                = (known after apply)
      + prefix_list_id        = (known after apply)
      + private_dns_enabled   = true
      + requester_managed     = (known after apply)
      + route_table_ids       = (known after apply)
      + security_group_ids    = (known after apply)
      + service_name          = "com.amazonaws.eu-central-1.kms"
      + state                 = (known after apply)
      + subnet_ids            = (known after apply)
      + tags_all              = (known after apply)
      + vpc_endpoint_type     = "Interface"
      + vpc_id                = (known after apply)

      + timeouts {
          + create = "10m"
          + delete = "10m"
          + update = "10m"
        }
    }

  # module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["s3"] will be created
  + resource "aws_vpc_endpoint" "this" {
      + arn                   = (known after apply)
      + cidr_blocks           = (known after apply)
      + dns_entry             = (known after apply)
      + id                    = (known after apply)
      + network_interface_ids = (known after apply)
      + owner_id              = (known after apply)
      + policy                = (known after apply)
      + prefix_list_id        = (known after apply)
      + private_dns_enabled   = false
      + requester_managed     = (known after apply)
      + route_table_ids       = (known after apply)
      + security_group_ids    = (known after apply)
      + service_name          = "com.amazonaws.eu-central-1.s3"
      + state                 = (known after apply)
      + subnet_ids            = (known after apply)
      + tags                  = {
          + "Name" = "tfe-s3-vpc-endpoint"
        }
      + tags_all              = {
          + "Name" = "tfe-s3-vpc-endpoint"
        }
      + vpc_endpoint_type     = "Gateway"
      + vpc_id                = (known after apply)

      + timeouts {
          + create = "10m"
          + delete = "10m"
          + update = "10m"
        }
    }

  # module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssm"] will be created
  + resource "aws_vpc_endpoint" "this" {
      + arn                   = (known after apply)
      + cidr_blocks           = (known after apply)
      + dns_entry             = (known after apply)
      + id                    = (known after apply)
      + network_interface_ids = (known after apply)
      + owner_id              = (known after apply)
      + policy                = (known after apply)
      + prefix_list_id        = (known after apply)
      + private_dns_enabled   = true
      + requester_managed     = (known after apply)
      + route_table_ids       = (known after apply)
      + security_group_ids    = (known after apply)
      + service_name          = "com.amazonaws.eu-central-1.ssm"
      + state                 = (known after apply)
      + subnet_ids            = (known after apply)
      + tags                  = {
          + "Name" = "tfe-ssm-vpc-endpoint"
        }
      + tags_all              = {
          + "Name" = "tfe-ssm-vpc-endpoint"
        }
      + vpc_endpoint_type     = "Interface"
      + vpc_id                = (known after apply)

      + timeouts {
          + create = "10m"
          + delete = "10m"
          + update = "10m"
        }
    }

  # module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssmmessages"] will be created
  + resource "aws_vpc_endpoint" "this" {
      + arn                   = (known after apply)
      + cidr_blocks           = (known after apply)
      + dns_entry             = (known after apply)
      + id                    = (known after apply)
      + network_interface_ids = (known after apply)
      + owner_id              = (known after apply)
      + policy                = (known after apply)
      + prefix_list_id        = (known after apply)
      + private_dns_enabled   = true
      + requester_managed     = (known after apply)
      + route_table_ids       = (known after apply)
      + security_group_ids    = (known after apply)
      + service_name          = "com.amazonaws.eu-central-1.ssmmessages"
      + state                 = (known after apply)
      + subnet_ids            = (known after apply)
      + tags                  = {
          + "Name" = "tfe-ssmmessages-vpc-endpoint"
        }
      + tags_all              = {
          + "Name" = "tfe-ssmmessages-vpc-endpoint"
        }
      + vpc_endpoint_type     = "Interface"
      + vpc_id                = (known after apply)

      + timeouts {
          + create = "10m"
          + delete = "10m"
          + update = "10m"
        }
    }

Plan: 91 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + active_active          = (sensitive value)
  + health_check_url       = "https://tfe-xx.akulov.cc/_health_check"
  + iact_url               = "https://tfe-xx.akulov.cc/admin/retrieve-iact"
  + initial_admin_user_url = "https://tfe-xx.akulov.cc/admin/initial-admin-user"
  + tfe_url                = "https://tfe-xx.akulov.cc"

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

module.active_active.module.settings.random_id.registry_session_encryption_key: Creating...
module.active_active.module.settings.random_id.install_id: Creating...
module.active_active.module.settings.random_id.cookie_hash: Creating...
module.active_active.module.settings.random_id.internal_api_token: Creating...
module.active_active.module.settings.random_id.registry_session_secret_key: Creating...
module.active_active.module.settings.random_id.user_token: Creating...
module.active_active.module.redis[0].random_id.redis_password[0]: Creating...
random_string.friendly_name: Creating...
module.active_active.module.database[0].random_string.postgresql_password: Creating...
module.active_active.module.settings.random_id.user_token: Creation complete after 0s [id=JJM-7aV5WiPelzVYI6f8dA]
module.active_active.module.redis[0].random_id.redis_password[0]: Creation complete after 0s [id=Yo8KFADOWpEmqR-PQRsyEA]
module.active_active.module.settings.random_id.registry_session_encryption_key: Creation complete after 0s [id=IqmA0KYbnMP-mA84Uvqsjw]
module.active_active.module.settings.random_id.registry_session_secret_key: Creation complete after 0s [id=16uk3BHKKKxkWKnqROhIkQ]
module.active_active.module.settings.random_id.root_secret: Creating...
module.active_active.module.settings.random_id.internal_api_token: Creation complete after 0s [id=QEQzp5VcRQ2igg5mZKwYEQ]
module.active_active.module.settings.random_id.cookie_hash: Creation complete after 0s [id=3FEfRXe1-svPWlIPWRPGjg]
module.active_active.module.settings.random_id.enc_password: Creating...
module.active_active.module.settings.random_string.password: Creating...
module.active_active.module.settings.random_id.archivist_token: Creating...
module.active_active.module.settings.random_id.install_id: Creation complete after 0s [id=Sy6ET0FkSTBcjWTjEbNSZQ]
module.active_active.module.database[0].random_string.postgresql_password: Creation complete after 0s [id=OHaPPXM17JX9MFs8a2xoEU7p7PPGU6Pp9CGNXb58xwIHIvPIflUeyFV1MQTNWvzyOi2qRfKTgPCX5MSsrzuWVHQr9DCG2Ro9ZwEV3EIWP8CBkw1zwbIIpWJDCOzZtE17]
module.active_active.module.settings.random_id.root_secret: Creation complete after 0s [id=kPr_BiwMdfm0tUAEjzAGmg]
module.active_active.module.settings.random_id.enc_password: Creation complete after 0s [id=VOgBP94OAEwpZqO9tBcJaA]
random_string.friendly_name: Creation complete after 0s [id=gglo]
module.active_active.module.settings.random_string.password: Creation complete after 0s [id=5j396IF9u7QiMfLv]
module.active_active.module.settings.random_id.archivist_token: Creation complete after 0s [id=bddyWWV9l2yB8UYn3CGbXQ]
module.kms.aws_kms_key.main: Creating...
aws_secretsmanager_secret.vm_key: Creating...
module.active_active.module.networking[0].module.vpc.aws_vpc.this[0]: Creating...
aws_secretsmanager_secret.vm_cert: Creating...
aws_secretsmanager_secret.license: Creating...
module.active_active.module.service_accounts.aws_iam_role.instance_role: Creating...
aws_acm_certificate.aws12: Creating...
module.active_active.module.networking[0].module.vpc.aws_eip.nat[1]: Creating...
module.active_active.module.networking[0].module.vpc.aws_eip.nat[0]: Creating...
aws_secretsmanager_secret.vm_key: Creation complete after 1s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:gglo-key-aFxHtM]
aws_secretsmanager_secret.vm_cert: Creation complete after 1s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:gglo-cert-PXAUPU]
aws_secretsmanager_secret.license: Creation complete after 1s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:gglo-license-aFxHtM]
aws_secretsmanager_secret_version.vm_key: Creating...
aws_secretsmanager_secret_version.vm_cert: Creating...
aws_secretsmanager_secret_version.license: Creating...
module.kms.aws_kms_key.main: Creation complete after 1s [id=b7c9bfdf-1096-4e77-af60-ce2a50ac5889]
module.active_active.data.aws_kms_key.main: Reading...
module.kms.aws_kms_alias.main: Creating...
aws_secretsmanager_secret_version.vm_key: Creation complete after 0s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:gglo-key-aFxHtM|FA9B05BA-CD49-4D46-911B-A79746DD0205]
module.active_active.module.networking[0].module.vpc.aws_eip.nat[0]: Creation complete after 1s [id=eipalloc-05c5278421e47c7c4]
aws_secretsmanager_secret_version.vm_cert: Creation complete after 0s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:gglo-cert-PXAUPU|51D9B437-B2ED-4785-9125-D8369A783F70]
module.active_active.module.networking[0].module.vpc.aws_eip.nat[1]: Creation complete after 1s [id=eipalloc-03aa3af8245013dec]
module.active_active.data.aws_kms_key.main: Read complete after 0s [id=b7c9bfdf-1096-4e77-af60-ce2a50ac5889]
aws_secretsmanager_secret_version.license: Creation complete after 1s [id=arn:aws:secretsmanager:eu-central-1:267023797923:secret:gglo-license-aFxHtM|5F8A6144-E5A3-4EBE-88A3-658522FB0750]
module.active_active.module.service_accounts.data.aws_iam_policy_document.secretsmanager: Reading...
module.active_active.module.service_accounts.aws_iam_policy.kms_policy: Creating...
module.active_active.module.service_accounts.data.aws_iam_policy_document.secretsmanager: Read complete after 0s [id=1598946984]
module.active_active.module.object_storage[0].aws_s3_bucket.tfe_data_bucket: Creating...
aws_acm_certificate.aws12: Creation complete after 2s [id=arn:aws:acm:eu-central-1:267023797923:certificate/7ea77304-0347-45fb-813c-1d0eb99bba95]
module.kms.aws_kms_alias.main: Creation complete after 1s [id=alias/gglo-key]
module.active_active.module.service_accounts.aws_iam_policy.kms_policy: Creation complete after 1s [id=arn:aws:iam::267023797923:policy/gglo-key]
module.active_active.module.service_accounts.aws_iam_role.instance_role: Creation complete after 4s [id=gglo-tfe20220804085812439200000001]
module.active_active.module.service_accounts.aws_iam_role_policy_attachment.misc["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]: Creating...
module.active_active.module.service_accounts.aws_iam_role_policy_attachment.kms_policy: Creating...
module.active_active.module.service_accounts.aws_iam_role_policy_attachment.misc["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]: Creating...
module.active_active.module.service_accounts.aws_iam_role_policy.secretsmanager[0]: Creating...
module.active_active.module.service_accounts.aws_iam_instance_profile.tfe: Creating...
module.active_active.module.service_accounts.aws_iam_role_policy.tfe_asg_discovery: Creating...
module.active_active.module.service_accounts.aws_iam_role_policy.secretsmanager[0]: Creation complete after 1s [id=gglo-tfe20220804085812439200000001:gglo-tfe-secretsmanager]
module.active_active.module.service_accounts.aws_iam_role_policy_attachment.misc["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]: Creation complete after 1s [id=gglo-tfe20220804085812439200000001-20220804085816441600000005]
module.active_active.module.service_accounts.aws_iam_role_policy.tfe_asg_discovery: Creation complete after 1s [id=gglo-tfe20220804085812439200000001:gglo-tfe-asg-discovery]
module.active_active.module.service_accounts.aws_iam_role_policy_attachment.kms_policy: Creation complete after 1s [id=gglo-tfe20220804085812439200000001-20220804085816440700000004]
module.active_active.module.service_accounts.aws_iam_role_policy_attachment.misc["arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"]: Creation complete after 1s [id=gglo-tfe20220804085812439200000001-20220804085816440500000003]
module.active_active.module.object_storage[0].aws_s3_bucket.tfe_data_bucket: Creation complete after 3s [id=gglo-tfe-data]
module.active_active.module.object_storage[0].aws_s3_bucket_public_access_block.tfe_data: Creating...
module.active_active.module.object_storage[0].data.aws_iam_policy_document.tfe_data: Reading...
module.active_active.module.object_storage[0].data.aws_iam_policy_document.tfe_data: Read complete after 0s [id=1527455931]
module.active_active.module.service_accounts.aws_iam_instance_profile.tfe: Creation complete after 2s [id=gglo-tfe20220804085815985400000002]
module.active_active.module.object_storage[0].aws_s3_bucket_public_access_block.tfe_data: Creation complete after 1s [id=gglo-tfe-data]
module.active_active.module.object_storage[0].aws_s3_bucket_policy.tfe_data: Creating...
module.active_active.module.networking[0].module.vpc.aws_vpc.this[0]: Still creating... [10s elapsed]
module.active_active.module.networking[0].module.vpc.aws_vpc.this[0]: Creation complete after 14s [id=vpc-0890cd594095bf425]
module.active_active.module.networking[0].module.vpc.aws_internet_gateway.this[0]: Creating...
module.active_active.module.networking[0].module.vpc.aws_route_table.private[1]: Creating...
module.active_active.module.networking[0].module.vpc.aws_route_table.private[0]: Creating...
module.active_active.module.networking[0].module.vpc.aws_route_table.public[0]: Creating...
module.active_active.module.networking[0].module.vpc.aws_subnet.public[0]: Creating...
module.active_active.module.networking[0].module.vpc.aws_subnet.public[1]: Creating...
module.active_active.module.networking[0].module.vpc.aws_default_security_group.this[0]: Creating...
module.active_active.module.networking[0].module.vpc.aws_subnet.private[1]: Creating...
module.active_active.module.networking[0].module.vpc.aws_subnet.private[0]: Creating...
module.active_active.module.networking[0].module.vpc.aws_route_table.private[1]: Creation complete after 1s [id=rtb-05d8e1acca4966223]
module.active_active.module.networking[0].module.vpc.aws_route_table.public[0]: Creation complete after 1s [id=rtb-00f14f75ffdf4bf65]
module.active_active.module.networking[0].module.vpc.aws_route_table.private[0]: Creation complete after 1s [id=rtb-00251c914cd4b9ab3]
module.active_active.module.networking[0].module.vpc.aws_subnet.private[1]: Creation complete after 1s [id=subnet-0b400b224cfcb7040]
module.active_active.module.redis[0].aws_security_group.redis[0]: Creating...
module.active_active.module.vm.aws_security_group.tfe_instance: Creating...
module.active_active.module.load_balancer[0].aws_security_group.tfe_outbound_allow: Creating...
module.active_active.module.load_balancer[0].aws_security_group.tfe_lb_allow: Creating...
module.active_active.module.object_storage[0].aws_s3_bucket_policy.tfe_data: Creation complete after 9s [id=gglo-tfe-data]
module.active_active.module.networking[0].module.vpc.aws_internet_gateway.this[0]: Creation complete after 1s [id=igw-079208a9091a08ecd]
module.active_active.module.database[0].aws_security_group.postgresql: Creating...
module.active_active.module.load_balancer[0].aws_lb_target_group.tfe_tg_443: Creating...
module.active_active.module.networking[0].module.vpc.aws_subnet.private[0]: Creation complete after 1s [id=subnet-0fb3a5207f4098c10]
module.active_active.module.networking[0].module.vpc.aws_route.public_internet_gateway[0]: Creating...
module.active_active.module.networking[0].module.vpc.aws_default_security_group.this[0]: Creation complete after 2s [id=sg-0a7274650812651dc]
module.active_active.module.networking[0].module.vpc.aws_route_table_association.private[0]: Creating...
module.active_active.module.networking[0].module.vpc.aws_route.public_internet_gateway[0]: Creation complete after 1s [id=r-rtb-00f14f75ffdf4bf651080289494]
module.active_active.module.networking[0].module.vpc.aws_route_table_association.private[1]: Creating...
module.active_active.module.load_balancer[0].aws_lb_target_group.tfe_tg_443: Creation complete after 1s [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:targetgroup/gglo-tfe-alb-tg-443/453622e7d8552710]
module.active_active.module.networking[0].aws_security_group.ssm: Creating...
module.active_active.module.networking[0].module.vpc.aws_route_table_association.private[0]: Creation complete after 0s [id=rtbassoc-066141479aca0676e]
module.active_active.module.redis[0].aws_elasticache_subnet_group.tfe[0]: Creating...
module.active_active.module.load_balancer[0].aws_security_group.tfe_outbound_allow: Creation complete after 1s [id=sg-0c73043db1cc54baf]
module.active_active.module.database[0].aws_db_subnet_group.tfe: Creating...
module.active_active.module.load_balancer[0].aws_security_group.tfe_lb_allow: Creation complete after 2s [id=sg-08eb6b0c438aa6db8]
module.active_active.module.vm.aws_security_group.tfe_instance: Creation complete after 2s [id=sg-08e4e09b7c39a0185]
module.active_active.module.redis[0].aws_security_group.redis[0]: Creation complete after 2s [id=sg-09fe0e9f0d6988710]
module.active_active.module.load_balancer[0].aws_security_group_rule.tfe_outbound_allow_all: Creating...
module.active_active.module.load_balancer[0].aws_security_group_rule.tfe_lb_allow_inbound_http: Creating...
module.active_active.module.load_balancer[0].aws_security_group_rule.tfe_lb_allow_inbound_https: Creating...
module.active_active.module.networking[0].module.vpc.aws_route_table_association.private[1]: Creation complete after 1s [id=rtbassoc-0fb57380cd733ff13]
module.active_active.module.database[0].aws_security_group.postgresql: Creation complete after 2s [id=sg-0f16f48e00a70421b]
module.active_active.module.vm.aws_security_group_rule.tfe_outbound: Creating...
module.active_active.module.vm.aws_security_group_rule.tfe_inbound: Creating...
module.active_active.module.load_balancer[0].aws_security_group_rule.tfe_outbound_allow_all: Creation complete after 0s [id=sgrule-1749606187]
module.active_active.module.redis[0].aws_security_group_rule.redis_ingress[0]: Creating...
module.active_active.module.load_balancer[0].aws_security_group_rule.tfe_lb_allow_inbound_http: Creation complete after 0s [id=sgrule-294504142]
module.active_active.module.redis[0].aws_security_group_rule.redis_egress[0]: Creating...
module.active_active.module.redis[0].aws_elasticache_subnet_group.tfe[0]: Creation complete after 2s [id=gglo-tfe-redis]
module.active_active.module.database[0].aws_security_group_rule.postgresql_ingress: Creating...
module.active_active.module.vm.aws_security_group_rule.tfe_outbound: Creation complete after 1s [id=sgrule-2710359646]
module.active_active.module.database[0].aws_security_group_rule.postgresql_egress: Creating...
module.active_active.module.database[0].aws_db_subnet_group.tfe: Creation complete after 1s [id=gglo]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Creating...
module.active_active.module.networking[0].aws_security_group.ssm: Creation complete after 2s [id=sg-0be55ff30560d6e8c]
module.active_active.module.database[0].aws_db_instance.postgresql: Creating...
module.active_active.module.redis[0].aws_security_group_rule.redis_ingress[0]: Creation complete after 1s [id=sgrule-1580687111]
module.active_active.module.load_balancer[0].aws_security_group_rule.tfe_lb_allow_inbound_https: Creation complete after 1s [id=sgrule-2170416698]
module.active_active.module.database[0].aws_security_group_rule.postgresql_tfe_ingress: Creating...
module.active_active.module.vm.aws_security_group_rule.tfe_ui: Creating...
module.active_active.module.vm.aws_security_group_rule.tfe_inbound: Creation complete after 1s [id=sgrule-1297045457]
module.active_active.module.database[0].aws_security_group_rule.postgresql_ingress: Creation complete after 1s [id=sgrule-2784312599]
module.active_active.module.database[0].aws_security_group_rule.postgresql_tfe_egress: Creating...
module.active_active.module.redis[0].aws_security_group_rule.redis_tfe_egress[0]: Creating...
module.active_active.module.redis[0].aws_security_group_rule.redis_egress[0]: Creation complete after 2s [id=sgrule-1473340436]
module.active_active.module.redis[0].aws_security_group_rule.redis_tfe_ingress[0]: Creating...
module.active_active.module.vm.aws_security_group_rule.tfe_ui: Creation complete after 1s [id=sgrule-3383170564]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssmmessages"]: Creating...
module.active_active.module.database[0].aws_security_group_rule.postgresql_egress: Creation complete after 1s [id=sgrule-1107235147]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["kms"]: Creating...
module.active_active.module.redis[0].aws_security_group_rule.redis_tfe_egress[0]: Creation complete after 0s [id=sgrule-239199689]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2"]: Creating...
module.active_active.module.database[0].aws_security_group_rule.postgresql_tfe_ingress: Creation complete after 2s [id=sgrule-1218020503]
module.active_active.module.redis[0].aws_security_group_rule.redis_tfe_ingress[0]: Creation complete after 1s [id=sgrule-2803335386]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2messages"]: Creating...
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["s3"]: Creating...
module.active_active.module.database[0].aws_security_group_rule.postgresql_tfe_egress: Creation complete after 2s [id=sgrule-3512381704]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssm"]: Creating...
module.active_active.module.networking[0].module.vpc.aws_subnet.public[0]: Still creating... [10s elapsed]
module.active_active.module.networking[0].module.vpc.aws_subnet.public[1]: Still creating... [10s elapsed]
module.active_active.module.networking[0].module.vpc.aws_subnet.public[0]: Creation complete after 11s [id=subnet-0264d442cecf54402]
module.active_active.module.networking[0].module.vpc.aws_subnet.public[1]: Creation complete after 11s [id=subnet-08f0fa3c00fbc3dd6]
module.active_active.module.networking[0].module.vpc.aws_route_table_association.public[1]: Creating...
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[1]: Creating...
module.active_active.module.networking[0].module.vpc.aws_route_table_association.public[1]: Creation complete after 1s [id=rtbassoc-0b4ecfb383c395e6f]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["s3"]: Creation complete after 6s [id=vpce-0dd7a1b9a05c7a38e]
module.active_active.module.networking[0].module.vpc.aws_route_table_association.public[0]: Creating...
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[0]: Creating...
module.active_active.module.networking[0].module.vpc.aws_route_table_association.public[0]: Creation complete after 0s [id=rtbassoc-0883f26edc4acb933]
module.active_active.module.load_balancer[0].aws_lb.tfe_lb: Creating...
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [10s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [10s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssmmessages"]: Still creating... [10s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["kms"]: Still creating... [10s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2"]: Still creating... [10s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2messages"]: Still creating... [10s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssm"]: Still creating... [10s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[1]: Still creating... [10s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[0]: Still creating... [10s elapsed]
module.active_active.module.load_balancer[0].aws_lb.tfe_lb: Still creating... [10s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [20s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [20s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssmmessages"]: Still creating... [20s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["kms"]: Still creating... [20s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2"]: Still creating... [20s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2messages"]: Still creating... [20s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssm"]: Still creating... [20s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[1]: Still creating... [20s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[0]: Still creating... [20s elapsed]
module.active_active.module.load_balancer[0].aws_lb.tfe_lb: Still creating... [20s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [30s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [30s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssmmessages"]: Still creating... [30s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["kms"]: Still creating... [30s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2"]: Still creating... [30s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2messages"]: Still creating... [30s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssm"]: Still creating... [30s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[1]: Still creating... [31s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[0]: Still creating... [30s elapsed]
module.active_active.module.load_balancer[0].aws_lb.tfe_lb: Still creating... [30s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [40s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [40s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssmmessages"]: Still creating... [40s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["kms"]: Still creating... [40s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2"]: Still creating... [40s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2messages"]: Still creating... [40s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssm"]: Still creating... [40s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[1]: Still creating... [41s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[0]: Still creating... [40s elapsed]
module.active_active.module.load_balancer[0].aws_lb.tfe_lb: Still creating... [40s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [50s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [50s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssmmessages"]: Still creating... [50s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["kms"]: Still creating... [50s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2"]: Still creating... [50s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2messages"]: Still creating... [50s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssm"]: Still creating... [50s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[1]: Still creating... [51s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[0]: Still creating... [50s elapsed]
module.active_active.module.load_balancer[0].aws_lb.tfe_lb: Still creating... [50s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [1m0s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [1m0s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssmmessages"]: Still creating... [1m0s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["kms"]: Still creating... [1m0s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2"]: Still creating... [1m0s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2messages"]: Still creating... [1m0s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssm"]: Still creating... [1m0s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[1]: Still creating... [1m1s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[0]: Still creating... [1m0s elapsed]
module.active_active.module.load_balancer[0].aws_lb.tfe_lb: Still creating... [1m0s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [1m10s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [1m10s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssmmessages"]: Still creating... [1m10s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["kms"]: Still creating... [1m10s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2"]: Still creating... [1m10s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2messages"]: Still creating... [1m10s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssm"]: Still creating... [1m10s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[1]: Still creating... [1m11s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[0]: Still creating... [1m10s elapsed]
module.active_active.module.load_balancer[0].aws_lb.tfe_lb: Still creating... [1m10s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [1m20s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [1m20s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssmmessages"]: Still creating... [1m20s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["kms"]: Still creating... [1m20s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2"]: Still creating... [1m20s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2messages"]: Still creating... [1m20s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssm"]: Still creating... [1m20s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[1]: Still creating... [1m21s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[0]: Still creating... [1m20s elapsed]
module.active_active.module.load_balancer[0].aws_lb.tfe_lb: Still creating... [1m20s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [1m30s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [1m30s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssmmessages"]: Still creating... [1m30s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["kms"]: Still creating... [1m30s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2"]: Still creating... [1m30s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2messages"]: Still creating... [1m30s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssm"]: Still creating... [1m30s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2"]: Creation complete after 1m33s [id=vpce-0a3d8f2f3e5fad236]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ec2messages"]: Creation complete after 1m35s [id=vpce-057b4ca69b384d084]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[1]: Still creating... [1m31s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssm"]: Creation complete after 1m35s [id=vpce-08ea2210934b08396]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[0]: Still creating... [1m30s elapsed]
module.active_active.module.load_balancer[0].aws_lb.tfe_lb: Still creating... [1m30s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [1m40s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [1m40s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssmmessages"]: Still creating... [1m40s elapsed]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["kms"]: Still creating... [1m40s elapsed]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[1]: Creation complete after 1m37s [id=nat-002ab8ca49ffcee6a]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["kms"]: Creation complete after 1m44s [id=vpce-0063e3c9de329db42]
module.active_active.module.networking[0].module.vpc_endpoints.aws_vpc_endpoint.this["ssmmessages"]: Creation complete after 1m44s [id=vpce-05684ebc82a35118d]
module.active_active.module.networking[0].module.vpc.aws_nat_gateway.this[0]: Creation complete after 1m36s [id=nat-05c3dc116d3fcc5f6]
module.active_active.module.networking[0].module.vpc.aws_route.private_nat_gateway[1]: Creating...
module.active_active.module.networking[0].module.vpc.aws_route.private_nat_gateway[0]: Creating...
module.active_active.module.networking[0].module.vpc.aws_route.private_nat_gateway[1]: Creation complete after 1s [id=r-rtb-05d8e1acca49662231080289494]
module.active_active.module.networking[0].module.vpc.aws_route.private_nat_gateway[0]: Creation complete after 1s [id=r-rtb-00251c914cd4b9ab31080289494]
module.active_active.module.load_balancer[0].aws_lb.tfe_lb: Still creating... [1m40s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [1m50s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [1m50s elapsed]
module.active_active.module.load_balancer[0].aws_lb.tfe_lb: Still creating... [1m50s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [2m0s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [2m0s elapsed]
module.active_active.module.load_balancer[0].aws_lb.tfe_lb: Creation complete after 1m54s [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:loadbalancer/app/gglo-tfe-web-alb/364a13b0c7fb9bd9]
module.active_active.module.load_balancer[0].aws_route53_record.tfe: Creating...
module.active_active.module.load_balancer[0].aws_lb_listener.tfe_listener_443: Creating...
module.active_active.module.load_balancer[0].aws_lb_listener.tfe_listener_80: Creating...
module.active_active.module.load_balancer[0].aws_lb_listener.tfe_listener_80: Creation complete after 0s [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:listener/app/gglo-tfe-web-alb/364a13b0c7fb9bd9/81491e0b1632f15e]
module.active_active.module.load_balancer[0].aws_lb_listener.tfe_listener_443: Creation complete after 0s [id=arn:aws:elasticloadbalancing:eu-central-1:267023797923:listener/app/gglo-tfe-web-alb/364a13b0c7fb9bd9/6b6466c9440d38c3]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [2m10s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [2m10s elapsed]
module.active_active.module.load_balancer[0].aws_route53_record.tfe: Still creating... [10s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [2m20s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [2m20s elapsed]
module.active_active.module.load_balancer[0].aws_route53_record.tfe: Still creating... [20s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [2m30s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [2m30s elapsed]
module.active_active.module.load_balancer[0].aws_route53_record.tfe: Still creating... [30s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [2m40s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [2m40s elapsed]
module.active_active.module.load_balancer[0].aws_route53_record.tfe: Still creating... [40s elapsed]
module.active_active.module.load_balancer[0].aws_route53_record.tfe: Creation complete after 42s [id=Z09465023NE5ESR8G9LQD_tfe-xx.akulov.cc_A]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [2m50s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [2m50s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [3m0s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [3m0s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [3m10s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [3m10s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [3m20s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [3m20s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [3m30s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [3m30s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [3m40s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [3m40s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [3m50s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [3m50s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [4m0s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [4m0s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [4m10s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [4m10s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [4m20s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [4m20s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [4m30s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [4m30s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [4m40s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [4m40s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [4m50s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [4m50s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [5m0s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [5m0s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [5m10s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [5m10s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [5m20s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [5m20s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [5m30s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [5m30s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [5m40s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [5m40s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [5m50s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [5m50s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [6m0s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [6m0s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [6m10s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [6m10s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [6m20s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [6m20s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [6m30s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [6m30s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [6m40s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [6m40s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [6m50s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [6m50s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Still creating... [7m0s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [7m0s elapsed]
module.active_active.module.redis[0].aws_elasticache_replication_group.redis[0]: Creation complete after 7m0s [id=gglo-tfe]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [7m10s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [7m20s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [7m30s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [7m40s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [7m50s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [8m0s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [8m10s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [8m20s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [8m30s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [8m40s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [8m50s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [9m0s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [9m10s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [9m20s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Still creating... [9m30s elapsed]
module.active_active.module.database[0].aws_db_instance.postgresql: Creation complete after 9m37s [id=gglo-tfe20220804085830201900000006]
module.active_active.module.vm.aws_launch_configuration.tfe: Creating...
module.active_active.module.vm.aws_launch_configuration.tfe: Creation complete after 2s [id=gglo-tfe-ec2-asg-lt-20220804090807259100000007]
module.active_active.module.vm.aws_autoscaling_group.tfe_asg: Creating...
module.active_active.module.vm.aws_autoscaling_group.tfe_asg: Still creating... [10s elapsed]
module.active_active.module.vm.aws_autoscaling_group.tfe_asg: Still creating... [20s elapsed]
module.active_active.module.vm.aws_autoscaling_group.tfe_asg: Creation complete after 29s [id=gglo-tfe-asg]

Apply complete! Resources: 91 added, 0 changed, 0 destroyed.

Outputs:

active_active = <sensitive>
health_check_url = "https://tfe-xx.akulov.cc/_health_check"
iact_url = "https://tfe-xx.akulov.cc/admin/retrieve-iact"
initial_admin_user_url = "https://tfe-xx.akulov.cc/admin/initial-admin-user"
tfe_url = "https://tfe-xx.akulov.cc"
aakulov@aakulov-C02F20PGMD6R tfe-aws-activeactive-usingmodule % terraform output
active_active = <sensitive>
health_check_url = "https://tfe-xx.akulov.cc/_health_check"
iact_url = "https://tfe-xx.akulov.cc/admin/retrieve-iact"
initial_admin_user_url = "https://tfe-xx.akulov.cc/admin/initial-admin-user"
tfe_url = "https://tfe-xx.akulov.cc"
```

### Connect to the instances

- Find instance id in the AWS Console

- Connect to the instance ssh session using AWS SSM

```bash
aws ssm start-session --target i-Instance_ID_here
```

### Check outputs

- Run `terraform output -json active_active | jq "."`

- Expected result:

```bash
% terraform output -json active_active | jq "."
{
  "dns_configuration_notice": "If you are using external DNS, please make sure to create a DNS record using the load_balancer_address output that has been provided",
  "health_check_url": "https://tfe-xx.akulov.cc/_health_check",
  "key": "b7c9bfdf-1096-4e77-af60-636dfddfd",
  "load_balancer_address": "gglo-tfe-web-alb-7876553.eu-central-1.elb.amazonaws.com",
  "login_url": "https://tfe-xx.akulov.cc/admin/account/new?token=xxxxxxxxxxxxx",
  "network_id": "vpc-0890cd594095bf425",
  "network_private_subnet_cidrs": [
    "10.0.32.0/20",
    "10.0.48.0/20"
  ],
  "private_subnet_ids": [
    "subnet-0fb3a5207f4098c10",
    "subnet-0b400b224cfcb7040"
  ],
  "public_subnet_ids": [
    "subnet-0264d442cecf54402",
    "subnet-08f0fa3c00fbc3dd6"
  ],
  "replicated_console_url": "https://tfe-xx.akulov.cc:8800/",
  "replicated_dashboard_password": "xxxxxxxxxxx",
  "tfe_autoscaling_group": {
    "arn": "arn:aws:autoscaling:eu-central-1:267023797923:autoScalingGroup:71e6dc51-43dd-4282-b295-801d867a3de1:autoScalingGroupName/gglo-tfe-asg",
    "availability_zones": [
      "eu-central-1a",
      "eu-central-1b"
    ],
    "capacity_rebalance": false,
    "default_cooldown": 300,
    "desired_capacity": 2,
    "enabled_metrics": null,
    "force_delete": false,
    "force_delete_warm_pool": false,
    "health_check_grace_period": 1500,
    "health_check_type": "ELB",
    "id": "gglo-tfe-asg",
    "initial_lifecycle_hook": [],
    "instance_refresh": [],
    "launch_configuration": "gglo-tfe-ec2-asg-lt-20220804090807259100000007",
    "launch_template": [],
    "load_balancers": null,
    "max_instance_lifetime": 0,
    "max_size": 2,
    "metrics_granularity": "1Minute",
    "min_elb_capacity": null,
    "min_size": 2,
    "mixed_instances_policy": [],
    "name": "gglo-tfe-asg",
    "name_prefix": "",
    "placement_group": "",
    "protect_from_scale_in": false,
    "service_linked_role_arn": "arn:aws:iam::267023797923:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling",
    "suspended_processes": null,
    "tag": [],
    "tags": [
      {
        "key": "Name",
        "propagate_at_launch": "true",
        "value": "gglo-tfe"
      }
    ],
    "target_group_arns": [
      "arn:aws:elasticloadbalancing:eu-central-1:267023797923:targetgroup/gglo-tfe-alb-tg-443/453622e7d8552710"
    ],
    "termination_policies": null,
    "timeouts": null,
    "vpc_zone_identifier": [
      "subnet-0b400b224cfcb7040",
      "subnet-0fb3a5207f4098c10"
    ],
    "wait_for_capacity_timeout": "10m",
    "wait_for_elb_capacity": null,
    "warm_pool": []
  },
  "tfe_instance_sg": "sg-08e4e09b7c39a0185",
  "tfe_url": "https://tfe-xx.akulov.cc"
```
