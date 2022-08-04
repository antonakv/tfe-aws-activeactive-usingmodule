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

```

- Run the `terraform apply`

Expected result

```bash
$ terraform apply


```

### Connect to the instances

- Find instance id in the AWS Console

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
  "login_url": "https://tfe12.akulov.cc/admin/account/new?token=xxxxxxxxxxxxx",
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
