variable "ssl_cert_path" {
  type        = string
  description = "SSL certificate file path"
}
variable "ssl_key_path" {
  type        = string
  description = "SSL key file path"
}
variable "ssl_chain_path" {
  type        = string
  description = "SSL chain file path"
}
variable "ssl_fullchain_cert_path" {
  type        = string
  description = "SSL fullchain cert file path"
}
variable "domain_name" {
  type        = string
  description = "Cloudflare domain name"
}
variable "tfe_license_path" {
  type        = string
  description = "TFE license path"
}
variable "distribution" {
  type = string
}
variable "tfe_subdomain" {
  type        = string
  description = "Subdomain name for TFE"
}
variable "tags" {
  type        = string
  description = "Tags for ASG"
}
variable "vm_cert_path" {
  type        = string
  description = "VM certificate path"
}
variable "vm_key_path" {
  type        = string
  description = "VM key path"
}
