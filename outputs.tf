output "active_active" {
  value       = module.active_active
  description = "The output of all the public_active_active module."
  sensitive   = true
}

output "tfe_url" {
  value       = module.active_active.tfe_url
  description = "The URL to the TFE application."
}

output "health_check_url" {
  value       = "${module.active_active.tfe_url}/_health_check"
  description = "The URL with path to access the TFE instance health check."
}

output "iact_url" {
  value       = "${module.active_active.tfe_url}/admin/retrieve-iact"
  description = "The URL with path to access the TFE instance Retrieve IACT."
}

output "initial_admin_user_url" {
  value       = "${module.active_active.tfe_url}/admin/initial-admin-user"
  description = "The URL with path to access the TFE instance Initial Admin User."
}
