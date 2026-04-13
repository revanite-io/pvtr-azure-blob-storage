output "storage_account_resource_id" {
  description = "Full resource ID for the plugin's storageaccountresourceid config"
  value       = module.pvtr_azure_blob_storage.storage_account_resource_id
}

output "resource_group_name" {
  value = module.pvtr_azure_blob_storage.resource_group_name
}

output "storage_account_name" {
  value = module.pvtr_azure_blob_storage.storage_account_name
}

output "plugin_client_id" {
  description = "Application (client) ID for plugin service principal"
  value       = azuread_application.plugin.client_id
}

output "plugin_tenant_id" {
  description = "Azure AD tenant ID"
  value       = data.azuread_client_config.current.tenant_id
}

output "plugin_client_secret" {
  description = "Client secret for plugin service principal"
  value       = azuread_service_principal_password.plugin.value
  sensitive   = true
}
