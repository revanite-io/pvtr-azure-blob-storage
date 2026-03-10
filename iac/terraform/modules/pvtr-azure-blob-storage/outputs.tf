output "storage_account_resource_id" {
  description = "Full resource ID of the storage account (for plugin config)"
  value       = azurerm_storage_account.this.id
}

output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.this.name
}

output "storage_account_name" {
  description = "Name of the storage account"
  value       = azurerm_storage_account.this.name
}

output "log_analytics_workspace_id" {
  description = "Resource ID of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.this.id
}

output "key_vault_name" {
  description = "Name of the Key Vault used for CMEK"
  value       = azurerm_key_vault.this.name
}
