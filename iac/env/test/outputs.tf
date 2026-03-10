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
