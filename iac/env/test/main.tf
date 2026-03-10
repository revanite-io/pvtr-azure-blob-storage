terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}

provider "azurerm" {
  subscription_id                 = var.subscription_id
  resource_provider_registrations = "none"
  storage_use_azuread             = true
  features {}
}

module "pvtr_azure_blob_storage" {
  source = "../../terraform/modules/pvtr-azure-blob-storage"

  location             = var.location
  resource_group_name  = var.resource_group_name
  storage_account_name = var.storage_account_name
  allowed_ips          = var.allowed_ips
  immutability_state   = var.immutability_state
  allowed_locations    = var.allowed_locations
  tags                 = var.tags
}
