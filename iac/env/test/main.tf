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
  source = "git::https://github.com/revanite-io/pvtr-terraform.git//modules/pvtr-azure-blob-storage?ref=9f8ca38296b4ad4b264b997ff6427285ca7aafdb" # v0.1.0

  location             = var.location
  resource_group_name  = var.resource_group_name
  storage_account_name = var.storage_account_name
  allowed_ips          = var.allowed_ips
  immutability_state   = var.immutability_state
  allowed_locations    = var.allowed_locations
  tags                 = var.tags
}
