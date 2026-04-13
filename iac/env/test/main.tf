terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  subscription_id                 = var.subscription_id
  resource_provider_registrations = "none"
  storage_use_azuread             = true
  features {}
}

provider "azuread" {}

data "azuread_client_config" "current" {}

# Service principal for plugin authentication
resource "azuread_application" "plugin" {
  display_name = "pvtr-abs-test-sp"
  owners       = [data.azuread_client_config.current.object_id]
}

resource "azuread_service_principal" "plugin" {
  client_id = azuread_application.plugin.client_id
  owners    = [data.azuread_client_config.current.object_id]
}

resource "azuread_service_principal_password" "plugin" {
  service_principal_id = azuread_service_principal.plugin.id
  end_date             = timeadd(plantimestamp(), "8760h") # 1 year
}

# Reader on the resource group (covers storage, diagnostics, policy reads)
resource "azurerm_role_assignment" "plugin_reader" {
  scope                = "/subscriptions/${var.subscription_id}/resourceGroups/${module.pvtr_azure_blob_storage.resource_group_name}"
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.plugin.object_id
}

# Security Reader on the subscription (covers Defender for Storage reads)
resource "azurerm_role_assignment" "plugin_security_reader" {
  scope                = "/subscriptions/${var.subscription_id}"
  role_definition_name = "Security Reader"
  principal_id         = azuread_service_principal.plugin.object_id
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
