data "azurerm_client_config" "current" {}

locals {
  storage_account_name = var.storage_account_name != "" ? var.storage_account_name : "pvtrabs${random_string.suffix.result}"
  allowed_locations    = length(var.allowed_locations) > 0 ? var.allowed_locations : [var.location]
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
  numeric = true
}

# -----------------------------------------------------------------------------
# Resource Group
# -----------------------------------------------------------------------------

resource "azurerm_resource_group" "this" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

# -----------------------------------------------------------------------------
# User-Assigned Managed Identity (for CMEK)
# -----------------------------------------------------------------------------

resource "azurerm_user_assigned_identity" "this" {
  name                = "${local.storage_account_name}-identity"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  tags                = var.tags
}

# -----------------------------------------------------------------------------
# Key Vault + Key (for CMEK)
# -----------------------------------------------------------------------------

resource "azurerm_key_vault" "this" {
  name                       = "kv-${local.storage_account_name}"
  resource_group_name        = azurerm_resource_group.this.name
  location                   = azurerm_resource_group.this.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = true
  soft_delete_retention_days = 7
  tags                       = var.tags

  # Grant the deployer key management permissions
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    key_permissions = [
      "Create",
      "Delete",
      "Get",
      "List",
      "Purge",
      "Recover",
      "UnwrapKey",
      "WrapKey",
      "GetRotationPolicy",
      "SetRotationPolicy",
    ]
  }

  # Grant the managed identity permissions for CMEK
  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = azurerm_user_assigned_identity.this.principal_id

    key_permissions = [
      "Get",
      "UnwrapKey",
      "WrapKey",
    ]
  }
}

resource "azurerm_key_vault_key" "this" {
  name         = "${local.storage_account_name}-cmek"
  key_vault_id = azurerm_key_vault.this.id
  key_type     = "RSA"
  key_size     = 3072
  tags         = var.tags

  key_opts = [
    "unwrapKey",
    "wrapKey",
  ]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }
    expire_after         = "P${var.key_rotation_max_days}D"
    notify_before_expiry = "P29D"
  }
}

# -----------------------------------------------------------------------------
# Storage Account
# -----------------------------------------------------------------------------

resource "azurerm_storage_account" "this" {
  name                            = local.storage_account_name
  resource_group_name             = azurerm_resource_group.this.name
  location                        = azurerm_resource_group.this.location
  account_tier                    = "Standard"
  account_replication_type        = "GZRS"
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  shared_access_key_enabled       = false
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = true
  tags                            = var.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.this.id]
  }

  customer_managed_key {
    key_vault_key_id          = azurerm_key_vault_key.this.id
    user_assigned_identity_id = azurerm_user_assigned_identity.this.id
  }

  network_rules {
    default_action = "Deny"
    ip_rules       = var.allowed_ips
    bypass         = ["AzureServices"]
  }

  blob_properties {
    versioning_enabled = true

    container_delete_retention_policy {
      days = var.soft_delete_retention_days
    }

    delete_retention_policy {
      days                     = var.soft_delete_retention_days
      permanent_delete_enabled = false
    }
  }

  immutability_policy {
    state                         = var.immutability_state
    period_since_creation_in_days = var.immutability_period_days
    allow_protected_append_writes = false
  }
}

# -----------------------------------------------------------------------------
# Log Analytics Workspace + Diagnostic Settings
# -----------------------------------------------------------------------------

resource "azurerm_log_analytics_workspace" "this" {
  name                = "law-${local.storage_account_name}"
  resource_group_name = azurerm_resource_group.this.name
  location            = azurerm_resource_group.this.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = var.tags
}

resource "azurerm_monitor_diagnostic_setting" "blob" {
  name                       = "blob-diagnostics"
  target_resource_id         = "${azurerm_storage_account.this.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }

  enabled_log {
    category = "StorageDelete"
  }

  enabled_metric {
    category = "Transaction"
  }
}

# -----------------------------------------------------------------------------
# Microsoft Defender for Storage
# -----------------------------------------------------------------------------

resource "azurerm_security_center_storage_defender" "this" {
  storage_account_id = azurerm_storage_account.this.id
}

# -----------------------------------------------------------------------------
# Azure Policy Assignments (Resource Group scope)
# -----------------------------------------------------------------------------

resource "azurerm_resource_group_policy_assignment" "allowed_locations" {
  name                 = "allowed-locations"
  resource_group_id    = azurerm_resource_group.this.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c"

  parameters = jsonencode({
    listOfAllowedLocations = {
      value = local.allowed_locations
    }
  })
}

resource "azurerm_resource_group_policy_assignment" "customer_managed_keys" {
  name                 = "storage-cmk-required"
  resource_group_id    = azurerm_resource_group.this.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/6fac406b-40ca-413b-bf8e-0bf964659c25"
}

resource "azurerm_resource_group_policy_assignment" "key_rotation" {
  name                 = "storage-key-rotation"
  resource_group_id    = azurerm_resource_group.this.id
  policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/d8cf8476-a2ec-4916-896e-992351803c44"

  parameters = jsonencode({
    maximumDaysToRotate = {
      value = var.key_rotation_max_days
    }
  })
}
