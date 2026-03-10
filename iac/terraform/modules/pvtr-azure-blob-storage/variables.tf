variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "centralus"
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
  default     = "rg-pvtr-azure-blob-storage"
}

variable "storage_account_name" {
  description = "Storage account name (3-24 lowercase alphanumeric). If empty, auto-generated."
  type        = string
  default     = ""

  validation {
    condition     = var.storage_account_name == "" || can(regex("^[a-z0-9]{3,24}$", var.storage_account_name))
    error_message = "Storage account name must be 3-24 lowercase alphanumeric characters."
  }
}

variable "allowed_ips" {
  description = "List of IP addresses or CIDR ranges allowed to access the storage account"
  type        = list(string)
}

variable "immutability_state" {
  description = "Immutability policy state. WARNING: 'Locked' is irreversible and prevents storage account deletion."
  type        = string
  default     = "Unlocked"

  validation {
    condition     = contains(["Disabled", "Unlocked", "Locked"], var.immutability_state)
    error_message = "immutability_state must be one of: Disabled, Unlocked, Locked."
  }
}

variable "immutability_period_days" {
  description = "Immutability period in days since creation"
  type        = number
  default     = 1
}

variable "allowed_locations" {
  description = "Locations allowed by the 'Allowed locations' policy. Defaults to [location]."
  type        = list(string)
  default     = []
}

variable "soft_delete_retention_days" {
  description = "Number of days to retain soft-deleted blobs and containers"
  type        = number
  default     = 7
}

variable "key_rotation_max_days" {
  description = "Maximum days allowed between key rotations for the key rotation policy"
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
