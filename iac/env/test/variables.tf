variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "location" {
  description = "Azure region for all resources"
  type        = string
  default     = "centralus"
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
  default     = "rg-pvtr-abs-test"
}

variable "storage_account_name" {
  description = "Storage account name. If empty, auto-generated."
  type        = string
  default     = ""
}

variable "allowed_ips" {
  description = "List of IP addresses allowed to access the storage account (e.g. runner IP)"
  type        = list(string)
}

variable "immutability_state" {
  description = "Immutability policy state (Disabled, Unlocked, or Locked)"
  type        = string
  default     = "Unlocked"
}

variable "allowed_locations" {
  description = "Locations allowed by policy. Defaults to [location]."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    environment = "test"
    managed_by  = "terraform"
    project     = "pvtr-azure-blob-storage"
  }
}
