# Running Evaluations Against Azure Infrastructure

This guide covers provisioning Azure infrastructure with Terraform and running the plugin against it.

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- [Go](https://go.dev/dl/) >= 1.21
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) (`az`)
- An Azure subscription with Owner or Contributor + User Access Administrator role
- The following Azure resource providers registered on your subscription:
  - `Microsoft.Storage`
  - `Microsoft.KeyVault`
  - `Microsoft.OperationalInsights`
  - `Microsoft.Security`
  - `Microsoft.Authorization`

To check and register providers:

```bash
az provider show -n Microsoft.Storage --query "registrationState"
az provider register -n Microsoft.Storage
```

## 1. Authenticate to Azure

```bash
az login
az account set --subscription <your-subscription-id>
```

## 2. Provision Infrastructure

### Configure variables

```bash
cd iac/env/test
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with your values:

```hcl
subscription_id = "<your-subscription-id>"
allowed_ips     = ["<your-public-ip>"]
```

To find your public IP:

```bash
curl -s https://ifconfig.me
```

Optional overrides (defaults shown):

| Variable | Default | Description |
|---|---|---|
| `location` | `centralus` | Azure region |
| `resource_group_name` | `rg-pvtr-abs-test` | Resource group name |
| `storage_account_name` | (auto-generated) | Storage account name |
| `immutability_state` | `Unlocked` | `Disabled`, `Unlocked`, or `Locked` |
| `allowed_locations` | `[location]` | Regions allowed by Azure Policy |

> **Warning**: Setting `immutability_state = "Locked"` is irreversible and prevents resource deletion. Use `Unlocked` for testing.

### Apply

```bash
terraform init
terraform plan
terraform apply
```

Note the outputs — you'll need `storage_account_resource_id` for the plugin config.

```bash
terraform output storage_account_resource_id
```

## 3. Build the Plugin

From the repository root:

```bash
make build
```

This produces the `pvtr-azure-blob-storage` binary in the project root.

## 4. Configure the Plugin

Create or update `config.yml` in the repository root:

```yaml
loglevel: debug
write-directory: evaluation_results
services:
  myService1:
    plugin: pvtr-azure-blob-storage
    policy:
      catalogs: ["CCC.ObjStor"]
      applicability:
        - tlp-amber
        - tlp-red
        - tlp-clear
        - tlp-green
    vars:
      storageaccountresourceid: <storage_account_resource_id from terraform output>
```

Replace the `storageaccountresourceid` value with the full resource ID from Terraform output, e.g.:

```
/subscriptions/328eb894-.../resourceGroups/rg-pvtr-abs-test/providers/Microsoft.Storage/storageAccounts/pvtrabstest
```

## 5. Run the Plugin

```bash
./pvtr-azure-blob-storage --service myService1 --config config.yml
```

Results are written to the `evaluation_results/` directory in YAML format.

### Understanding Results

Each assessment step produces one of these results:

| Result | Meaning |
|---|---|
| `Passed` | The control requirement is satisfied |
| `Failed` | The control requirement is not met |
| `NeedsReview` | Could not be determined automatically; manual review required |
| `Unknown` | The step encountered an error during evaluation |

## 6. Tear Down Infrastructure

When finished, destroy the resources to avoid ongoing costs:

```bash
cd iac/env/test
terraform destroy
```

> **Note**: If `immutability_state` was set to `Locked`, the storage account cannot be deleted by Terraform. You will need to wait for the immutability period to expire or manually remove it through Azure support.

## Troubleshooting

### Provider registration errors

If you see `AuthorizationFailed` errors about resource provider registration, ensure the required providers are registered:

```bash
az provider register -n Microsoft.Storage
az provider register -n Microsoft.KeyVault
az provider register -n Microsoft.OperationalInsights
az provider register -n Microsoft.Security
```

The Terraform configuration uses `resource_provider_registrations = "none"` to avoid automatic registration, which requires elevated permissions.

### Storage account access denied

The Terraform provider uses Azure AD authentication for storage data plane operations (`storage_use_azuread = true`). Ensure your authenticated identity has the `Storage Blob Data Owner` role on the subscription or storage account.

### Plugin can't reach storage account

The storage account restricts network access to IPs listed in `allowed_ips`. Ensure your current public IP is included in `terraform.tfvars`.
