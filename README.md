# Privateer Plugin for Azure Blob Storage

A [Privateer](https://github.com/privateerproj/privateer-sdk) plugin that evaluates Azure Blob Storage accounts against the [CCC Object Storage](https://commoncloudcontrols.com/catalogs/storage/object/controls) catalog controls.

## Overview

This plugin connects to an Azure Storage Account and evaluates its configuration against the Common Cloud Controls (CCC) Object Storage catalog. It checks encryption, access control, versioning, immutability, logging, network restrictions, and policy compliance — producing a structured report of passed, failed, and review-needed controls.

## Prerequisites

- Go 1.26.2 or later
- An Azure subscription with a Storage Account to evaluate
- Azure credentials (one of the following):
  - An active `az login` session
  - A service principal with Reader + Security Reader roles
  - A bearer token from `az account get-access-token`

### Required Azure Permissions

The plugin performs read-only operations. Minimum required roles:

| Role | Scope | Covers |
|------|-------|--------|
| Reader | Resource group or storage account | Storage properties, blob service, diagnostics, policy assignments |
| Security Reader | Subscription | Microsoft Defender for Storage settings |

## Installation

### From source

```bash
git clone https://github.com/revanite-io/pvtr-azure-blob-storage.git
cd pvtr-azure-blob-storage
make build
```

### From releases

Download the latest binary from the [releases page](https://github.com/revanite-io/pvtr-azure-blob-storage/releases).

## Configuration

Copy `example-config.yml` and customize it:

```bash
cp example-config.yml config.yml
```

At minimum, set the `storageaccountresourceid` to your target storage account:

```yaml
services:
  myService1:
    plugin: pvtr-azure-blob-storage
    policy:
      catalogs: ["CCC.ObjStor"]
    vars:
      storageaccountresourceid: /subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.Storage/storageAccounts/<account-name>
```

### Authentication

The plugin tries authentication methods in this order:

1. **Bearer token** (short-lived, for one-off runs):
   ```yaml
   vars:
     token: <bearer-token>
   ```
   Generate via: `az account get-access-token --resource https://management.azure.com --query accessToken -o tsv`

2. **Service principal** (long-lived, for CI/automation):
   ```yaml
   vars:
     clientid: <application-client-id>
     clientsecret: <client-secret-value>
     tenantid: <azure-ad-tenant-id>
   ```

3. **DefaultAzureCredential** (no config needed) — uses `az login`, managed identity, or `AZURE_*` environment variables automatically.

## Usage

This plugin is designed to run via Privateer. See the [Privateer documentation](https://github.com/privateerproj/privateer-sdk) for details on running plugins.

For local development and debugging:

```bash
make build
```

## Controls Evaluated

The plugin evaluates controls from two CCC catalogs:

### CCC.ObjStor (Object Storage)

| Control | Description |
|---------|-------------|
| CN01 | Prevent requests with untrusted KMS keys |
| CN02 | Uniform bucket-level access enforcement |
| CN03 | Bucket deletion recovery and immutability |
| CN04 | Default retention policies |
| CN05 | Object versioning |
| CN06 | Access logging |
| CN07 | MFA deletion protection |

### CCC.Core

| Control | Description |
|---------|-------------|
| CN01 | Encryption in transit (TLS) |
| CN02 | Encryption at rest |
| CN03 | Authentication required |
| CN04 | Access attempts logged |
| CN05 | Network access restricted |
| CN06 | Deployment restricted to regions |
| CN07 | Defender alerts enabled |
| CN09 | Log access controlled |
| CN10 | Replication to untrusted prevented |
| CN11 | Customer-managed keys used |

## Development

```bash
# Run tests
make test

# Run tests with coverage
make test-cov

# Build
make build

# Tidy dependencies
make tidy
```

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on how to get started.

Looking for something to work on? Check the [contribute page](https://github.com/revanite-io/pvtr-azure-blob-storage/contribute) for good first issues.

## Related Projects

- [privateer-sdk](https://github.com/privateerproj/privateer-sdk) - The SDK this plugin is built on
- [go-gemara](https://github.com/gemaraproj/go-gemara) - Assessment framework types
- [Common Cloud Controls](https://commoncloudcontrols.com) - The control catalogs evaluated by this plugin
