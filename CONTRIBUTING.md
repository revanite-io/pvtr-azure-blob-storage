# Contributing to pvtr-azure-blob-storage

Thank you for your interest in contributing to the Privateer Azure Blob Storage plugin. This guide covers everything you need to get started.

## Finding Work

- **Good first issues**: Visit the [contribute page](https://github.com/revanite-io/pvtr-azure-blob-storage/contribute) to find issues labeled for new contributors.
- **Open issues**: Browse [all open issues](https://github.com/revanite-io/pvtr-azure-blob-storage/issues) for bugs, feature requests, and enhancements.
- **New ideas**: If you have an idea that isn't captured in an issue, open one first to discuss the approach before writing code.

## Development Setup

### Prerequisites

- **Go 1.26.2 or later** (version specified in `go.mod`)
- **golangci-lint** for linting (`go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`)
- **An Azure subscription** (only needed if you're testing against real infrastructure)
- **Terraform 1.5+** (only needed if you're modifying the test environment in `iac/`)

### Clone and Build

```bash
git clone https://github.com/revanite-io/pvtr-azure-blob-storage.git
cd pvtr-azure-blob-storage
make tidy
make build
```

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage report
make test-cov

# Run tests for a specific package
go test ./data/ -v

# Run a specific test
go test ./data/ -v -run TestLoadWithOptions_FullPayload
```

All tests run without Azure credentials. The test suite uses mock clients that simulate Azure API responses, so you don't need a live Azure environment to contribute.

### Linting

```bash
golangci-lint run ./...
```

CI runs this on every pull request. Fix any issues before submitting.

## Project Structure

```
.
├── main.go                          # Plugin entrypoint, wires orchestrator
├── example-config.yml               # Reference configuration for users
├── Makefile                         # Build, test, and release targets
├── data/
│   ├── catalogs/                    # Embedded CCC catalog YAML files
│   ├── clients.go                   # Azure client interfaces and factories
│   ├── data_collection.go           # Loader: fetches data from Azure APIs
│   ├── data_collection_test.go      # Tests for the loader
│   └── testhelpers_test.go          # Mock clients and test utilities
├── evaluation_plans/
│   ├── evaluation_plans.go          # Maps assessment IDs to step functions
│   ├── reusable_steps/
│   │   └── steps.go                 # Steps shared across catalogs
│   └── ccc/
│       └── data/
│           ├── steps.go             # Assessment step implementations
│           └── steps_test.go        # Tests for assessment steps
└── iac/
    └── env/
        └── test/                    # Terraform for the test Azure environment
```

### Key Concepts

- **Loader** (`data/data_collection.go`): Connects to Azure, fetches storage account properties, blob service config, diagnostics, Defender settings, and policy assignments. Returns a `Payload` struct with all collected data.

- **Assessment Steps** (`evaluation_plans/ccc/data/steps.go`): Functions that evaluate the payload against specific CCC controls. Each step receives the payload and returns a result (`Passed`, `Failed`, `NeedsReview`, `NotApplicable`, `Unknown`), a message, and a confidence level.

- **Evaluation Plans** (`evaluation_plans/evaluation_plans.go`): Maps CCC assessment requirement IDs (e.g., `CCC.ObjStor.CN01.AR01`) to one or more assessment step functions.

### Assessment Step Signature

Every assessment step follows this signature:

```go
func StepName(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel)
```

The function should:
1. Type-assert the payload using `reusable_steps.VerifyPayload(payloadData)`
2. Check that required data fields are present (return `gemara.Unknown` if not)
3. Evaluate the control and return the appropriate result

### Adding a New Assessment Step

1. **Write the step function** in `evaluation_plans/ccc/data/steps.go`
2. **Write tests** in `evaluation_plans/ccc/data/steps_test.go` covering:
   - Happy path (control passes)
   - Failure path (control fails)
   - Missing data (returns `Unknown`)
   - Malformed payload (returns `Unknown`)
3. **Register the step** in `evaluation_plans/evaluation_plans.go` under the appropriate assessment ID
4. **Run tests**: `go test ./...`
5. **Run lint**: `golangci-lint run ./...`

### Adding a New Azure Data Source

If your assessment step needs data not currently in the `Payload` struct:

1. **Define the data structure** in `data/data_collection.go`
2. **Add the field** to the `Payload` struct
3. **Create a client interface** in `data/clients.go` if a new Azure client is needed
4. **Add the fetch function** in `data/data_collection.go`
5. **Call it from `LoadWithOptions`**
6. **Write a mock client** in `data/testhelpers_test.go`
7. **Add an `Option` function** in `data/clients.go` (e.g., `WithNewClient`)
8. **Write tests** that use the mock to verify the fetch logic

## Testing Guidelines

See [TESTING.md](TESTING.md) for the full testing strategy document. Key points:

- **Table-driven tests**: Use `t.Run` with subtests for each test case.
- **Mock everything**: All Azure API interactions are mocked. Never call real Azure APIs in tests.
- **Cover edge cases**: Test nil fields, missing data, error conditions, and happy paths.
- **Use the existing patterns**: Look at `data/data_collection_test.go` and `evaluation_plans/ccc/data/steps_test.go` for examples.

## Pull Request Process

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b my-feature
   ```

2. **Make your changes** following the patterns described above.

3. **Run tests and lint** before committing:
   ```bash
   go test ./...
   golangci-lint run ./...
   ```

4. **Write meaningful commit messages** following [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):
   - `feat:` for new features
   - `fix:` for bug fixes
   - `chore:` for maintenance tasks
   - `docs:` for documentation changes

5. **Open a pull request** against `main`. The PR title must also follow conventional commit format (enforced by CI).

6. **CI checks** will run automatically:
   - Build
   - Tests with coverage threshold (currently 26%)
   - Linting via golangci-lint

7. **Code review**: A member of `@revanite-io/coders` will review your PR.

## Terraform / Infrastructure

The `iac/env/test/` directory contains Terraform configuration for the test Azure environment. This provisions:

- A storage account configured to pass most CCC controls
- Diagnostic settings, Defender for Storage, Azure Policies
- A service principal for plugin authentication

If you need to modify the test infrastructure:

1. Ensure you have Azure credentials with appropriate permissions
2. Review `iac/env/test/terraform.tfvars.example` for required variables
3. Run `terraform plan` before `terraform apply`
4. Never commit `terraform.tfvars` (it contains subscription IDs and is gitignored)

## Code of Conduct

Be respectful and constructive. We're building something together.

## Questions?

Open an issue on the repository. We're happy to help you get started.
