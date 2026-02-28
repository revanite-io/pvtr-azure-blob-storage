package data

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

// AccountsClient abstracts armstorage.AccountsClient for testing.
type AccountsClient interface {
	GetProperties(
		ctx context.Context,
		resourceGroupName string,
		accountName string,
		options *armstorage.AccountsClientGetPropertiesOptions,
	) (armstorage.AccountsClientGetPropertiesResponse, error)
}

// BlobServicesClient abstracts armstorage.BlobServicesClient for testing.
type BlobServicesClient interface {
	GetServiceProperties(
		ctx context.Context,
		resourceGroupName string,
		accountName string,
		options *armstorage.BlobServicesClientGetServicePropertiesOptions,
	) (armstorage.BlobServicesClientGetServicePropertiesResponse, error)
}

// DiagnosticsClient abstracts armmonitor.DiagnosticSettingsClient for testing.
type DiagnosticsClient interface {
	NewListPager(
		resourceURI string,
		options *armmonitor.DiagnosticSettingsClientListOptions,
	) *runtime.Pager[armmonitor.DiagnosticSettingsClientListResponse]
}

// DefenderClient abstracts armsecurity.DefenderForStorageClient for testing.
type DefenderClient interface {
	Get(
		ctx context.Context,
		resourceID string,
		settingName armsecurity.SettingName,
		options *armsecurity.DefenderForStorageClientGetOptions,
	) (armsecurity.DefenderForStorageClientGetResponse, error)
}

// PolicyClient abstracts armpolicy.AssignmentsClient for testing.
type PolicyClient interface {
	NewListForResourcePager(
		resourceGroupName string,
		resourceProviderNamespace string,
		parentResourcePath string,
		resourceType string,
		resourceName string,
		options *armpolicy.AssignmentsClientListForResourceOptions,
	) *runtime.Pager[armpolicy.AssignmentsClientListForResourceResponse]
}

// CredentialFactory abstracts Azure credential creation for testing.
type CredentialFactory interface {
	NewDefaultCredential() (*azidentity.DefaultAzureCredential, error)
}

// defaultCredentialFactory creates real Azure credentials.
type defaultCredentialFactory struct{}

func (f *defaultCredentialFactory) NewDefaultCredential() (*azidentity.DefaultAzureCredential, error) {
	return azidentity.NewDefaultAzureCredential(nil)
}

// loaderOptions holds optional dependencies for LoadWithOptions.
type loaderOptions struct {
	accountsClient     AccountsClient
	blobServicesClient BlobServicesClient
	diagnosticsClient  DiagnosticsClient
	defenderClient     DefenderClient
	policyClient       PolicyClient
	credentialFactory  CredentialFactory
}

// Option configures the Loader.
type Option func(*loaderOptions)

// WithAccountsClient overrides the default armstorage.AccountsClient.
func WithAccountsClient(c AccountsClient) Option {
	return func(o *loaderOptions) { o.accountsClient = c }
}

// WithBlobServicesClient overrides the default armstorage.BlobServicesClient.
func WithBlobServicesClient(c BlobServicesClient) Option {
	return func(o *loaderOptions) { o.blobServicesClient = c }
}

// WithDiagnosticsClient overrides the default armmonitor.DiagnosticSettingsClient.
func WithDiagnosticsClient(c DiagnosticsClient) Option {
	return func(o *loaderOptions) { o.diagnosticsClient = c }
}

// WithDefenderClient overrides the default armsecurity.DefenderForStorageClient.
func WithDefenderClient(c DefenderClient) Option {
	return func(o *loaderOptions) { o.defenderClient = c }
}

// WithPolicyClient overrides the default armpolicy.AssignmentsClient.
func WithPolicyClient(c PolicyClient) Option {
	return func(o *loaderOptions) { o.policyClient = c }
}

// WithCredentialFactory overrides the default Azure credential factory.
func WithCredentialFactory(f CredentialFactory) Option {
	return func(o *loaderOptions) { o.credentialFactory = f }
}
