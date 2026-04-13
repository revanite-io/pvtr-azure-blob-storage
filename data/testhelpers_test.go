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

// ptr returns a pointer to the given value.
func ptr[T any](v T) *T { return &v }

// mockCredentialFactory satisfies CredentialFactory for tests.
type mockCredentialFactory struct{}

func (f *mockCredentialFactory) NewDefaultCredential() (*azidentity.DefaultAzureCredential, error) {
	return nil, nil // never called when all clients are injected
}

// trackingCredentialFactory records whether NewDefaultCredential was called.
type trackingCredentialFactory struct {
	called bool
}

func (f *trackingCredentialFactory) NewDefaultCredential() (*azidentity.DefaultAzureCredential, error) {
	f.called = true
	return nil, nil
}

// mockAccountsClient satisfies AccountsClient for tests.
type mockAccountsClient struct {
	response    armstorage.AccountsClientGetPropertiesResponse
	err         error
	fallbackErr error // error on first call (with expand), success on second
	callCount   int
}

func (m *mockAccountsClient) GetProperties(
	ctx context.Context,
	resourceGroupName string,
	accountName string,
	options *armstorage.AccountsClientGetPropertiesOptions,
) (armstorage.AccountsClientGetPropertiesResponse, error) {
	m.callCount++
	if m.fallbackErr != nil && m.callCount == 1 {
		return armstorage.AccountsClientGetPropertiesResponse{}, m.fallbackErr
	}
	return m.response, m.err
}

// mockBlobServicesClient satisfies BlobServicesClient for tests.
type mockBlobServicesClient struct {
	response armstorage.BlobServicesClientGetServicePropertiesResponse
	err      error
}

func (m *mockBlobServicesClient) GetServiceProperties(
	ctx context.Context,
	resourceGroupName string,
	accountName string,
	options *armstorage.BlobServicesClientGetServicePropertiesOptions,
) (armstorage.BlobServicesClientGetServicePropertiesResponse, error) {
	return m.response, m.err
}

// mockDiagnosticsClient satisfies DiagnosticsClient for tests.
type mockDiagnosticsClient struct {
	pages []armmonitor.DiagnosticSettingsClientListResponse
	err   error
}

func (m *mockDiagnosticsClient) NewListPager(
	resourceURI string,
	options *armmonitor.DiagnosticSettingsClientListOptions,
) *runtime.Pager[armmonitor.DiagnosticSettingsClientListResponse] {
	idx := 0
	return runtime.NewPager(runtime.PagingHandler[armmonitor.DiagnosticSettingsClientListResponse]{
		More: func(resp armmonitor.DiagnosticSettingsClientListResponse) bool {
			return idx < len(m.pages)
		},
		Fetcher: func(ctx context.Context, resp *armmonitor.DiagnosticSettingsClientListResponse) (armmonitor.DiagnosticSettingsClientListResponse, error) {
			if m.err != nil {
				return armmonitor.DiagnosticSettingsClientListResponse{}, m.err
			}
			if idx >= len(m.pages) {
				return armmonitor.DiagnosticSettingsClientListResponse{}, nil
			}
			page := m.pages[idx]
			idx++
			return page, nil
		},
	})
}

// mockDefenderClient satisfies DefenderClient for tests.
type mockDefenderClient struct {
	response armsecurity.DefenderForStorageClientGetResponse
	err      error
}

func (m *mockDefenderClient) Get(
	ctx context.Context,
	resourceID string,
	settingName armsecurity.SettingName,
	options *armsecurity.DefenderForStorageClientGetOptions,
) (armsecurity.DefenderForStorageClientGetResponse, error) {
	return m.response, m.err
}

// mockPolicyClient satisfies PolicyClient for tests.
type mockPolicyClient struct {
	pages []armpolicy.AssignmentsClientListForResourceResponse
	err   error
}

func (m *mockPolicyClient) NewListForResourcePager(
	resourceGroupName string,
	resourceProviderNamespace string,
	parentResourcePath string,
	resourceType string,
	resourceName string,
	options *armpolicy.AssignmentsClientListForResourceOptions,
) *runtime.Pager[armpolicy.AssignmentsClientListForResourceResponse] {
	idx := 0
	return runtime.NewPager(runtime.PagingHandler[armpolicy.AssignmentsClientListForResourceResponse]{
		More: func(resp armpolicy.AssignmentsClientListForResourceResponse) bool {
			return idx < len(m.pages)
		},
		Fetcher: func(ctx context.Context, resp *armpolicy.AssignmentsClientListForResourceResponse) (armpolicy.AssignmentsClientListForResourceResponse, error) {
			if m.err != nil {
				return armpolicy.AssignmentsClientListForResourceResponse{}, m.err
			}
			if idx >= len(m.pages) {
				return armpolicy.AssignmentsClientListForResourceResponse{}, nil
			}
			page := m.pages[idx]
			idx++
			return page, nil
		},
	})
}

// validResourceID is a well-formed resource ID for tests.
const validResourceID = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/test-rg/providers/Microsoft.Storage/storageAccounts/teststorage"

// minimalAccountsResponse returns a response with the minimum fields set.
func minimalAccountsResponse() armstorage.AccountsClientGetPropertiesResponse {
	return armstorage.AccountsClientGetPropertiesResponse{
		Account: armstorage.Account{
			Properties: &armstorage.AccountProperties{
				PrimaryEndpoints: &armstorage.Endpoints{
					Blob: ptr("https://teststorage.blob.core.windows.net/"),
				},
			},
		},
	}
}

// allMockOptions returns functional options with all clients mocked using minimal defaults.
func allMockOptions() []Option {
	return []Option{
		WithCredentialFactory(&mockCredentialFactory{}),
		WithAccountsClient(&mockAccountsClient{response: minimalAccountsResponse()}),
		WithBlobServicesClient(&mockBlobServicesClient{}),
		WithDiagnosticsClient(&mockDiagnosticsClient{}),
		WithDefenderClient(&mockDefenderClient{}),
		WithPolicyClient(&mockPolicyClient{}),
	}
}
