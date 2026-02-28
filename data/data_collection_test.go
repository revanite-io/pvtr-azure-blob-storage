package data

import (
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/privateerproj/privateer-sdk/config"
)

func testConfig(vars map[string]any) *config.Config {
	return &config.Config{Vars: vars}
}

func TestParseResourceID(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantSub string
		wantRG  string
		wantSA  string
	}{
		{
			name:    "valid resource ID",
			input:   validResourceID,
			wantSub: "00000000-0000-0000-0000-000000000000",
			wantRG:  "test-rg",
			wantSA:  "teststorage",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "missing subscription",
			input:   "/subscriptions//resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa",
			wantErr: true,
		},
		{
			name:    "wrong provider",
			input:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Compute/storageAccounts/sa",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rid, err := parseResourceID(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rid.subscriptionID != tt.wantSub {
				t.Errorf("subscriptionID = %q, want %q", rid.subscriptionID, tt.wantSub)
			}
			if rid.resourceGroupName != tt.wantRG {
				t.Errorf("resourceGroupName = %q, want %q", rid.resourceGroupName, tt.wantRG)
			}
			if rid.storageAccountName != tt.wantSA {
				t.Errorf("storageAccountName = %q, want %q", rid.storageAccountName, tt.wantSA)
			}
		})
	}
}

func TestLoadWithOptions_MissingResourceID(t *testing.T) {
	cfg := testConfig(map[string]any{})
	_, err := LoadWithOptions(cfg, allMockOptions()...)
	if err == nil {
		t.Fatal("expected error for missing resource ID")
	}
}

func TestLoadWithOptions_InvalidResourceID(t *testing.T) {
	cfg := testConfig(map[string]any{"storageaccountresourceid": "not-a-resource-id"})
	_, err := LoadWithOptions(cfg, allMockOptions()...)
	if err == nil {
		t.Fatal("expected error for invalid resource ID")
	}
}

func TestLoadWithOptions_StorageAccountFetchFailure(t *testing.T) {
	cfg := testConfig(map[string]any{"storageaccountresourceid": validResourceID})
	opts := []Option{
		WithCredentialFactory(&mockCredentialFactory{}),
		WithAccountsClient(&mockAccountsClient{err: fmt.Errorf("network error")}),
		WithBlobServicesClient(&mockBlobServicesClient{}),
		WithDiagnosticsClient(&mockDiagnosticsClient{}),
		WithDefenderClient(&mockDefenderClient{}),
		WithPolicyClient(&mockPolicyClient{}),
	}
	_, err := LoadWithOptions(cfg, opts...)
	if err == nil {
		t.Fatal("expected error when storage account fetch fails")
	}
}

func TestLoadWithOptions_GeoReplicationFallback(t *testing.T) {
	cfg := testConfig(map[string]any{"storageaccountresourceid": validResourceID})
	opts := []Option{
		WithCredentialFactory(&mockCredentialFactory{}),
		WithAccountsClient(&mockAccountsClient{
			fallbackErr: fmt.Errorf("geo replication not available"),
			response:    minimalAccountsResponse(),
		}),
		WithBlobServicesClient(&mockBlobServicesClient{}),
		WithDiagnosticsClient(&mockDiagnosticsClient{}),
		WithDefenderClient(&mockDefenderClient{}),
		WithPolicyClient(&mockPolicyClient{}),
	}
	result, err := LoadWithOptions(cfg, opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)
	if payload.StorageAccount == nil {
		t.Error("expected StorageAccount to be populated after fallback")
	}
}

func TestLoadWithOptions_BlobServiceFailureNonFatal(t *testing.T) {
	cfg := testConfig(map[string]any{"storageaccountresourceid": validResourceID})
	opts := []Option{
		WithCredentialFactory(&mockCredentialFactory{}),
		WithAccountsClient(&mockAccountsClient{response: minimalAccountsResponse()}),
		WithBlobServicesClient(&mockBlobServicesClient{err: fmt.Errorf("blob error")}),
		WithDiagnosticsClient(&mockDiagnosticsClient{}),
		WithDefenderClient(&mockDefenderClient{}),
		WithPolicyClient(&mockPolicyClient{}),
	}
	result, err := LoadWithOptions(cfg, opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	payload := result.(Payload)
	if payload.BlobService != nil {
		t.Error("expected BlobService to be nil when fetch fails")
	}
}

func TestLoadWithOptions_FullPayload(t *testing.T) {
	cfg := testConfig(map[string]any{"storageaccountresourceid": validResourceID})

	accountResp := armstorage.AccountsClientGetPropertiesResponse{
		Account: armstorage.Account{
			SKU: &armstorage.SKU{Name: to.Ptr(armstorage.SKUNameStandardZRS)},
			Properties: &armstorage.AccountProperties{
				AllowSharedKeyAccess:  ptr(false),
				AllowBlobPublicAccess: ptr(false),
				PublicNetworkAccess:   to.Ptr(armstorage.PublicNetworkAccessDisabled),
				Encryption: &armstorage.Encryption{
					KeySource: to.Ptr(armstorage.KeySourceMicrosoftKeyvault),
					Services: &armstorage.EncryptionServices{
						Blob: &armstorage.EncryptionService{Enabled: ptr(true)},
					},
				},
				ImmutableStorageWithVersioning: &armstorage.ImmutableStorageAccount{
					Enabled: ptr(true),
					ImmutabilityPolicy: &armstorage.AccountImmutabilityPolicyProperties{
						State:                                 to.Ptr(armstorage.AccountImmutabilityPolicyStateLocked),
						ImmutabilityPeriodSinceCreationInDays: ptr(int32(90)),
					},
				},
				PrimaryEndpoints: &armstorage.Endpoints{
					Blob: ptr("https://teststorage.blob.core.windows.net/"),
				},
			},
		},
	}

	// The SDK's BlobServiceProperties struct has a field named BlobServiceProperties
	// of type *BlobServicePropertiesProperties. The response embeds BlobServiceProperties,
	// so the access pattern is: resp.BlobServiceProperties.BlobServiceProperties
	blobResp := armstorage.BlobServicesClientGetServicePropertiesResponse{
		BlobServiceProperties: armstorage.BlobServiceProperties{
			BlobServiceProperties: &armstorage.BlobServicePropertiesProperties{
				IsVersioningEnabled: ptr(true),
				ContainerDeleteRetentionPolicy: &armstorage.DeleteRetentionPolicy{
					Enabled: ptr(true),
					Days:    ptr(int32(7)),
				},
			},
		},
	}

	diagPages := []armmonitor.DiagnosticSettingsClientListResponse{
		{
			DiagnosticSettingsResourceCollection: armmonitor.DiagnosticSettingsResourceCollection{
				Value: []*armmonitor.DiagnosticSettingsResource{
					{
						Properties: &armmonitor.DiagnosticSettings{
							WorkspaceID: ptr("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/myworkspace"),
							Logs: []*armmonitor.LogSettings{
								{Enabled: ptr(true), CategoryGroup: ptr("allLogs")},
							},
						},
					},
				},
			},
		},
	}

	defenderResp := armsecurity.DefenderForStorageClientGetResponse{
		DefenderForStorageSetting: armsecurity.DefenderForStorageSetting{
			Properties: &armsecurity.DefenderForStorageSettingProperties{
				IsEnabled: ptr(true),
			},
		},
	}

	policyPages := []armpolicy.AssignmentsClientListForResourceResponse{
		{
			AssignmentListResult: armpolicy.AssignmentListResult{
				Value: []*armpolicy.Assignment{
					{
						Properties: &armpolicy.AssignmentProperties{
							PolicyDefinitionID: ptr("/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c"),
							EnforcementMode:    to.Ptr(armpolicy.EnforcementModeDefault),
							Parameters: map[string]*armpolicy.ParameterValuesValue{
								"listOfAllowedLocations": {Value: []any{"eastus", "westus2"}},
							},
						},
					},
					{
						Properties: &armpolicy.AssignmentProperties{
							PolicyDefinitionID: ptr("/providers/Microsoft.Authorization/policyDefinitions/6fac406b-40ca-413b-bf8e-0bf964659c25"),
							EnforcementMode:    to.Ptr(armpolicy.EnforcementModeDefault),
						},
					},
				},
			},
		},
	}

	opts := []Option{
		WithCredentialFactory(&mockCredentialFactory{}),
		WithAccountsClient(&mockAccountsClient{response: accountResp}),
		WithBlobServicesClient(&mockBlobServicesClient{response: blobResp}),
		WithDiagnosticsClient(&mockDiagnosticsClient{pages: diagPages}),
		WithDefenderClient(&mockDefenderClient{response: defenderResp}),
		WithPolicyClient(&mockPolicyClient{pages: policyPages}),
	}

	result, err := LoadWithOptions(cfg, opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	p := result.(Payload)

	// Verify resource metadata
	if p.SubscriptionID != "00000000-0000-0000-0000-000000000000" {
		t.Errorf("SubscriptionID = %q", p.SubscriptionID)
	}
	if p.StorageAccountURI != "https://teststorage.blob.core.windows.net/" {
		t.Errorf("StorageAccountURI = %q", p.StorageAccountURI)
	}

	// Verify storage account
	if p.StorageAccount == nil {
		t.Fatal("StorageAccount is nil")
	}
	if p.StorageAccount.AllowSharedKeyAccess == nil || *p.StorageAccount.AllowSharedKeyAccess {
		t.Error("AllowSharedKeyAccess should be false")
	}
	if p.StorageAccount.SKU == nil || *p.StorageAccount.SKU.Name != "Standard_ZRS" {
		t.Errorf("SKU Name = %v", p.StorageAccount.SKU)
	}

	// Verify blob service
	if p.BlobService == nil {
		t.Fatal("BlobService is nil")
	}
	if !*p.BlobService.IsVersioningEnabled {
		t.Error("IsVersioningEnabled should be true")
	}

	// Verify diagnostics
	if p.Diagnostics == nil || !*p.Diagnostics.StorageBlobLogsEnabled {
		t.Error("Diagnostics should show logging enabled")
	}
	if *p.Diagnostics.LogAnalyticsWorkspaceName != "myworkspace" {
		t.Errorf("workspace name = %q", *p.Diagnostics.LogAnalyticsWorkspaceName)
	}

	// Verify security
	if p.Security == nil || !*p.Security.DefenderForStorage.IsEnabled {
		t.Error("Defender should be enabled")
	}

	// Verify policies
	if p.Policies == nil {
		t.Fatal("Policies is nil")
	}
	if p.Policies.AllowedLocations == nil || !p.Policies.AllowedLocations.Assigned {
		t.Error("AllowedLocations should be assigned")
	}
	if len(p.Policies.AllowedLocations.AllowedLocations) != 2 {
		t.Errorf("AllowedLocations count = %d", len(p.Policies.AllowedLocations.AllowedLocations))
	}
	if p.Policies.CustomerManagedKeys == nil || !p.Policies.CustomerManagedKeys.Assigned {
		t.Error("CustomerManagedKeys should be assigned")
	}
}
