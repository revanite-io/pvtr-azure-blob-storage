package data

import (
	"testing"

	"github.com/gemaraproj/go-gemara"

	d "github.com/revanite-io/pvtr-azure-blob-storage/data"
)

// ptr is a generic helper for creating pointer values in test data.
func ptr[T any](v T) *T {
	return &v
}

// --- SharedKeyAccessDisabled ---

func TestSharedKeyAccessDisabled(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "shared key access disabled returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					AllowSharedKeyAccess: ptr(false),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "shared key access enabled returns Failed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					AllowSharedKeyAccess: ptr(true),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil AllowSharedKeyAccess returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil StorageAccount returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "not a payload",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := SharedKeyAccessDisabled(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- SharedKeyAccessDisabledForDenial ---

func TestSharedKeyAccessDisabledForDenial(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "shared key access disabled returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					AllowSharedKeyAccess: ptr(false),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "shared key access enabled returns Failed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					AllowSharedKeyAccess: ptr(true),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil AllowSharedKeyAccess returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil StorageAccount returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    42,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := SharedKeyAccessDisabledForDenial(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- AuthenticationRequired ---

func TestAuthenticationRequired(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "public access and shared key both disabled returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					AllowBlobPublicAccess: ptr(false),
					AllowSharedKeyAccess:  ptr(false),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "public access enabled returns Failed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					AllowBlobPublicAccess: ptr(true),
					AllowSharedKeyAccess:  ptr(false),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "shared key access enabled returns Failed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					AllowBlobPublicAccess: ptr(false),
					AllowSharedKeyAccess:  ptr(true),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil AllowBlobPublicAccess returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil AllowSharedKeyAccess returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					AllowBlobPublicAccess: ptr(false),
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil StorageAccount returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    nil,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := AuthenticationRequired(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- EncryptionIsEnabled ---

func TestEncryptionIsEnabled(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "blob encryption enabled returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					Encryption: &d.EncryptionData{
						Services: &d.EncryptionServices{
							Blob: &d.EncryptionService{
								Enabled: ptr(true),
							},
						},
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "blob encryption disabled returns Failed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					Encryption: &d.EncryptionData{
						Services: &d.EncryptionServices{
							Blob: &d.EncryptionService{
								Enabled: ptr(false),
							},
						},
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil Enabled returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					Encryption: &d.EncryptionData{
						Services: &d.EncryptionServices{
							Blob: &d.EncryptionService{},
						},
					},
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil Blob returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					Encryption: &d.EncryptionData{
						Services: &d.EncryptionServices{},
					},
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil Services returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					Encryption: &d.EncryptionData{},
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil Encryption returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil StorageAccount returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    struct{}{},
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := EncryptionIsEnabled(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- NetworkAccessRestricted ---

func TestNetworkAccessRestricted(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "public network access disabled returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					PublicNetworkAccess: ptr("Disabled"),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "secured by perimeter returns NeedsReview",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					PublicNetworkAccess: ptr("SecuredByPerimeter"),
				},
			},
			wantResult: gemara.NeedsReview,
		},
		{
			name: "enabled with deny and IP rules returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					PublicNetworkAccess: ptr("Enabled"),
					NetworkRuleSet: &d.NetworkRuleSet{
						DefaultAction: ptr("Deny"),
						IPRules: []d.IPRule{
							{IPAddressOrRange: ptr("10.0.0.1")},
						},
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "enabled with deny but no IP rules returns Failed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					PublicNetworkAccess: ptr("Enabled"),
					NetworkRuleSet: &d.NetworkRuleSet{
						DefaultAction: ptr("Deny"),
						IPRules:       []d.IPRule{},
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "enabled with allow default action returns Failed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					PublicNetworkAccess: ptr("Enabled"),
					NetworkRuleSet: &d.NetworkRuleSet{
						DefaultAction: ptr("Allow"),
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "enabled with nil default action returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					PublicNetworkAccess: ptr("Enabled"),
					NetworkRuleSet:     &d.NetworkRuleSet{},
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "enabled with nil NetworkRuleSet returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					PublicNetworkAccess: ptr("Enabled"),
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "unknown public network access value returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					PublicNetworkAccess: ptr("SomethingElse"),
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil PublicNetworkAccess returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil StorageAccount returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "bad",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := NetworkAccessRestricted(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- ImmutabilityEnabled ---

func TestImmutabilityEnabled(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "immutability enabled returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					ImmutableStorageWithVersioning: &d.ImmutabilityData{
						Enabled: ptr(true),
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "immutability disabled returns Failed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					ImmutableStorageWithVersioning: &d.ImmutabilityData{
						Enabled: ptr(false),
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil Enabled returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					ImmutableStorageWithVersioning: &d.ImmutabilityData{},
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil ImmutableStorageWithVersioning returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil StorageAccount returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    123,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := ImmutabilityEnabled(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- ImmutabilityPolicyLocked ---

func TestImmutabilityPolicyLocked(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "policy locked returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					ImmutableStorageWithVersioning: &d.ImmutabilityData{
						ImmutabilityPolicy: &d.ImmutabilityPolicy{
							State: ptr("Locked"),
						},
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "policy unlocked returns Failed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					ImmutableStorageWithVersioning: &d.ImmutabilityData{
						ImmutabilityPolicy: &d.ImmutabilityPolicy{
							State: ptr("Unlocked"),
						},
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil State returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					ImmutableStorageWithVersioning: &d.ImmutabilityData{
						ImmutabilityPolicy: &d.ImmutabilityPolicy{},
					},
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil ImmutabilityPolicy returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					ImmutableStorageWithVersioning: &d.ImmutabilityData{},
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil ImmutableStorageWithVersioning returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil StorageAccount returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    false,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := ImmutabilityPolicyLocked(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- DeletionPreventedForRetentionPolicy ---

func TestDeletionPreventedForRetentionPolicy(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "immutability enabled and policy locked returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					ImmutableStorageWithVersioning: &d.ImmutabilityData{
						Enabled: ptr(true),
						ImmutabilityPolicy: &d.ImmutabilityPolicy{
							State: ptr("Locked"),
						},
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "immutability enabled but policy unlocked returns Passed with medium confidence",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					ImmutableStorageWithVersioning: &d.ImmutabilityData{
						Enabled: ptr(true),
						ImmutabilityPolicy: &d.ImmutabilityPolicy{
							State: ptr("Unlocked"),
						},
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "immutability disabled returns Failed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					ImmutableStorageWithVersioning: &d.ImmutabilityData{
						Enabled: ptr(false),
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil ImmutabilityPolicy returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					ImmutableStorageWithVersioning: &d.ImmutabilityData{
						Enabled: ptr(true),
					},
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil policy State returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					ImmutableStorageWithVersioning: &d.ImmutabilityData{
						Enabled: ptr(true),
						ImmutabilityPolicy: &d.ImmutabilityPolicy{},
					},
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil Enabled returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					ImmutableStorageWithVersioning: &d.ImmutabilityData{},
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil ImmutableStorageWithVersioning returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil StorageAccount returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    []string{"bad"},
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := DeletionPreventedForRetentionPolicy(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- VersioningEnabled ---

func TestVersioningEnabled(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "versioning enabled returns Passed",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{
					IsVersioningEnabled: ptr(true),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "versioning disabled returns Failed",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{
					IsVersioningEnabled: ptr(false),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil IsVersioningEnabled returns Unknown",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil BlobService returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "wrong",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := VersioningEnabled(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- NewVersionOnModification ---

func TestNewVersionOnModification(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "versioning enabled returns Passed with high confidence",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{
					IsVersioningEnabled: ptr(true),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "versioning disabled returns Failed",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{
					IsVersioningEnabled: ptr(false),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil IsVersioningEnabled returns Unknown",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil BlobService returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    3.14,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := NewVersionOnModification(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- PreviousVersionsRecoverable ---

func TestPreviousVersionsRecoverable(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "versioning enabled returns Passed with high confidence",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{
					IsVersioningEnabled: ptr(true),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "versioning disabled returns Failed",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{
					IsVersioningEnabled: ptr(false),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil IsVersioningEnabled returns Unknown",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil BlobService returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    nil,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := PreviousVersionsRecoverable(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- VersionsRetainedOnDeletion ---

func TestVersionsRetainedOnDeletion(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "versioning enabled returns Passed with high confidence",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{
					IsVersioningEnabled: ptr(true),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "versioning disabled returns Failed",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{
					IsVersioningEnabled: ptr(false),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil IsVersioningEnabled returns Unknown",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil BlobService returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "bad",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := VersionsRetainedOnDeletion(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- ContainerSoftDeleteEnabled ---

func TestContainerSoftDeleteEnabled(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "soft delete enabled and permanent delete not allowed returns Passed",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{
					ContainerDeleteRetentionPolicy: &d.DeleteRetentionPolicy{
						Enabled: ptr(true),
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "soft delete enabled but permanent delete allowed returns Failed",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{
					ContainerDeleteRetentionPolicy: &d.DeleteRetentionPolicy{
						Enabled:              ptr(true),
						AllowPermanentDelete: ptr(true),
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "soft delete enabled and permanent delete explicitly disallowed returns Passed",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{
					ContainerDeleteRetentionPolicy: &d.DeleteRetentionPolicy{
						Enabled:              ptr(true),
						AllowPermanentDelete: ptr(false),
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "soft delete disabled returns Failed",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{
					ContainerDeleteRetentionPolicy: &d.DeleteRetentionPolicy{
						Enabled: ptr(false),
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil Enabled returns Unknown",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{
					ContainerDeleteRetentionPolicy: &d.DeleteRetentionPolicy{},
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil ContainerDeleteRetentionPolicy returns Unknown",
			payload: d.Payload{
				BlobService: &d.BlobServiceData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil BlobService returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    42,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := ContainerSoftDeleteEnabled(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- LoggingToLogAnalyticsConfigured ---

func TestLoggingToLogAnalyticsConfigured(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "logging enabled with workspace ID returns Passed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled:  ptr(true),
					LogAnalyticsWorkspaceID: ptr("/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws"),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "logging disabled returns Failed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled: ptr(false),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "logging enabled but no workspace ID returns Failed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled: ptr(true),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "logging enabled but empty workspace ID returns Failed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled:  ptr(true),
					LogAnalyticsWorkspaceID: ptr(""),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil StorageBlobLogsEnabled returns Unknown",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil Diagnostics returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "wrong",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := LoggingToLogAnalyticsConfigured(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- AccessAttemptsLogged ---

func TestAccessAttemptsLogged(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "logging enabled with workspace returns Passed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled:  ptr(true),
					LogAnalyticsWorkspaceID: ptr("workspace-id"),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "logging disabled returns Failed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled: ptr(false),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "logging enabled but nil workspace returns Failed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled: ptr(true),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "logging enabled but empty workspace returns Failed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled:  ptr(true),
					LogAnalyticsWorkspaceID: ptr(""),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil StorageBlobLogsEnabled returns Unknown",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil Diagnostics returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    nil,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := AccessAttemptsLogged(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- LogAccessControlled ---

func TestLogAccessControlled(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "logging enabled with workspace returns Passed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled:  ptr(true),
					LogAnalyticsWorkspaceID: ptr("workspace-id"),
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "logging disabled returns Failed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled: ptr(false),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "logging enabled but nil workspace returns Failed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled: ptr(true),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "logging enabled but empty workspace returns Failed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled:  ptr(true),
					LogAnalyticsWorkspaceID: ptr(""),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil StorageBlobLogsEnabled returns Unknown",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil Diagnostics returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    struct{}{},
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := LogAccessControlled(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- LogBucketHighestSensitivityLevel ---

func TestLogBucketHighestSensitivityLevel(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "logging enabled returns NotApplicable for Log Analytics path",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled: ptr(true),
				},
			},
			wantResult: gemara.NotApplicable,
		},
		{
			name:       "nil Diagnostics returns NeedsReview for manual verification",
			payload:    d.Payload{},
			wantResult: gemara.NeedsReview,
		},
		{
			name: "logging disabled returns NeedsReview for manual verification",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled: ptr(false),
				},
			},
			wantResult: gemara.NeedsReview,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "bad",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := LogBucketHighestSensitivityLevel(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- MfaDeletionLogged ---

func TestMfaDeletionLogged(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "logging enabled returns NeedsReview",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled: ptr(true),
				},
			},
			wantResult: gemara.NeedsReview,
		},
		{
			name: "logging disabled returns Failed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{
					StorageBlobLogsEnabled: ptr(false),
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name:       "nil Diagnostics returns Failed",
			payload:    d.Payload{},
			wantResult: gemara.Failed,
		},
		{
			name: "nil StorageBlobLogsEnabled returns Failed",
			payload: d.Payload{
				Diagnostics: &d.DiagnosticsData{},
			},
			wantResult: gemara.Failed,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    123,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := MfaDeletionLogged(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- MfaDeletionSupported ---

func TestMfaDeletionSupported(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name:       "valid payload returns NeedsReview",
			payload:    d.Payload{},
			wantResult: gemara.NeedsReview,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "bad",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := MfaDeletionSupported(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- MfaDeletionEnforced ---

func TestMfaDeletionEnforced(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name:       "valid payload returns NeedsReview",
			payload:    d.Payload{},
			wantResult: gemara.NeedsReview,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    nil,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := MfaDeletionEnforced(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- DefenderAlertsEnabled ---

func TestDefenderAlertsEnabled(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "defender enabled returns Passed",
			payload: d.Payload{
				Security: &d.SecurityData{
					DefenderForStorage: &d.DefenderForStorageData{
						IsEnabled: ptr(true),
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "defender disabled returns Failed",
			payload: d.Payload{
				Security: &d.SecurityData{
					DefenderForStorage: &d.DefenderForStorageData{
						IsEnabled: ptr(false),
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil IsEnabled returns Unknown",
			payload: d.Payload{
				Security: &d.SecurityData{
					DefenderForStorage: &d.DefenderForStorageData{},
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil DefenderForStorage returns Unknown",
			payload: d.Payload{
				Security: &d.SecurityData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil Security returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    42,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := DefenderAlertsEnabled(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- DataReplicated ---

func TestDataReplicated(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "ZRS returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					SKU: &d.SKUData{Name: ptr("Standard_ZRS")},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "GRS returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					SKU: &d.SKUData{Name: ptr("Standard_GRS")},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "RAGRS returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					SKU: &d.SKUData{Name: ptr("Standard_RAGRS")},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "GZRS returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					SKU: &d.SKUData{Name: ptr("Standard_GZRS")},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "RAGZRS returns Passed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					SKU: &d.SKUData{Name: ptr("Standard_RAGZRS")},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "LRS returns Failed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					SKU: &d.SKUData{Name: ptr("Standard_LRS")},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "unknown SKU returns Failed",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					SKU: &d.SKUData{Name: ptr("Premium_Unknown")},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil SKU Name returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{
					SKU: &d.SKUData{},
				},
			},
			wantResult: gemara.Unknown,
		},
		{
			name: "nil SKU returns Unknown",
			payload: d.Payload{
				StorageAccount: &d.StorageAccountData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil StorageAccount returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "bad",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := DataReplicated(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- DeploymentRestrictedRegions ---

func TestDeploymentRestrictedRegions(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "policy assigned and enforced with locations returns Passed",
			payload: d.Payload{
				Policies: &d.PoliciesData{
					AllowedLocations: &d.AllowedLocationsPolicy{
						Assigned:         true,
						AllowedLocations: []string{"eastus", "westus"},
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "policy not assigned returns Failed",
			payload: d.Payload{
				Policies: &d.PoliciesData{
					AllowedLocations: &d.AllowedLocationsPolicy{
						Assigned: false,
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "policy assigned but DoNotEnforce returns Failed",
			payload: d.Payload{
				Policies: &d.PoliciesData{
					AllowedLocations: &d.AllowedLocationsPolicy{
						Assigned:         true,
						EnforcementMode:  ptr("DoNotEnforce"),
						AllowedLocations: []string{"eastus"},
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "policy assigned but no locations configured returns Failed",
			payload: d.Payload{
				Policies: &d.PoliciesData{
					AllowedLocations: &d.AllowedLocationsPolicy{
						Assigned:         true,
						AllowedLocations: []string{},
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil AllowedLocations policy returns Unknown",
			payload: d.Payload{
				Policies: &d.PoliciesData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil Policies returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    false,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := DeploymentRestrictedRegions(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- CustomerManagedKeysUsed ---

func TestCustomerManagedKeysUsed(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "policy assigned and enforced returns Passed",
			payload: d.Payload{
				Policies: &d.PoliciesData{
					CustomerManagedKeys: &d.CustomerManagedKeysPolicy{
						Assigned: true,
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "policy assigned with key rotation also assigned returns Passed",
			payload: d.Payload{
				Policies: &d.PoliciesData{
					CustomerManagedKeys: &d.CustomerManagedKeysPolicy{
						Assigned: true,
					},
					KeyRotation: &d.KeyRotationPolicy{
						Assigned: true,
					},
				},
			},
			wantResult: gemara.Passed,
		},
		{
			name: "policy not assigned returns Failed",
			payload: d.Payload{
				Policies: &d.PoliciesData{
					CustomerManagedKeys: &d.CustomerManagedKeysPolicy{
						Assigned: false,
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "policy assigned but DoNotEnforce returns Failed",
			payload: d.Payload{
				Policies: &d.PoliciesData{
					CustomerManagedKeys: &d.CustomerManagedKeysPolicy{
						Assigned:        true,
						EnforcementMode: ptr("DoNotEnforce"),
					},
				},
			},
			wantResult: gemara.Failed,
		},
		{
			name: "nil CustomerManagedKeys returns Unknown",
			payload: d.Payload{
				Policies: &d.PoliciesData{},
			},
			wantResult: gemara.Unknown,
		},
		{
			name:       "nil Policies returns Unknown",
			payload:    d.Payload{},
			wantResult: gemara.Unknown,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "bad",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := CustomerManagedKeysUsed(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- PreventUntrustedKmsKeysForBucketRead ---

func TestPreventUntrustedKmsKeysForBucketRead(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name:       "valid payload returns NeedsReview",
			payload:    d.Payload{},
			wantResult: gemara.NeedsReview,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "bad",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := PreventUntrustedKmsKeysForBucketRead(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- PreventUntrustedKmsKeysForObjectRead ---

func TestPreventUntrustedKmsKeysForObjectRead(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name:       "valid payload returns NeedsReview",
			payload:    d.Payload{},
			wantResult: gemara.NeedsReview,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    42,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := PreventUntrustedKmsKeysForObjectRead(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- PreventUntrustedKmsKeysForBucketWrite ---

func TestPreventUntrustedKmsKeysForBucketWrite(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name:       "valid payload returns NeedsReview",
			payload:    d.Payload{},
			wantResult: gemara.NeedsReview,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    nil,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := PreventUntrustedKmsKeysForBucketWrite(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- PreventUntrustedKmsKeysForObjectWrite ---

func TestPreventUntrustedKmsKeysForObjectWrite(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name:       "valid payload returns NeedsReview",
			payload:    d.Payload{},
			wantResult: gemara.NeedsReview,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    false,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := PreventUntrustedKmsKeysForObjectWrite(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- ConfirmHttpRequestFails ---

func TestConfirmHttpRequestFails(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name:       "empty URI returns NotRun",
			payload:    d.Payload{},
			wantResult: gemara.NotRun,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "not a payload",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := ConfirmHttpRequestFails(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- CheckTlsVersion ---

func TestCheckTlsVersion(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name:       "empty URI returns NotRun",
			payload:    d.Payload{},
			wantResult: gemara.NotRun,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    123,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := CheckTlsVersion(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- ConfirmOutdatedProtocolRequestsFail ---

func TestConfirmOutdatedProtocolRequestsFail(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name:       "empty URI returns NotRun",
			payload:    d.Payload{},
			wantResult: gemara.NotRun,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    42,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := ConfirmOutdatedProtocolRequestsFail(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- RedirectUnencryptedTraffic ---

func TestRedirectUnencryptedTraffic(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name: "valid URI returns Passed",
			payload: d.Payload{
				StorageAccountURI: "https://myaccount.blob.core.windows.net",
			},
			wantResult: gemara.Passed,
		},
		{
			name:       "empty URI returns NotRun",
			payload:    d.Payload{},
			wantResult: gemara.NotRun,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    nil,
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := RedirectUnencryptedTraffic(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}

// --- ReplicationToUntrustedPrevented ---

func TestReplicationToUntrustedPrevented(t *testing.T) {
	tests := []struct {
		name       string
		payload    any
		wantResult gemara.Result
	}{
		{
			name:       "valid payload returns Passed",
			payload:    d.Payload{},
			wantResult: gemara.Passed,
		},
		{
			name:       "wrong type returns Unknown",
			payload:    "bad",
			wantResult: gemara.Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, _ := ReplicationToUntrustedPrevented(tt.payload)
			if result != tt.wantResult {
				t.Errorf("got %v, want %v", result, tt.wantResult)
			}
		})
	}
}
