package data

import (
	"time"

	"github.com/privateerproj/privateer-sdk/config"
)

// Payload contains all Azure Storage Account data required for evaluation steps.
type Payload struct {
	Config *config.Config

	// Storage Account Resource
	StorageAccount *StorageAccountData

	// Blob Service Properties
	BlobService *BlobServiceData

	// Diagnostic and Logging
	Diagnostics *DiagnosticsData

	// Security and Compliance
	Security *SecurityData

	// Policies
	Policies *PoliciesData

	// Resource Metadata
	ResourceID         string
	SubscriptionID     string
	ResourceGroupName  string
	StorageAccountName string
	StorageAccountURI  string
}

// StorageAccountData contains properties from armstorage.Account
type StorageAccountData struct {
	// Authentication and Access
	AllowSharedKeyAccess  *bool
	AllowBlobPublicAccess *bool

	// Network Configuration
	PublicNetworkAccess *string // "Enabled", "Disabled", "SecuredByPerimeter"
	NetworkRuleSet      *NetworkRuleSet

	// Encryption
	Encryption *EncryptionData

	// Replication
	SKU                 *SKUData
	StatusOfSecondary   *string
	GeoReplicationStats *GeoReplicationStats

	// Immutability
	ImmutableStorageWithVersioning *ImmutabilityData

	// Endpoints
	PrimaryEndpoints *EndpointsData
}

// NetworkRuleSet contains network access rules
type NetworkRuleSet struct {
	DefaultAction *string // "Allow", "Deny"
	IPRules       []IPRule
}

// IPRule represents an IP address or range rule
type IPRule struct {
	IPAddressOrRange *string
}

// EncryptionData contains encryption configuration
type EncryptionData struct {
	Services  *EncryptionServices
	KeySource *string // "Microsoft.Storage", "Microsoft.Keyvault"
}

// EncryptionServices contains encryption settings for different services
type EncryptionServices struct {
	Blob *EncryptionService
}

// EncryptionService contains encryption settings for a service
type EncryptionService struct {
	Enabled *bool
}

// SKUData contains storage account SKU information
type SKUData struct {
	Name *string // Contains "LRS", "ZRS", "GRS", "GZRS", etc.
}

// GeoReplicationStats contains geo-replication status information
type GeoReplicationStats struct {
	LastSyncTime *time.Time
}

// ImmutabilityData contains immutability policy configuration
type ImmutabilityData struct {
	Enabled            *bool
	ImmutabilityPolicy *ImmutabilityPolicy
}

// ImmutabilityPolicy contains immutability policy details
type ImmutabilityPolicy struct {
	State                                 *string // AccountImmutabilityPolicyState enum
	ImmutabilityPeriodSinceCreationInDays *int32
}

// EndpointsData contains storage account endpoint URLs
type EndpointsData struct {
	Blob *string
}

// BlobServiceData contains properties from armstorage.BlobServiceProperties
type BlobServiceData struct {
	// Versioning
	IsVersioningEnabled *bool

	// Soft Delete Policies
	ContainerDeleteRetentionPolicy *DeleteRetentionPolicy
	DeleteRetentionPolicy          *DeleteRetentionPolicy
}

// DeleteRetentionPolicy contains soft delete retention policy configuration
type DeleteRetentionPolicy struct {
	Enabled              *bool
	Days                 *int32
	AllowPermanentDelete *bool
}

// DiagnosticsData contains diagnostic and logging configuration
type DiagnosticsData struct {
	LogAnalyticsWorkspaceID   *string
	LogAnalyticsWorkspaceName *string
	StorageBlobLogsEnabled    *bool
}

// SecurityData contains security-related configuration
type SecurityData struct {
	DefenderForStorage *DefenderForStorageData
}

// DefenderForStorageData contains Microsoft Defender for Storage configuration
type DefenderForStorageData struct {
	IsEnabled *bool
}

// PoliciesData contains Azure Policy assignments
type PoliciesData struct {
	AllowedLocations    *AllowedLocationsPolicy
	CustomerManagedKeys *CustomerManagedKeysPolicy
	KeyRotation         *KeyRotationPolicy
}

// AllowedLocationsPolicy contains allowed locations policy information
type AllowedLocationsPolicy struct {
	Assigned         bool
	EnforcementMode  *string
	AllowedLocations []string
}

// CustomerManagedKeysPolicy contains customer-managed keys policy information
type CustomerManagedKeysPolicy struct {
	Assigned        bool
	EnforcementMode *string
}

// KeyRotationPolicy contains key rotation policy information
type KeyRotationPolicy struct {
	Assigned            bool
	EnforcementMode     *string
	MaximumDaysToRotate *int
}

// Loader builds and returns a payload for the evaluation.
// Signature matches what the SDK expects
// TODO: Implement actual Azure API calls to populate payload data
func Loader(cfg *config.Config) (payload any, err error) {
	// TODO: Parse storage account resource ID from config
	// TODO: Authenticate with Azure using DefaultAzureCredential
	// TODO: Fetch storage account resource using armstorage.AccountsClient
	// TODO: Fetch blob service properties using armstorage.BlobServicesClient
	// TODO: Fetch diagnostic settings using armmonitor.DiagnosticSettingsClient
	// TODO: Fetch Defender for Storage settings using armsecurity.DefenderForStorageClient
	// TODO: Fetch Azure Policy assignments using armpolicy.Client
	// TODO: Parse and populate all payload fields

	return Payload{
		Config: cfg,
		// All other fields will be nil until Loader is fully implemented
	}, nil
}
