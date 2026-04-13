package data

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
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
	AllowedLocations *AllowedLocationsPolicy
}

// AllowedLocationsPolicy contains allowed locations policy information
type AllowedLocationsPolicy struct {
	Assigned         bool
	EnforcementMode  *string
	AllowedLocations []string
}

// resourceID holds parsed components of an Azure storage account resource ID.
type resourceID struct {
	subscriptionID     string
	resourceGroupName  string
	storageAccountName string
}

var resourceIDPattern = regexp.MustCompile(
	`^/subscriptions/([0-9a-fA-F-]+)/resourceGroups/([a-zA-Z0-9\-_()\.]+)/providers/Microsoft\.Storage/storageAccounts/([a-z0-9]+)$`,
)

func parseResourceID(raw string) (resourceID, error) {
	match := resourceIDPattern.FindStringSubmatch(raw)
	if len(match) != 4 {
		return resourceID{}, fmt.Errorf("invalid storage account resource ID: %s", raw)
	}
	return resourceID{
		subscriptionID:     match[1],
		resourceGroupName:  match[2],
		storageAccountName: match[3],
	}, nil
}

// Well-known Azure Policy definition IDs
const (
	policyAllowedLocations = "e56962a6-4747-49cd-b67b-bf8b01975c4c"
)

// Loader is the SDK-compatible entrypoint.
func Loader(cfg *config.Config) (any, error) {
	return LoadWithOptions(cfg)
}

// LoadWithOptions is the testable entrypoint with functional options.
func LoadWithOptions(cfg *config.Config, opts ...Option) (any, error) {
	options := &loaderOptions{
		credentialFactory: &defaultCredentialFactory{},
	}
	for _, opt := range opts {
		opt(options)
	}

	// Parse resource ID from config
	rawResourceID := cfg.GetString("storageaccountresourceid")
	if rawResourceID == "" {
		return nil, fmt.Errorf("required config 'storageaccountresourceid' is not provided")
	}

	rid, err := parseResourceID(rawResourceID)
	if err != nil {
		return nil, err
	}

	payload := Payload{
		Config:             cfg,
		ResourceID:         rawResourceID,
		SubscriptionID:     rid.subscriptionID,
		ResourceGroupName:  rid.resourceGroupName,
		StorageAccountName: rid.storageAccountName,
	}

	// Create clients if not injected
	if options.accountsClient == nil || options.blobServicesClient == nil ||
		options.diagnosticsClient == nil || options.defenderClient == nil ||
		options.policyClient == nil {

		cred, err := getCredential(cfg, options)
		if err != nil {
			return nil, fmt.Errorf("failed to get Azure credential: %v", err)
		}

		if options.accountsClient == nil {
			c, err := armstorage.NewAccountsClient(rid.subscriptionID, cred, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create storage accounts client: %v", err)
			}
			options.accountsClient = c
		}

		if options.blobServicesClient == nil {
			c, err := armstorage.NewBlobServicesClient(rid.subscriptionID, cred, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create blob services client: %v", err)
			}
			options.blobServicesClient = c
		}

		if options.diagnosticsClient == nil {
			factory, err := armmonitor.NewClientFactory(rid.subscriptionID, cred, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create monitor client factory: %v", err)
			}
			options.diagnosticsClient = factory.NewDiagnosticSettingsClient()
		}

		if options.defenderClient == nil {
			c, err := armsecurity.NewDefenderForStorageClient(cred, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create defender client: %v", err)
			}
			options.defenderClient = c
		}

		if options.policyClient == nil {
			factory, err := armpolicy.NewClientFactory(rid.subscriptionID, cred, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to create policy client factory: %v", err)
			}
			options.policyClient = factory.NewAssignmentsClient()
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Fetch storage account
	payload.StorageAccount, payload.StorageAccountURI, err = fetchStorageAccount(
		ctx, options.accountsClient, rid)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch storage account: %v", err)
	}

	// Non-critical fetches: populate nil on failure
	payload.BlobService = fetchBlobService(ctx, options.blobServicesClient, rid)
	payload.Diagnostics = fetchDiagnostics(ctx, options.diagnosticsClient, rawResourceID)
	payload.Security = fetchDefender(ctx, options.defenderClient, rawResourceID)
	payload.Policies = fetchPolicies(ctx, options.policyClient, rid)

	return payload, nil
}

// staticTokenCredential implements azcore.TokenCredential with a fixed bearer token.
type staticTokenCredential struct {
	token     string
	expiresOn time.Time
}

func (s *staticTokenCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: s.token, ExpiresOn: s.expiresOn}, nil
}

// getCredential returns an azcore.TokenCredential based on config vars.
// Priority: token (static bearer) > SP credentials > DefaultAzureCredential.
func getCredential(cfg *config.Config, options *loaderOptions) (azcore.TokenCredential, error) {
	if token := cfg.GetString("token"); token != "" {
		return &staticTokenCredential{token: token, expiresOn: time.Now().Add(1 * time.Hour)}, nil
	}

	clientID := cfg.GetString("clientid")
	clientSecret := cfg.GetString("clientsecret")
	tenantID := cfg.GetString("tenantid")

	spVarsPresent := 0
	for _, v := range []string{clientID, clientSecret, tenantID} {
		if v != "" {
			spVarsPresent++
		}
	}
	if spVarsPresent > 0 && spVarsPresent < 3 {
		fmt.Println("WARNING: partial service principal config detected (need all of clientid, clientsecret, tenantid); falling back to DefaultAzureCredential")
	}

	if spVarsPresent == 3 {
		return azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	}

	return options.credentialFactory.NewDefaultCredential()
}

func fetchStorageAccount(
	ctx context.Context, client AccountsClient, rid resourceID,
) (*StorageAccountData, string, error) {
	// Try with GeoReplicationStats expand first
	resp, err := client.GetProperties(ctx, rid.resourceGroupName, rid.storageAccountName,
		&armstorage.AccountsClientGetPropertiesOptions{
			Expand: to.Ptr(armstorage.StorageAccountExpandGeoReplicationStats),
		})
	if err != nil {
		// Fallback without expand
		resp, err = client.GetProperties(ctx, rid.resourceGroupName, rid.storageAccountName, nil)
		if err != nil {
			return nil, "", err
		}
	}

	props := resp.Properties
	if props == nil {
		return nil, "", fmt.Errorf("storage account properties are nil")
	}

	sa := &StorageAccountData{
		AllowSharedKeyAccess:  props.AllowSharedKeyAccess,
		AllowBlobPublicAccess: props.AllowBlobPublicAccess,
	}

	// Public network access (enum -> string)
	if props.PublicNetworkAccess != nil {
		s := string(*props.PublicNetworkAccess)
		sa.PublicNetworkAccess = &s
	}

	// Network rules
	if props.NetworkRuleSet != nil {
		nrs := &NetworkRuleSet{}
		if props.NetworkRuleSet.DefaultAction != nil {
			s := string(*props.NetworkRuleSet.DefaultAction)
			nrs.DefaultAction = &s
		}
		for _, rule := range props.NetworkRuleSet.IPRules {
			if rule.IPAddressOrRange != nil {
				nrs.IPRules = append(nrs.IPRules, IPRule{IPAddressOrRange: rule.IPAddressOrRange})
			}
		}
		sa.NetworkRuleSet = nrs
	}

	// Encryption
	if props.Encryption != nil {
		enc := &EncryptionData{}
		if props.Encryption.KeySource != nil {
			s := string(*props.Encryption.KeySource)
			enc.KeySource = &s
		}
		if props.Encryption.Services != nil && props.Encryption.Services.Blob != nil {
			enc.Services = &EncryptionServices{
				Blob: &EncryptionService{
					Enabled: props.Encryption.Services.Blob.Enabled,
				},
			}
		}
		sa.Encryption = enc
	}

	// SKU
	if resp.SKU != nil && resp.SKU.Name != nil {
		s := string(*resp.SKU.Name)
		sa.SKU = &SKUData{Name: &s}
	}

	// Geo-replication stats
	if props.GeoReplicationStats != nil {
		sa.GeoReplicationStats = &GeoReplicationStats{
			LastSyncTime: props.GeoReplicationStats.LastSyncTime,
		}
	}

	// Immutability
	if props.ImmutableStorageWithVersioning != nil {
		imm := &ImmutabilityData{
			Enabled: props.ImmutableStorageWithVersioning.Enabled,
		}
		if props.ImmutableStorageWithVersioning.ImmutabilityPolicy != nil {
			policy := &ImmutabilityPolicy{
				ImmutabilityPeriodSinceCreationInDays: props.ImmutableStorageWithVersioning.ImmutabilityPolicy.ImmutabilityPeriodSinceCreationInDays,
			}
			if props.ImmutableStorageWithVersioning.ImmutabilityPolicy.State != nil {
				s := string(*props.ImmutableStorageWithVersioning.ImmutabilityPolicy.State)
				policy.State = &s
			}
			imm.ImmutabilityPolicy = policy
		}
		sa.ImmutableStorageWithVersioning = imm
	}

	// Endpoints
	var uri string
	if props.PrimaryEndpoints != nil && props.PrimaryEndpoints.Blob != nil {
		uri = *props.PrimaryEndpoints.Blob
		sa.PrimaryEndpoints = &EndpointsData{Blob: props.PrimaryEndpoints.Blob}
	}

	return sa, uri, nil
}

func fetchBlobService(
	ctx context.Context, client BlobServicesClient, rid resourceID,
) *BlobServiceData {
	resp, err := client.GetServiceProperties(ctx, rid.resourceGroupName, rid.storageAccountName, nil)
	if err != nil {
		return nil
	}

	props := resp.BlobServiceProperties.BlobServiceProperties
	if props == nil {
		return nil
	}

	bs := &BlobServiceData{
		IsVersioningEnabled: props.IsVersioningEnabled,
	}

	if props.ContainerDeleteRetentionPolicy != nil {
		bs.ContainerDeleteRetentionPolicy = &DeleteRetentionPolicy{
			Enabled:              props.ContainerDeleteRetentionPolicy.Enabled,
			Days:                 props.ContainerDeleteRetentionPolicy.Days,
			AllowPermanentDelete: props.ContainerDeleteRetentionPolicy.AllowPermanentDelete,
		}
	}

	if props.DeleteRetentionPolicy != nil {
		bs.DeleteRetentionPolicy = &DeleteRetentionPolicy{
			Enabled:              props.DeleteRetentionPolicy.Enabled,
			Days:                 props.DeleteRetentionPolicy.Days,
			AllowPermanentDelete: props.DeleteRetentionPolicy.AllowPermanentDelete,
		}
	}

	return bs
}

func fetchDiagnostics(
	ctx context.Context, client DiagnosticsClient, storageAccountResourceID string,
) *DiagnosticsData {
	blobResourceID := storageAccountResourceID + "/blobServices/default"
	pager := client.NewListPager(blobResourceID, nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil
		}

		for _, setting := range page.Value {
			if setting.Properties == nil || setting.Properties.WorkspaceID == nil || *setting.Properties.WorkspaceID == "" {
				continue
			}

			readLogged, writeLogged, deleteLogged := false, false, false
			for _, logSetting := range setting.Properties.Logs {
				if logSetting.Enabled == nil || !*logSetting.Enabled {
					continue
				}
				if logSetting.CategoryGroup != nil {
					switch *logSetting.CategoryGroup {
					case "audit", "allLogs":
						readLogged, writeLogged, deleteLogged = true, true, true
					}
				} else if logSetting.Category != nil {
					switch *logSetting.Category {
					case "StorageRead":
						readLogged = true
					case "StorageWrite":
						writeLogged = true
					case "StorageDelete":
						deleteLogged = true
					}
				}
			}

			if readLogged && writeLogged && deleteLogged {
				allLogged := true
				workspaceID := *setting.Properties.WorkspaceID

				// Extract workspace name from resource ID
				workspaceName := workspaceID
				re := regexp.MustCompile(`/workspaces/(.+)$`)
				if match := re.FindStringSubmatch(workspaceID); len(match) > 1 {
					workspaceName = match[1]
				}

				return &DiagnosticsData{
					StorageBlobLogsEnabled:    &allLogged,
					LogAnalyticsWorkspaceID:   &workspaceID,
					LogAnalyticsWorkspaceName: &workspaceName,
				}
			}
		}
	}

	notLogged := false
	return &DiagnosticsData{
		StorageBlobLogsEnabled: &notLogged,
	}
}

func fetchDefender(
	ctx context.Context, client DefenderClient, storageAccountResourceID string,
) *SecurityData {
	resp, err := client.Get(ctx, storageAccountResourceID, armsecurity.SettingNameCurrent, nil)
	if err != nil {
		return nil
	}

	if resp.Properties == nil {
		return nil
	}

	return &SecurityData{
		DefenderForStorage: &DefenderForStorageData{
			IsEnabled: resp.Properties.IsEnabled,
		},
	}
}

func fetchPolicies(
	ctx context.Context, client PolicyClient, rid resourceID,
) *PoliciesData {
	pager := client.NewListForResourcePager(
		rid.resourceGroupName,
		"Microsoft.Storage",
		"",
		"storageAccounts",
		rid.storageAccountName,
		nil,
	)

	policies := &PoliciesData{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil
		}

		for _, assignment := range page.Value {
			if assignment.Properties == nil || assignment.Properties.PolicyDefinitionID == nil {
				continue
			}

			defID := *assignment.Properties.PolicyDefinitionID

			var enforcementMode *string
			if assignment.Properties.EnforcementMode != nil {
				s := string(*assignment.Properties.EnforcementMode)
				enforcementMode = &s
			}

			if strings.Contains(defID, policyAllowedLocations) {
				al := &AllowedLocationsPolicy{
					Assigned:        true,
					EnforcementMode: enforcementMode,
				}
				if assignment.Properties.Parameters != nil {
					if locParam, ok := assignment.Properties.Parameters["listOfAllowedLocations"]; ok && locParam.Value != nil {
						if locations, ok := locParam.Value.([]any); ok {
							for _, loc := range locations {
								if s, ok := loc.(string); ok {
									al.AllowedLocations = append(al.AllowedLocations, s)
								}
							}
						}
					}
				}
				policies.AllowedLocations = al
			}
		}
	}

	return policies
}
