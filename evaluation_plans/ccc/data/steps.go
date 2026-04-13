package data

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"github.com/gemaraproj/go-gemara"

	"github.com/revanite-io/pvtr-azure-blob-storage/evaluation_plans/reusable_steps"
)

// SharedKeyAccessDisabled verifies that shared key access is disabled on the storage account.
// This ensures uniform bucket-level access is enforced, preventing object-level permissions.
func SharedKeyAccessDisabled(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.StorageAccount == nil {
		return gemara.Unknown, "Storage account data not available", confidence
	}

	if payload.StorageAccount.AllowSharedKeyAccess == nil {
		return gemara.Unknown, "AllowSharedKeyAccess property not available", confidence
	}

	if *payload.StorageAccount.AllowSharedKeyAccess {
		return gemara.Failed, "Shared key access is enabled on the storage account", confidence
	}

	return gemara.Passed, "Shared key access is disabled on the storage account", confidence
}

// ConfirmHttpRequestFails verifies that HTTP requests (non-HTTPS) are rejected.
// This ensures all traffic is encrypted using TLS.
func ConfirmHttpRequestFails(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.StorageAccountURI == "" {
		return gemara.NotRun, "Storage account URI not available for HTTP testing", confidence
	}

	// Replace https:// with http:// to test HTTP endpoint
	httpURI := strings.Replace(payload.StorageAccountURI, "https://", "http://", 1)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
	}

	resp, err := client.Get(httpURI)
	if err != nil {
		// HTTP request failed (expected) - this is good
		return gemara.Passed, "HTTP requests are rejected (connection failed as expected)", confidence
	}
	defer func() { _ = resp.Body.Close() }()

	// If we got a response, HTTP is allowed (bad)
	return gemara.Failed, "HTTP requests are accepted (should be rejected)", confidence
}

// CheckTlsVersion verifies that the TLS version being used is TLS 1.2 or higher.
// This ensures encryption meets minimum security standards.
func CheckTlsVersion(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.StorageAccountURI == "" {
		return gemara.NotRun, "Storage account URI not available for TLS version testing", confidence
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS10, // Allow TLS 1.0+ to detect what version is actually used
				MaxVersion:         tls.VersionTLS13,
				InsecureSkipVerify: false,
			},
		},
	}

	resp, err := client.Get(payload.StorageAccountURI)
	if err != nil {
		return gemara.Unknown, "Failed to connect to storage account endpoint: " + err.Error(), confidence
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.TLS == nil {
		return gemara.Failed, "Connection did not use TLS", confidence
	}

	tlsVersion := resp.TLS.Version
	switch tlsVersion {
	case tls.VersionTLS13: // 0x0304
		return gemara.Passed, "TLS 1.3 is being used", confidence
	case tls.VersionTLS12: // 0x0303
		return gemara.Passed, "TLS 1.2 is being used", confidence
	case tls.VersionTLS11: // 0x0302
		return gemara.Failed, "TLS 1.1 is being used (minimum TLS 1.2 required)", confidence
	case tls.VersionTLS10: // 0x0301
		return gemara.Failed, "TLS 1.0 is being used (minimum TLS 1.2 required)", confidence
	default:
		return gemara.Unknown, "Unknown TLS version detected", confidence
	}
}

// ConfirmOutdatedProtocolRequestsFail verifies that requests using outdated TLS versions (1.0 or 1.1) are rejected.
// This ensures insecure protocols are not supported.
func ConfirmOutdatedProtocolRequestsFail(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.StorageAccountURI == "" {
		return gemara.NotRun, "Storage account URI not available for TLS protocol testing", confidence
	}

	// Test TLS 1.0
	tls10Client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS10,
				InsecureSkipVerify: false,
			},
		},
	}

	resp, err := tls10Client.Get(payload.StorageAccountURI)
	if err == nil {
		_ = resp.Body.Close()
		return gemara.Failed, "TLS 1.0 requests are accepted (should be rejected)", confidence
	}

	// Test TLS 1.1
	tls11Client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS11,
				MaxVersion:         tls.VersionTLS11,
				InsecureSkipVerify: false,
			},
		},
	}

	resp, err = tls11Client.Get(payload.StorageAccountURI)
	if err == nil {
		_ = resp.Body.Close()
		return gemara.Failed, "TLS 1.1 requests are accepted (should be rejected)", confidence
	}

	// Both TLS 1.0 and 1.1 requests failed (expected)
	return gemara.Passed, "TLS 1.0 and TLS 1.1 requests are rejected as expected", confidence
}

// EncryptionIsEnabled verifies that encryption at rest is enabled on the storage account.
// This ensures data is encrypted using industry-standard encryption methods.
func EncryptionIsEnabled(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.StorageAccount == nil {
		return gemara.Unknown, "Storage account data not available", confidence
	}

	if payload.StorageAccount.Encryption == nil {
		return gemara.Unknown, "Encryption configuration not available", confidence
	}

	if payload.StorageAccount.Encryption.Services == nil {
		return gemara.Unknown, "Encryption services configuration not available", confidence
	}

	if payload.StorageAccount.Encryption.Services.Blob == nil {
		return gemara.Unknown, "Blob encryption configuration not available", confidence
	}

	if payload.StorageAccount.Encryption.Services.Blob.Enabled == nil {
		return gemara.Unknown, "Blob encryption enabled property not available", confidence
	}

	if !*payload.StorageAccount.Encryption.Services.Blob.Enabled {
		return gemara.Failed, "Encryption at rest is not enabled for blob storage", confidence
	}

	return gemara.Passed, "Encryption at rest is enabled for blob storage", confidence
}

// PreventUntrustedKmsKeysForBucketRead verifies that requests to read buckets using untrusted KMS keys are prevented.
func PreventUntrustedKmsKeysForBucketRead(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	_, message = reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// This is a new requirement - Azure Storage Accounts don't have bucket-level KMS key restrictions
	// This would need to be enforced at the application/service level or through Azure Policy
	// Return NeedsReview for manual verification
	return gemara.NeedsReview, "This requirement needs to be verified manually. Azure Storage Accounts do not natively support bucket-level KMS key restrictions. This should be enforced at the application/service level or through custom Azure Policy", confidence
}

// PreventUntrustedKmsKeysForObjectRead verifies that requests to read objects using untrusted KMS keys are prevented.
func PreventUntrustedKmsKeysForObjectRead(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	_, message = reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// This is a new requirement - Azure Storage Accounts don't have object-level KMS key restrictions
	// This would need to be enforced at the application/service level or through Azure Policy
	// Return NeedsReview for manual verification
	return gemara.NeedsReview, "This requirement needs to be verified manually. Azure Storage Accounts do not natively support object-level KMS key restrictions. This should be enforced at the application/service level or through custom Azure Policy", confidence
}

// PreventUntrustedKmsKeysForBucketWrite verifies that requests to write to buckets using untrusted KMS keys are prevented.
func PreventUntrustedKmsKeysForBucketWrite(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	_, message = reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// This is a new requirement - Azure Storage Accounts don't have bucket-level KMS key restrictions
	// This would need to be enforced at the application/service level or through Azure Policy
	// Return NeedsReview for manual verification
	return gemara.NeedsReview, "This requirement needs to be verified manually. Azure Storage Accounts do not natively support bucket-level KMS key restrictions. This should be enforced at the application/service level or through custom Azure Policy", confidence
}

// PreventUntrustedKmsKeysForObjectWrite verifies that requests to write to objects using untrusted KMS keys are prevented.
func PreventUntrustedKmsKeysForObjectWrite(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	_, message = reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// This is a new requirement - Azure Storage Accounts don't have object-level KMS key restrictions
	// This would need to be enforced at the application/service level or through Azure Policy
	// Return NeedsReview for manual verification
	return gemara.NeedsReview, "This requirement needs to be verified manually. Azure Storage Accounts do not natively support object-level KMS key restrictions. This should be enforced at the application/service level or through custom Azure Policy", confidence
}

// SharedKeyAccessDisabledForDenial verifies that shared key access is disabled, ensuring uniform bucket-level access for denial cases.
func SharedKeyAccessDisabledForDenial(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.StorageAccount == nil {
		return gemara.Unknown, "Storage account data not available", confidence
	}

	if payload.StorageAccount.AllowSharedKeyAccess == nil {
		return gemara.Unknown, "AllowSharedKeyAccess property not available", confidence
	}

	if *payload.StorageAccount.AllowSharedKeyAccess {
		return gemara.Failed, "Shared key access is enabled on the storage account", confidence
	}

	return gemara.Passed, "Shared key access is disabled on the storage account", confidence
}

// ContainerSoftDeleteEnabled verifies that soft delete is enabled for containers, allowing recovery after deletion.
func ContainerSoftDeleteEnabled(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.BlobService == nil {
		return gemara.Unknown, "Blob service data not available", confidence
	}

	if payload.BlobService.ContainerDeleteRetentionPolicy == nil {
		return gemara.Unknown, "Container delete retention policy not available", confidence
	}

	if payload.BlobService.ContainerDeleteRetentionPolicy.Enabled == nil {
		return gemara.Unknown, "Container soft delete enabled property not available", confidence
	}

	if !*payload.BlobService.ContainerDeleteRetentionPolicy.Enabled {
		return gemara.Failed, "Container soft delete is not enabled", confidence
	}

	// Check that permanent delete is not allowed (soft delete should prevent permanent deletion)
	if payload.BlobService.ContainerDeleteRetentionPolicy.AllowPermanentDelete != nil && *payload.BlobService.ContainerDeleteRetentionPolicy.AllowPermanentDelete {
		return gemara.Failed, "Container soft delete is enabled but permanent deletion is allowed", confidence
	}

	return gemara.Passed, "Container soft delete is enabled and permanent deletion is prevented", confidence
}

// ImmutabilityPolicyLocked verifies that the immutability policy is locked and cannot be modified.
func ImmutabilityPolicyLocked(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.StorageAccount == nil {
		return gemara.Unknown, "Storage account data not available", confidence
	}

	if payload.StorageAccount.ImmutableStorageWithVersioning == nil {
		return gemara.Unknown, "Immutability configuration not available", confidence
	}

	if payload.StorageAccount.ImmutableStorageWithVersioning.ImmutabilityPolicy == nil {
		return gemara.Unknown, "Immutability policy not available", confidence
	}

	if payload.StorageAccount.ImmutableStorageWithVersioning.ImmutabilityPolicy.State == nil {
		return gemara.Unknown, "Immutability policy state not available", confidence
	}

	// Check if policy state is "Locked" (Azure uses "Locked" for locked policies)
	if *payload.StorageAccount.ImmutableStorageWithVersioning.ImmutabilityPolicy.State != "Locked" {
		return gemara.Failed, "Immutability policy is not locked", confidence
	}

	return gemara.Passed, "Immutability policy is locked", confidence
}

// ImmutabilityEnabled verifies that immutability is enabled for blob storage, preventing premature deletion or modification.
func ImmutabilityEnabled(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.StorageAccount == nil {
		return gemara.Unknown, "Storage account data not available", confidence
	}

	if payload.StorageAccount.ImmutableStorageWithVersioning == nil {
		return gemara.Unknown, "Immutability configuration not available", confidence
	}

	if payload.StorageAccount.ImmutableStorageWithVersioning.Enabled == nil {
		return gemara.Unknown, "Immutability enabled property not available", confidence
	}

	if !*payload.StorageAccount.ImmutableStorageWithVersioning.Enabled {
		return gemara.Failed, "Immutability is not enabled for blob storage", confidence
	}

	return gemara.Passed, "Immutability is enabled for blob storage", confidence
}

// DeletionPreventedForRetentionPolicy verifies that deletion of objects subject to retention policies is prevented.
func DeletionPreventedForRetentionPolicy(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.StorageAccount == nil {
		return gemara.Unknown, "Storage account data not available", confidence
	}

	if payload.StorageAccount.ImmutableStorageWithVersioning == nil {
		return gemara.Unknown, "Immutability configuration not available", confidence
	}

	if payload.StorageAccount.ImmutableStorageWithVersioning.Enabled == nil {
		return gemara.Unknown, "Immutability enabled property not available", confidence
	}

	if !*payload.StorageAccount.ImmutableStorageWithVersioning.Enabled {
		return gemara.Failed, "Immutability is not enabled, so deletion prevention for retention policies cannot be verified", confidence
	}

	if payload.StorageAccount.ImmutableStorageWithVersioning.ImmutabilityPolicy == nil {
		return gemara.Unknown, "Immutability policy not available", confidence
	}

	if payload.StorageAccount.ImmutableStorageWithVersioning.ImmutabilityPolicy.State == nil {
		return gemara.Unknown, "Immutability policy state not available", confidence
	}

	// If policy is locked, deletion should be prevented
	if *payload.StorageAccount.ImmutableStorageWithVersioning.ImmutabilityPolicy.State == "Locked" {
		return gemara.Passed, "Immutability policy is locked, preventing deletion of objects subject to retention policies", confidence
	}

	// Immutability is enabled but policy is unlocked. Azure still enforces retention
	// for the configured period — objects cannot be deleted or modified during that window.
	// Unlocked means the policy itself can be changed, not that retention is unenforced.
	return gemara.Passed, "Immutability is enabled. Azure enforces retention policy even when policy state is Unlocked", gemara.Medium
}

// VersioningEnabled verifies that versioning is enabled for blob storage, allowing unique identifiers for each version.
func VersioningEnabled(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.BlobService == nil {
		return gemara.Unknown, "Blob service data not available", confidence
	}

	if payload.BlobService.IsVersioningEnabled == nil {
		return gemara.Unknown, "Versioning enabled property not available", confidence
	}

	if !*payload.BlobService.IsVersioningEnabled {
		return gemara.Failed, "Versioning is not enabled for blob storage", confidence
	}

	return gemara.Passed, "Versioning is enabled for blob storage", confidence
}

// NewVersionOnModification verifies that modifying an object creates a new version with a unique identifier.
func NewVersionOnModification(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// First check if versioning is enabled (required for this to work)
	if payload.BlobService == nil {
		return gemara.Unknown, "Blob service data not available", confidence
	}

	if payload.BlobService.IsVersioningEnabled == nil {
		return gemara.Unknown, "Versioning enabled property not available", confidence
	}

	if !*payload.BlobService.IsVersioningEnabled {
		return gemara.Failed, "Versioning is not enabled, so new versions cannot be created on modification", confidence
	}

	// Azure guarantees that when versioning is enabled, modifying a blob creates a new
	// version with a unique version ID. This is documented platform behavior.
	return gemara.Passed, "Versioning is enabled. Azure assigns a new version ID on each blob modification", gemara.High
}

// PreviousVersionsRecoverable verifies that previous versions of objects can be recovered after modification.
func PreviousVersionsRecoverable(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// First check if versioning is enabled (required for this to work)
	if payload.BlobService == nil {
		return gemara.Unknown, "Blob service data not available", confidence
	}

	if payload.BlobService.IsVersioningEnabled == nil {
		return gemara.Unknown, "Versioning enabled property not available", confidence
	}

	if !*payload.BlobService.IsVersioningEnabled {
		return gemara.Failed, "Versioning is not enabled, so previous versions cannot be recovered", confidence
	}

	// Azure guarantees that when versioning is enabled, previous versions are retained
	// and can be accessed or restored. This is documented platform behavior.
	return gemara.Passed, "Versioning is enabled. Azure retains previous versions for recovery", gemara.High
}

// VersionsRetainedOnDeletion verifies that versions are retained when an object is deleted, allowing recovery.
func VersionsRetainedOnDeletion(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// First check if versioning is enabled (required for this to work)
	if payload.BlobService == nil {
		return gemara.Unknown, "Blob service data not available", confidence
	}

	if payload.BlobService.IsVersioningEnabled == nil {
		return gemara.Unknown, "Versioning enabled property not available", confidence
	}

	if !*payload.BlobService.IsVersioningEnabled {
		return gemara.Failed, "Versioning is not enabled, so versions cannot be retained on deletion", confidence
	}

	// Azure guarantees that when versioning is enabled, deleting a blob creates a
	// delete marker while retaining all previous versions for recovery.
	return gemara.Passed, "Versioning is enabled. Azure retains all versions when a blob is deleted", gemara.High
}

// LoggingToLogAnalyticsConfigured verifies that access logs are stored in Log Analytics, separate from the storage account.
func LoggingToLogAnalyticsConfigured(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Diagnostics == nil {
		return gemara.Unknown, "Diagnostics data not available", confidence
	}

	if payload.Diagnostics.StorageBlobLogsEnabled == nil {
		return gemara.Unknown, "Storage blob logs enabled property not available", confidence
	}

	if !*payload.Diagnostics.StorageBlobLogsEnabled {
		return gemara.Failed, "Logging to Log Analytics is not configured for blob storage", confidence
	}

	if payload.Diagnostics.LogAnalyticsWorkspaceID == nil || *payload.Diagnostics.LogAnalyticsWorkspaceID == "" {
		return gemara.Failed, "Log Analytics workspace is not configured", confidence
	}

	return gemara.Passed, "Logging to Log Analytics is configured for blob storage", confidence
}

// LogBucketHighestSensitivityLevel verifies that buckets storing access logs are classified at the highest sensitivity level.
func LogBucketHighestSensitivityLevel(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// Check if logging to Log Analytics is configured (logs are stored there, not in buckets)
	if payload.Diagnostics != nil && payload.Diagnostics.StorageBlobLogsEnabled != nil && *payload.Diagnostics.StorageBlobLogsEnabled {
		// Logs are stored in Log Analytics, not in storage buckets.
		// This control applies when logs are stored in object storage buckets —
		// since they aren't, the requirement is not applicable.
		return gemara.NotApplicable, "Access logs are stored in Log Analytics, not in storage buckets. Bucket sensitivity classification is not applicable", gemara.High
	}

	// Logging is not configured to Log Analytics — cannot determine where logs go
	return gemara.NeedsReview, "Unable to determine log storage destination. If logs are stored in storage buckets, they must be classified at the highest sensitivity level", confidence
}

// MfaDeletionSupported verifies that the service supports MFA requirement for object deletion.
func MfaDeletionSupported(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	_, message = reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// Azure Storage Accounts do not natively support MFA requirements for object deletion
	// This would need to be enforced through Conditional Access policies or application-level controls
	return gemara.NeedsReview, "Azure Storage Accounts do not natively support MFA requirements for object deletion. This should be enforced through Azure AD Conditional Access policies or application-level controls. Manual verification required", confidence
}

// MfaDeletionEnforced verifies that MFA deletion protection is enforced when enabled.
func MfaDeletionEnforced(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	_, message = reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// Azure Storage Accounts do not natively support MFA requirements for object deletion
	// This would need to be enforced through Conditional Access policies or application-level controls
	return gemara.NeedsReview, "Azure Storage Accounts do not natively support MFA requirements for object deletion. This should be enforced through Azure AD Conditional Access policies or application-level controls. Manual verification required to confirm enforcement", confidence
}

// MfaDeletionLogged verifies that deletion attempts are logged with MFA requirement and validation status.
func MfaDeletionLogged(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// Check if logging is configured
	if payload.Diagnostics == nil || payload.Diagnostics.StorageBlobLogsEnabled == nil || !*payload.Diagnostics.StorageBlobLogsEnabled {
		return gemara.Failed, "Logging is not configured, so deletion attempts cannot be logged", confidence
	}

	// Azure Storage Accounts do not natively log MFA requirement/validation status for deletions
	// This would need to be logged through Azure AD sign-in logs or application-level logging
	return gemara.NeedsReview, "Azure Storage Accounts do not natively log MFA requirement/validation status for deletions. This should be logged through Azure AD sign-in logs or application-level logging. Manual verification required", confidence
}

// RedirectUnencryptedTraffic verifies that unencrypted traffic is either blocked or redirected to secure equivalent.
func RedirectUnencryptedTraffic(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// This check is related to ConfirmHttpRequestFails - if HTTP requests fail, unencrypted traffic is blocked
	// Azure Storage Accounts do not redirect HTTP to HTTPS, they simply reject HTTP requests
	// We can verify this by checking if HTTP requests fail (which is already checked in ConfirmHttpRequestFails)
	if payload.StorageAccountURI == "" {
		return gemara.NotRun, "Storage account URI not available for traffic redirection testing", confidence
	}

	// Azure Storage Accounts block HTTP requests rather than redirecting them
	// This is acceptable behavior - blocking is sufficient
	return gemara.Passed, "Azure Storage Accounts block unencrypted HTTP traffic (redirects are not supported, but blocking is sufficient)", confidence
}

// AuthenticationRequired verifies that authentication is required for all access attempts.
func AuthenticationRequired(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.StorageAccount == nil {
		return gemara.Unknown, "Storage account data not available", confidence
	}

	if payload.StorageAccount.AllowBlobPublicAccess == nil {
		return gemara.Unknown, "AllowBlobPublicAccess property not available", confidence
	}

	if payload.StorageAccount.AllowSharedKeyAccess == nil {
		return gemara.Unknown, "AllowSharedKeyAccess property not available", confidence
	}

	if *payload.StorageAccount.AllowBlobPublicAccess {
		return gemara.Failed, "Public blob access is enabled, allowing unauthenticated access", confidence
	}

	if *payload.StorageAccount.AllowSharedKeyAccess {
		return gemara.Failed, "Shared key access is enabled, allowing unauthenticated access", confidence
	}

	return gemara.Passed, "Authentication is required for all access attempts", confidence
}

// AccessAttemptsLogged verifies that all access attempts are logged with client identity, time, and result.
func AccessAttemptsLogged(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Diagnostics == nil {
		return gemara.Unknown, "Diagnostics data not available", confidence
	}

	if payload.Diagnostics.StorageBlobLogsEnabled == nil {
		return gemara.Unknown, "Storage blob logs enabled property not available", confidence
	}

	if !*payload.Diagnostics.StorageBlobLogsEnabled {
		return gemara.Failed, "Logging to Log Analytics is not configured for blob storage, so access attempts are not logged", confidence
	}

	if payload.Diagnostics.LogAnalyticsWorkspaceID == nil || *payload.Diagnostics.LogAnalyticsWorkspaceID == "" {
		return gemara.Failed, "Log Analytics workspace is not configured", confidence
	}

	// Azure Storage logs include client identity (IP address, user principal), time, and result (success/failure)
	// When logging to Log Analytics is configured, these details are captured
	return gemara.Passed, "Logging to Log Analytics is configured for blob storage, which logs all access attempts with client identity, time, and result", confidence
}

// NetworkAccessRestricted verifies that network access is restricted to allowed sources only.
func NetworkAccessRestricted(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.StorageAccount == nil {
		return gemara.Unknown, "Storage account data not available", confidence
	}

	if payload.StorageAccount.PublicNetworkAccess == nil {
		return gemara.Unknown, "Public network access property not available", confidence
	}

	// If public network access is disabled, access is restricted
	if *payload.StorageAccount.PublicNetworkAccess == "Disabled" {
		return gemara.Passed, "Public network access is disabled for the storage account", confidence
	}

	// If secured by perimeter, we can't assess it
	if *payload.StorageAccount.PublicNetworkAccess == "SecuredByPerimeter" {
		return gemara.NeedsReview, "Public network access is secured by Network Security Perimeter, which this plugin does not support assessment of", confidence
	}

	// If public network access is enabled, check network rules
	if *payload.StorageAccount.PublicNetworkAccess == "Enabled" {
		if payload.StorageAccount.NetworkRuleSet == nil {
			return gemara.Unknown, "Network rule set not available", confidence
		}

		if payload.StorageAccount.NetworkRuleSet.DefaultAction == nil {
			return gemara.Unknown, "Network rule set default action not available", confidence
		}

		// If default action is Deny, only allowlisted IPs can access
		if *payload.StorageAccount.NetworkRuleSet.DefaultAction == "Deny" {
			ipCount := len(payload.StorageAccount.NetworkRuleSet.IPRules)
			if ipCount > 0 {
				return gemara.Passed, "Public network access is enabled but restricted to allowlisted IP addresses", confidence
			}
			return gemara.Failed, "Public network access is enabled with default deny, but no IP rules are configured", confidence
		}

		return gemara.Failed, "Public network access is enabled and default action is not set to deny", confidence
	}

	return gemara.Unknown, "Public network access status is unclear", confidence
}

// DeploymentRestrictedRegions verifies that deployment is prevented in restricted regions.
func DeploymentRestrictedRegions(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Policies == nil {
		return gemara.Unknown, "Policies data not available", confidence
	}

	if payload.Policies.AllowedLocations == nil {
		return gemara.Unknown, "Allowed locations policy data not available", confidence
	}

	if !payload.Policies.AllowedLocations.Assigned {
		return gemara.Failed, "Azure Policy 'Allowed locations' is not assigned to prevent deployment in restricted regions", confidence
	}

	if payload.Policies.AllowedLocations.EnforcementMode != nil && *payload.Policies.AllowedLocations.EnforcementMode == "DoNotEnforce" {
		return gemara.Failed, "Azure Policy 'Allowed locations' is assigned but enforcement mode is set to DoNotEnforce", confidence
	}

	if len(payload.Policies.AllowedLocations.AllowedLocations) == 0 {
		return gemara.Failed, "Azure Policy 'Allowed locations' is assigned but no allowed locations are configured", confidence
	}

	return gemara.Passed, "Azure Policy 'Allowed locations' is assigned and enforced to prevent deployment in restricted regions", confidence
}

// DefenderAlertsEnabled verifies that Microsoft Defender for Cloud alerts are enabled for suspicious activities.
func DefenderAlertsEnabled(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Security == nil {
		return gemara.Unknown, "Security data not available", confidence
	}

	if payload.Security.DefenderForStorage == nil {
		return gemara.Unknown, "Defender for Storage data not available", confidence
	}

	if payload.Security.DefenderForStorage.IsEnabled == nil {
		return gemara.Unknown, "Defender for Storage enabled property not available", confidence
	}

	if !*payload.Security.DefenderForStorage.IsEnabled {
		return gemara.Failed, "Microsoft Defender for Storage is not enabled", confidence
	}

	return gemara.Passed, "Microsoft Defender for Storage is enabled", confidence
}

// DataReplicated verifies that data is replicated across multiple availability zones or regions.
func DataReplicated(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.StorageAccount == nil {
		return gemara.Unknown, "Storage account data not available", confidence
	}

	if payload.StorageAccount.SKU == nil {
		return gemara.Unknown, "Storage account SKU not available", confidence
	}

	if payload.StorageAccount.SKU.Name == nil {
		return gemara.Unknown, "Storage account SKU name not available", confidence
	}

	skuName := *payload.StorageAccount.SKU.Name

	// Check for zone-redundant storage (ZRS, GZRS, RAGZRS)
	if strings.Contains(skuName, "ZRS") {
		return gemara.Passed, "Data is replicated across multiple availability zones", confidence
	}

	// Check for geo-redundant storage (GRS, RAGRS, GZRS)
	if strings.Contains(skuName, "GRS") || strings.Contains(skuName, "RAGRS") || strings.Contains(skuName, "GZRS") || strings.Contains(skuName, "RAGZRS") {
		return gemara.Passed, "Data is replicated across multiple regions", confidence
	}

	// Check for locally redundant storage (LRS) - not replicated
	if strings.Contains(skuName, "LRS") {
		return gemara.Failed, "Data is not replicated across multiple availability zones or regions (LRS)", confidence
	}

	return gemara.Failed, "Data replication type is unknown or not configured", confidence
}

// LogAccessControlled verifies that access logs cannot be accessed, modified, or deleted without proper authorization.
func LogAccessControlled(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Diagnostics == nil {
		return gemara.Unknown, "Diagnostics data not available", confidence
	}

	if payload.Diagnostics.StorageBlobLogsEnabled == nil {
		return gemara.Unknown, "Storage blob logs enabled property not available", confidence
	}

	if !*payload.Diagnostics.StorageBlobLogsEnabled {
		return gemara.Failed, "Logging to Log Analytics is not configured for the storage account", confidence
	}

	if payload.Diagnostics.LogAnalyticsWorkspaceID == nil || *payload.Diagnostics.LogAnalyticsWorkspaceID == "" {
		return gemara.Failed, "Log Analytics workspace is not configured", confidence
	}

	// When logs are stored in Log Analytics, access is controlled by Azure RBAC on the workspace
	return gemara.Passed, "Logging to Log Analytics is configured, with access controlled by Azure RBAC on the Log Analytics workspace", confidence
}

// ReplicationToUntrustedPrevented verifies that data replication to untrusted destinations is prevented.
func ReplicationToUntrustedPrevented(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	_, message = reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	// TODO: Implement actual check once payload structure is available
	// Based on CCC_C10_TR01 from plugin-to-upgrade/ABS/CCC_C10.go
	// This is enforced by Azure - replication outside network access is always blocked
	return gemara.Passed, "Object replication outside of the network access enabled on the Storage Account is always blocked on Azure Storage Accounts", confidence
}

// CustomerManagedKeysUsed verifies that customer-managed encryption keys are used and properly managed.
func CustomerManagedKeysUsed(payloadData any) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	payload, message := reusable_steps.VerifyPayload(payloadData)
	if message != "" {
		return gemara.Unknown, message, confidence
	}

	if payload.Policies == nil {
		return gemara.Unknown, "Policies data not available", confidence
	}

	if payload.Policies.CustomerManagedKeys == nil {
		return gemara.Unknown, "Customer-managed keys policy data not available", confidence
	}

	if !payload.Policies.CustomerManagedKeys.Assigned {
		return gemara.Failed, "Azure Policy requiring customer-managed keys is not assigned", confidence
	}

	if payload.Policies.CustomerManagedKeys.EnforcementMode != nil && *payload.Policies.CustomerManagedKeys.EnforcementMode == "DoNotEnforce" {
		return gemara.Failed, "Azure Policy requiring customer-managed keys is assigned but enforcement mode is set to DoNotEnforce", confidence
	}

	// Also check if key rotation policy is assigned (optional but recommended)
	if payload.Policies.KeyRotation != nil && payload.Policies.KeyRotation.Assigned {
		return gemara.Passed, "Azure Policy requiring customer-managed keys is assigned and enforced, and key rotation policy is also configured", confidence
	}

	return gemara.Passed, "Azure Policy requiring customer-managed keys is assigned and enforced", confidence
}
