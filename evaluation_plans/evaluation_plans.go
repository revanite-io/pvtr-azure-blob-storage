package evaluation_plans

import (
	"github.com/revanite-io/pvtr-azure-blob-storage/evaluation_plans/ccc/data"
	"github.com/revanite-io/pvtr-azure-blob-storage/evaluation_plans/reusable_steps"
	"github.com/gemaraproj/go-gemara"
)

var (
	// Add more entries here if other catalogs or catalog versions are adopted by the plugin
	// Then use orchestrator.AddEvaluationSuite to make these available to the user
	CCC = map[string][]gemara.AssessmentStep{
		// For best results, ensure every assessment id is represented in this map
		"CCC.ObjStor.CN01.AR01": {
			/* When a request is made to read a bucket, the service
			MUST prevent any request using KMS keys not listed as trusted by
			the organization.
			*/
			data.PreventUntrustedKmsKeysForBucketRead,
		},
		"CCC.ObjStor.CN01.AR02": {
			/* When a request is made to read an object, the service
			MUST prevent any request using KMS keys not listed as trusted by
			the organization.
			*/
			data.PreventUntrustedKmsKeysForObjectRead,
		},
		"CCC.ObjStor.CN01.AR03": {
			/* When a request is made to write to a bucket, the service MUST
			prevent any request using KMS keys not listed as trusted by the
			organization.
			*/
			data.PreventUntrustedKmsKeysForBucketWrite,
		},
		"CCC.ObjStor.CN01.AR04": {
			/* When a request is made to write to an object, the service MUST
			prevent any request using KMS keys not listed as trusted by the
			organization.
			*/
			data.PreventUntrustedKmsKeysForObjectWrite,
		},
		"CCC.ObjStor.CN02.AR01": {
			/* When a permission set is allowed for an object in a bucket, the
			service MUST allow the same permission set to access all objects
			in the same bucket.
			*/
			data.SharedKeyAccessDisabled,
		},
		"CCC.ObjStor.CN02.AR02": {
			/* When a permission set is denied for an object in a bucket, the
			service MUST deny the same permission set to access all objects
			in the same bucket.
			*/
			data.SharedKeyAccessDisabledForDenial,
		},
		"CCC.ObjStor.CN03.AR01": {
			/* When an object storage bucket deletion is attempted, the bucket MUST be
			fully recoverable for a set time-frame after deletion is requested.
			*/
			data.ContainerSoftDeleteEnabled,
		},
		"CCC.ObjStor.CN03.AR02": {
			/* When an attempt is made to modify the retention policy for an object
			storage bucket, the service MUST prevent the policy from being modified.
			*/
			data.ImmutabilityPolicyLocked,
		},
		"CCC.ObjStor.CN04.AR01": {
			/* When an object is uploaded to the object storage system, the object
			MUST automatically receive a default retention policy that prevents
			premature deletion or modification.
			*/
			data.ImmutabilityEnabled,
		},
		"CCC.ObjStor.CN04.AR02": {
			/* When an attempt is made to delete or modify an object that is subject
			to an active retention policy, the service MUST prevent the action
			from being completed.
			*/
			data.DeletionPreventedForRetentionPolicy,
		},
		"CCC.ObjStor.CN05.AR01": {
			/* When an object is uploaded to the object storage bucket, the object
			MUST be stored with a unique identifier.
			*/
			data.VersioningEnabled,
		},
		"CCC.ObjStor.CN05.AR02": {
			/* When an object is modified, the service MUST assign a new unique
			identifier to the modified object to differentiate it from the
			previous version.
			*/
			data.NewVersionOnModification,
		},
		"CCC.ObjStor.CN05.AR03": {
			/* When an object is modified, the service MUST allow for recovery
			of previous versions of the object.
			*/
			data.PreviousVersionsRecoverable,
		},
		"CCC.ObjStor.CN05.AR04": {
			/* When an object is deleted, the service MUST retain other versions of
			the object to allow for recovery of previous versions.
			*/
			data.VersionsRetainedOnDeletion,
		},
		"CCC.ObjStor.CN07.AR01": {
			/* The object storage service MUST support a configuration option that
			requires MFA to be successfully completed before any object deletion
			can be attempted, regardless of the request interface.
			*/
			data.MfaDeletionSupported,
		},
		"CCC.ObjStor.CN07.AR02": {
			/* When MFA deletion protection is enabled on a bucket or object
			namespace, the service MUST deny any deletion request from an identity
			that has not satisfied the MFA requirement at the time of the request.
			*/
			data.MfaDeletionEnforced,
		},
		"CCC.ObjStor.CN07.AR03": {
			/* When an attempt is made to delete an object, the service&#39;s audit logs MUST
			clearly record each deletion attempt, including whether MFA was required
			and whether validation was met.
			*/
			data.MfaDeletionLogged,
		},

		// CCC
		"CCC.Core.CN01.AR01": {
			/* When a port is exposed for non-SSH network traffic, all traffic
			   MUST include a TLS handshake AND be encrypted using TLS 1.3 or
			   higher. */
			data.ConfirmHttpRequestFails,
			data.CheckTlsVersion,
			data.ConfirmOutdatedProtocolRequestsFail,
		},
		"CCC.Core.CN01.AR02": {
			/* When a port is exposed for SSH network traffic, all traffic MUST
			   include a SSH handshake AND be encrypted using SSHv2 or higher. */
			reusable_steps.AzureBuiltIn,
		},
		"CCC.Core.CN01.AR03": {
			/* When the service receives unencrypted traffic,
			   then it MUST either block the request or automatically
			   redirect it to the secure equivalent. */
			data.RedirectUnencryptedTraffic,
		},
		"CCC.Core.CN02.AR01": {
			/* When data is stored, it MUST be encrypted using the latest
			   industry-standard encryption methods. */
			data.EncryptionIsEnabled,
		},
		"CCC.Core.CN03": {
			data.AuthenticationRequired,
		},
		"CCC.Core.CN04": {
			data.AccessAttemptsLogged,
		},
		"CCC.Core.CN05": {
			data.NetworkAccessRestricted,
		},
		"CCC.Core.CN06": {
			data.DeploymentRestrictedRegions,
		},
		"CCC.Core.CN07": {
			data.DefenderAlertsEnabled,
		},
		"CCC.Core.CN09": {
			data.LogAccessControlled,
		},
		"CCC.Core.CN10": {
			data.ReplicationToUntrustedPrevented,
		},
	}
)
