// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	oauthv1 "github.com/openshift/api/oauth/v1"
	internal "github.com/openshift/client-go/oauth/applyconfigurations/internal"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	managedfields "k8s.io/apimachinery/pkg/util/managedfields"
	v1 "k8s.io/client-go/applyconfigurations/meta/v1"
)

// OAuthClientAuthorizationApplyConfiguration represents a declarative configuration of the OAuthClientAuthorization type for use
// with apply.
type OAuthClientAuthorizationApplyConfiguration struct {
	v1.TypeMetaApplyConfiguration    `json:",inline"`
	*v1.ObjectMetaApplyConfiguration `json:"metadata,omitempty"`
	ClientName                       *string  `json:"clientName,omitempty"`
	UserName                         *string  `json:"userName,omitempty"`
	UserUID                          *string  `json:"userUID,omitempty"`
	Scopes                           []string `json:"scopes,omitempty"`
}

// OAuthClientAuthorization constructs a declarative configuration of the OAuthClientAuthorization type for use with
// apply.
func OAuthClientAuthorization(name string) *OAuthClientAuthorizationApplyConfiguration {
	b := &OAuthClientAuthorizationApplyConfiguration{}
	b.WithName(name)
	b.WithKind("OAuthClientAuthorization")
	b.WithAPIVersion("oauth.openshift.io/v1")
	return b
}

// ExtractOAuthClientAuthorization extracts the applied configuration owned by fieldManager from
// oAuthClientAuthorization. If no managedFields are found in oAuthClientAuthorization for fieldManager, a
// OAuthClientAuthorizationApplyConfiguration is returned with only the Name, Namespace (if applicable),
// APIVersion and Kind populated. It is possible that no managed fields were found for because other
// field managers have taken ownership of all the fields previously owned by fieldManager, or because
// the fieldManager never owned fields any fields.
// oAuthClientAuthorization must be a unmodified OAuthClientAuthorization API object that was retrieved from the Kubernetes API.
// ExtractOAuthClientAuthorization provides a way to perform a extract/modify-in-place/apply workflow.
// Note that an extracted apply configuration will contain fewer fields than what the fieldManager previously
// applied if another fieldManager has updated or force applied any of the previously applied fields.
// Experimental!
func ExtractOAuthClientAuthorization(oAuthClientAuthorization *oauthv1.OAuthClientAuthorization, fieldManager string) (*OAuthClientAuthorizationApplyConfiguration, error) {
	return extractOAuthClientAuthorization(oAuthClientAuthorization, fieldManager, "")
}

// ExtractOAuthClientAuthorizationStatus is the same as ExtractOAuthClientAuthorization except
// that it extracts the status subresource applied configuration.
// Experimental!
func ExtractOAuthClientAuthorizationStatus(oAuthClientAuthorization *oauthv1.OAuthClientAuthorization, fieldManager string) (*OAuthClientAuthorizationApplyConfiguration, error) {
	return extractOAuthClientAuthorization(oAuthClientAuthorization, fieldManager, "status")
}

func extractOAuthClientAuthorization(oAuthClientAuthorization *oauthv1.OAuthClientAuthorization, fieldManager string, subresource string) (*OAuthClientAuthorizationApplyConfiguration, error) {
	b := &OAuthClientAuthorizationApplyConfiguration{}
	err := managedfields.ExtractInto(oAuthClientAuthorization, internal.Parser().Type("com.github.openshift.api.oauth.v1.OAuthClientAuthorization"), fieldManager, b, subresource)
	if err != nil {
		return nil, err
	}
	b.WithName(oAuthClientAuthorization.Name)

	b.WithKind("OAuthClientAuthorization")
	b.WithAPIVersion("oauth.openshift.io/v1")
	return b, nil
}

// WithKind sets the Kind field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Kind field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithKind(value string) *OAuthClientAuthorizationApplyConfiguration {
	b.Kind = &value
	return b
}

// WithAPIVersion sets the APIVersion field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the APIVersion field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithAPIVersion(value string) *OAuthClientAuthorizationApplyConfiguration {
	b.APIVersion = &value
	return b
}

// WithName sets the Name field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Name field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithName(value string) *OAuthClientAuthorizationApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Name = &value
	return b
}

// WithGenerateName sets the GenerateName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the GenerateName field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithGenerateName(value string) *OAuthClientAuthorizationApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.GenerateName = &value
	return b
}

// WithNamespace sets the Namespace field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Namespace field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithNamespace(value string) *OAuthClientAuthorizationApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Namespace = &value
	return b
}

// WithUID sets the UID field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the UID field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithUID(value types.UID) *OAuthClientAuthorizationApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.UID = &value
	return b
}

// WithResourceVersion sets the ResourceVersion field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ResourceVersion field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithResourceVersion(value string) *OAuthClientAuthorizationApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.ResourceVersion = &value
	return b
}

// WithGeneration sets the Generation field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Generation field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithGeneration(value int64) *OAuthClientAuthorizationApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.Generation = &value
	return b
}

// WithCreationTimestamp sets the CreationTimestamp field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the CreationTimestamp field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithCreationTimestamp(value metav1.Time) *OAuthClientAuthorizationApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.CreationTimestamp = &value
	return b
}

// WithDeletionTimestamp sets the DeletionTimestamp field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DeletionTimestamp field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithDeletionTimestamp(value metav1.Time) *OAuthClientAuthorizationApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.DeletionTimestamp = &value
	return b
}

// WithDeletionGracePeriodSeconds sets the DeletionGracePeriodSeconds field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the DeletionGracePeriodSeconds field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithDeletionGracePeriodSeconds(value int64) *OAuthClientAuthorizationApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	b.DeletionGracePeriodSeconds = &value
	return b
}

// WithLabels puts the entries into the Labels field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Labels field,
// overwriting an existing map entries in Labels field with the same key.
func (b *OAuthClientAuthorizationApplyConfiguration) WithLabels(entries map[string]string) *OAuthClientAuthorizationApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	if b.Labels == nil && len(entries) > 0 {
		b.Labels = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Labels[k] = v
	}
	return b
}

// WithAnnotations puts the entries into the Annotations field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, the entries provided by each call will be put on the Annotations field,
// overwriting an existing map entries in Annotations field with the same key.
func (b *OAuthClientAuthorizationApplyConfiguration) WithAnnotations(entries map[string]string) *OAuthClientAuthorizationApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	if b.Annotations == nil && len(entries) > 0 {
		b.Annotations = make(map[string]string, len(entries))
	}
	for k, v := range entries {
		b.Annotations[k] = v
	}
	return b
}

// WithOwnerReferences adds the given value to the OwnerReferences field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the OwnerReferences field.
func (b *OAuthClientAuthorizationApplyConfiguration) WithOwnerReferences(values ...*v1.OwnerReferenceApplyConfiguration) *OAuthClientAuthorizationApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	for i := range values {
		if values[i] == nil {
			panic("nil value passed to WithOwnerReferences")
		}
		b.OwnerReferences = append(b.OwnerReferences, *values[i])
	}
	return b
}

// WithFinalizers adds the given value to the Finalizers field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Finalizers field.
func (b *OAuthClientAuthorizationApplyConfiguration) WithFinalizers(values ...string) *OAuthClientAuthorizationApplyConfiguration {
	b.ensureObjectMetaApplyConfigurationExists()
	for i := range values {
		b.Finalizers = append(b.Finalizers, values[i])
	}
	return b
}

func (b *OAuthClientAuthorizationApplyConfiguration) ensureObjectMetaApplyConfigurationExists() {
	if b.ObjectMetaApplyConfiguration == nil {
		b.ObjectMetaApplyConfiguration = &v1.ObjectMetaApplyConfiguration{}
	}
}

// WithClientName sets the ClientName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the ClientName field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithClientName(value string) *OAuthClientAuthorizationApplyConfiguration {
	b.ClientName = &value
	return b
}

// WithUserName sets the UserName field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the UserName field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithUserName(value string) *OAuthClientAuthorizationApplyConfiguration {
	b.UserName = &value
	return b
}

// WithUserUID sets the UserUID field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the UserUID field is set to the value of the last call.
func (b *OAuthClientAuthorizationApplyConfiguration) WithUserUID(value string) *OAuthClientAuthorizationApplyConfiguration {
	b.UserUID = &value
	return b
}

// WithScopes adds the given value to the Scopes field in the declarative configuration
// and returns the receiver, so that objects can be build by chaining "With" function invocations.
// If called multiple times, values provided by each call will be appended to the Scopes field.
func (b *OAuthClientAuthorizationApplyConfiguration) WithScopes(values ...string) *OAuthClientAuthorizationApplyConfiguration {
	for i := range values {
		b.Scopes = append(b.Scopes, values[i])
	}
	return b
}

// GetName retrieves the value of the Name field in the declarative configuration.
func (b *OAuthClientAuthorizationApplyConfiguration) GetName() *string {
	b.ensureObjectMetaApplyConfigurationExists()
	return b.Name
}
