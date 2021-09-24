package logout

import (
	"context"
	"fmt"
	"io"

	"k8s.io/apiserver/pkg/admission"
	"k8s.io/klog/v2"

	oauthv1 "github.com/openshift/api/oauth/v1"
)

func Register(plugins *admission.Plugins) {
	plugins.Register("oauth.openshift.io/AuditLogouts",
		func(config io.Reader) (admission.Interface, error) {
			return NewAuditLogoutsAdmission()
		})
}

type auditLogoutsAdmission struct {
	*admission.Handler
}

func NewAuditLogoutsAdmission() (*auditLogoutsAdmission, error) {
	return &auditLogoutsAdmission{
		Handler: admission.NewHandler(admission.Delete),
	}, nil
}

func (c *auditLogoutsAdmission) Validate(ctx context.Context, a admission.Attributes, _ admission.ObjectInterfaces) error {
	if a.GetResource().GroupResource() != oauthv1.Resource("oauthaccesstokens") {
		return nil
	}

	obj, ok := a.GetObject().(*oauthv1.OAuthAccessToken)
	if !ok {
		return admission.NewForbidden(a,
			fmt.Errorf("object was marked as kind oauthaccesstoken but was unable to be converted: %v (%T), old object, %v (%T)",
				a.GetObject(), a.GetObject(), a.GetOldObject(), a.GetOldObject(),
			),
		)
	}

	klog.V(2).Infof("deletion of oauthaccesstoken for user %v", obj.UserName)
	a.AddAnnotation("oauth.admission.openshift.io/user", obj.UserName)

	return nil
}
