package admission

import (
	"github.com/openshift/oauth-apiserver/pkg/admission/logout"
	"k8s.io/apiserver/pkg/server/options"
)

func InstallOauthAdmissionPlugins(ao *options.AdmissionOptions) {
	ao.RecommendedPluginOrder = append(ao.RecommendedPluginOrder, "oauth.openshift.io/AuditLogouts")
	logout.Register(ao.Plugins)
}
