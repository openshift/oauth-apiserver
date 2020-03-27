module github.com/openshift/oauth-apiserver

go 1.15

require (
	github.com/MakeNowJust/heredoc v1.0.0
	github.com/certifi/gocertifi v0.0.0-20191021191039-0944d244cd40 // indirect
	github.com/getsentry/raven-go v0.2.0 // indirect
	github.com/go-openapi/spec v0.19.3
	github.com/google/btree v1.0.0
	github.com/google/gofuzz v1.1.0
	github.com/google/uuid v1.1.2
	github.com/jteeuwen/go-bindata v3.0.8-0.20151023091102-a0ff2567cfb7+incompatible
	github.com/openshift/api v0.0.0-20201216151826-78a19e96f9eb
	github.com/openshift/apiserver-library-go v0.0.0-20201204115753-d48a1b462aa6
	github.com/openshift/build-machinery-go v0.0.0-20200917070002-f171684f77ab
	github.com/openshift/client-go v0.0.0-20201214125552-e615e336eb49
	github.com/openshift/library-go v0.0.0-20210106214821-c4d0b9c8d55f
	github.com/pkg/profile v1.4.0 // indirect
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.6.1
	k8s.io/api v0.20.1
	k8s.io/apiextensions-apiserver v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/apiserver v0.20.1
	k8s.io/client-go v0.20.1
	k8s.io/code-generator v0.20.1
	k8s.io/component-base v0.20.1
	k8s.io/klog/v2 v2.4.0
	k8s.io/kube-aggregator v0.20.1
	k8s.io/kube-openapi v0.0.0-20201113171705-d219536bb9fd
	k8s.io/kubernetes v1.20.1
)

replace (
	k8s.io/api => k8s.io/api v0.20.1
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.20.1
	k8s.io/apimachinery => k8s.io/apimachinery v0.20.1
	k8s.io/apiserver => github.com/openshift/kubernetes-apiserver v0.0.0-20210106144646-d2bf56fab5ef // points to openshift-apiserver-4.7-kubernetes-1.20.1
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.20.1
	k8s.io/client-go => k8s.io/client-go v0.20.1
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.20.1
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.20.1
	k8s.io/code-generator => k8s.io/code-generator v0.20.1
	k8s.io/component-base => k8s.io/component-base v0.20.1
	k8s.io/component-helpers => k8s.io/component-helpers v0.20.1
	k8s.io/controller-manager => k8s.io/controller-manager v0.20.1
	k8s.io/cri-api => k8s.io/cri-api v0.20.1
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.20.1
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.20.1
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.20.1
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20201113171705-d219536bb9fd
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.20.1
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.20.1
	k8s.io/kubectl => k8s.io/kubectl v0.20.1
	k8s.io/kubelet => k8s.io/kubelet v0.20.1
	k8s.io/kubernetes => k8s.io/kubernetes v1.20.1
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.20.1
	k8s.io/metrics => k8s.io/metrics v0.20.1
	k8s.io/mount-utils => k8s.io/mount-utils v0.20.1
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.20.1
)
