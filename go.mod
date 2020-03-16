module github.com/openshift/oauth-apiserver

go 1.13

require (
	github.com/certifi/gocertifi v0.0.0-20191021191039-0944d244cd40 // indirect
	github.com/getsentry/raven-go v0.2.0 // indirect
	github.com/go-openapi/spec v0.19.3
	github.com/google/gofuzz v1.1.0
	github.com/google/uuid v1.1.1
	github.com/jteeuwen/go-bindata v3.0.8-0.20151023091102-a0ff2567cfb7+incompatible
	github.com/openshift/api master
	github.com/openshift/build-machinery-go v0.0.0-20200211121458-5e3d6e570160
	github.com/openshift/client-go master
	github.com/openshift/library-go master
	github.com/pkg/profile v1.4.0 // indirect
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5
	k8s.io/api v0.18.0
	k8s.io/apimachinery v0.18.0
	k8s.io/apiserver v0.18.0
	k8s.io/client-go v0.18.0
	k8s.io/code-generator v0.18.0
	k8s.io/component-base v0.18.0
	k8s.io/kube-openapi v0.0.0-20200121204235-bf4fb3bd569c
)

replace k8s.io/apiserver => github.com/openshift/kubernetes-apiserver oauth-apiserver-4.5-kubernetes-1.18.0
