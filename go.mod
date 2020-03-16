module github.com/openshift/oauth-apiserver

go 1.13

require (
	github.com/certifi/gocertifi v0.0.0-20191021191039-0944d244cd40 // indirect
	github.com/getsentry/raven-go v0.2.0 // indirect
	github.com/go-openapi/spec v0.19.3
	github.com/google/gofuzz v1.1.0
	github.com/google/uuid v1.1.1
	github.com/jteeuwen/go-bindata v3.0.8-0.20151023091102-a0ff2567cfb7+incompatible
	github.com/openshift/api v0.0.0-20200316151409-184bfe77d92c
	github.com/openshift/build-machinery-go v0.0.0-20200211121458-5e3d6e570160
	github.com/openshift/client-go v0.0.0-20200116152001-92a2713fa240
	github.com/openshift/library-go v0.0.0-20200316093823-959aa604cb51
	github.com/pkg/profile v1.4.0 // indirect
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5
	k8s.io/api v0.17.2
	k8s.io/apimachinery v0.17.2
	k8s.io/apiserver v0.17.1
	k8s.io/client-go v0.17.1
	k8s.io/code-generator v0.17.1
	k8s.io/component-base v0.17.1
	k8s.io/kube-openapi v0.0.0-20191107075043-30be4d16710a
)

replace (
	k8s.io/api => k8s.io/api v0.0.0-20191204082340-384b28a90b2b
	k8s.io/apimachinery => k8s.io/apimachinery v0.0.0-20191121175448-79c2a76c473a
	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20191204085103-2ce178ac32b7
	k8s.io/client-go => k8s.io/client-go v0.0.0-20191204083517-ea72ff2b5b2f
	k8s.io/code-generator => k8s.io/code-generator v0.0.0-20191121175249-e95606b614f0
	k8s.io/component-base => k8s.io/component-base v0.0.0-20191204084121-18d14e17701e
)
