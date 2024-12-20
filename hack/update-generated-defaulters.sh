#!/usr/bin/env bash

source "$(dirname "${BASH_SOURCE}")/lib/init.sh"

SCRIPT_ROOT=$(dirname ${BASH_SOURCE})/..
CODEGEN_PKG=${CODEGEN_PKG:-$(cd ${SCRIPT_ROOT}; ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ../../../k8s.io/code-generator)}

verify="${VERIFY:-}"

go install ./${CODEGEN_PKG}/cmd/defaulter-gen

function codegen::join() { local IFS="$1"; shift; echo "$*"; }

# enumerate group versions
ALL_FQ_APIS=(
    github.com/openshift/oauth-apiserver/pkg/oauth/apis/oauth/v1
    github.com/openshift/oauth-apiserver/pkg/user/apis/user/v1
)

ALL_PEERS=(
    k8s.io/apimachinery/pkg/api/resource
    k8s.io/apimachinery/pkg/apis/meta/v1
    k8s.io/apimachinery/pkg/apis/meta/internalversion
    k8s.io/apimachinery/pkg/runtime
    k8s.io/apimachinery/pkg/conversion
    k8s.io/apimachinery/pkg/types
    k8s.io/api/core/v1
)


echo "Generating defaults"
${GOPATH}/bin/defaulter-gen "${ALL_FQ_APIS[@]}" --extra-peer-dirs $(codegen::join , "${ALL_PEERS[@]}") --output-file zz_generated.defaults.go --go-header-file ${SCRIPT_ROOT}/hack/boilerplate.txt --v=8 "$@"
