#!/usr/bin/env bash

# Copyright 2026 The OpenShift Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Script to fetch latest OpenAPI spec from a running OAuth API server.
# Puts the updated spec at api/openapi-spec/

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
OPENAPI_ROOT_DIR="${OPENAPI_ROOT_DIR:-${SCRIPT_ROOT}/api/openapi-spec}"
DISCOVERY_ROOT_DIR="${DISCOVERY_ROOT_DIR:-${SCRIPT_ROOT}/api/discovery}"

ETCD_HOST="${ETCD_HOST:-127.0.0.1}"
ETCD_PORT="${ETCD_PORT:-2379}"
OAUTH_API_HOST="${OAUTH_API_HOST:-127.0.0.1}"
OAUTH_API_PORT="${OAUTH_API_PORT:-8445}"

TMP_DIR=$(mktemp -d -t update-openapi-spec.XXXXXX)
BIN_DIR="${TMP_DIR}/bin"
CERT_DIR="${TMP_DIR}/certs"
ETCD_DATA_DIR="${TMP_DIR}/etcd-data"

mkdir -p "${BIN_DIR}" "${CERT_DIR}" "${ETCD_DATA_DIR}"

echo "Working directory: ${TMP_DIR}"

ETCD_PID=""
OAUTH_APISERVER_PID=""
PRESERVE_TMP_DIR=false

function cleanup() {
  echo "Cleaning up..."

  if [[ -n "${OAUTH_APISERVER_PID}" ]]; then
    echo "Stopping oauth-apiserver (PID: ${OAUTH_APISERVER_PID})"
    kill "${OAUTH_APISERVER_PID}" 2>/dev/null || true
    wait "${OAUTH_APISERVER_PID}" 2>/dev/null || true
  fi

  if [[ -n "${ETCD_PID}" ]]; then
    echo "Stopping etcd (PID: ${ETCD_PID})"
    kill "${ETCD_PID}" 2>/dev/null || true
    wait "${ETCD_PID}" 2>/dev/null || true
  fi

  if [[ "${PRESERVE_TMP_DIR}" == "true" ]]; then
    echo "Temp directory preserved at: ${TMP_DIR}"
  else
    echo "Removing temporary directory: ${TMP_DIR}"
    rm -rf "${TMP_DIR}"
  fi

  echo "Cleanup complete"
}

function wait_for_url() {
  local url="$1"
  local description="${2:-service}"
  local max_attempts="${3:-60}"
  local attempt=0

  echo "Waiting for ${description} at ${url}..."

  while [[ ${attempt} -lt ${max_attempts} ]]; do
    if curl -kfsS "${url}" >/dev/null 2>&1; then
      echo "${description} is healthy"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done

  echo "ERROR: ${description} did not become healthy after ${max_attempts} seconds"
  return 1
}

function wait_for_openapi_aggregation() {
  local url="$1"
  local max_attempts="${2:-60}"
  local attempt=0

  echo "Waiting for OpenAPI aggregation to complete..."

  while [[ ${attempt} -lt ${max_attempts} ]]; do
    if response=$(curl -kfsS "${url}/openapi/v3" 2>/dev/null); then
      if path_count=$(echo "${response}" | jq -r '.paths | length' 2>/dev/null); then
        if [[ "${path_count}" -gt 0 ]]; then
          echo "OpenAPI aggregation complete (${path_count} API groups available)"
          return 0
        fi
      fi
    fi
    attempt=$((attempt + 1))
    sleep 1
  done

  echo "ERROR: OpenAPI aggregation did not complete after ${max_attempts} seconds"
  return 1
}

trap cleanup EXIT SIGINT SIGTERM

if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required but not installed. Please install jq."
  exit 1
fi

if ! command -v oc &>/dev/null; then
  echo "ERROR: oc is required but not installed."
  exit 1
fi

# Resolve etcd image and registry auth.
#
# Image resolution (first match wins):
#   1. ETCD_IMAGE env var — set by ci-operator dependencies in CI,
#      or manually by the user. If set, skips release resolution entirely.
#   2. OPENSHIFT_RELEASE env var if set.
#   3. Auto-detect version from .ci-operator.yaml and construct release pullspec
#      (ocp/release:<version> for 4.x, ocp/release-<major>:<version> for 5+).
#
# Registry auth:
#   oc resolves credentials via REGISTRY_AUTH_FILE, ~/.config/containers/auth.json,
#   or ~/.docker/config.json (see oc's auth_resolver.go).

if [[ -z "${ETCD_IMAGE:-}" ]]; then
  OPENSHIFT_RELEASE="${OPENSHIFT_RELEASE:-}"

  if [[ -z "${OPENSHIFT_RELEASE}" ]]; then
    OPENSHIFT_VERSION=""
    if [[ -f "${SCRIPT_ROOT}/.ci-operator.yaml" ]]; then
      OPENSHIFT_VERSION=$(grep -oE 'openshift-[0-9]+\.[0-9]+' "${SCRIPT_ROOT}/.ci-operator.yaml" | head -1 | sed 's/openshift-//')
    fi
    if [[ -z "${OPENSHIFT_VERSION}" ]]; then
      echo "ERROR: Could not detect OpenShift version from .ci-operator.yaml"
      echo "Set OPENSHIFT_RELEASE or ETCD_IMAGE directly."
      exit 1
    fi
    MAJOR_VERSION="${OPENSHIFT_VERSION%%.*}"
    if [[ "${MAJOR_VERSION}" -ge 5 ]]; then
      OPENSHIFT_RELEASE="registry.ci.openshift.org/ocp/release-${MAJOR_VERSION}:${OPENSHIFT_VERSION}"
    else
      OPENSHIFT_RELEASE="registry.ci.openshift.org/ocp/release:${OPENSHIFT_VERSION}"
    fi
  fi
  echo "Using release: ${OPENSHIFT_RELEASE}"

fi

echo "Extracting etcd..."
ETCD="${BIN_DIR}/etcd"
ETCD_EXTRACT_DIR="${TMP_DIR}/etcd-extract"
rm -rf "${ETCD_EXTRACT_DIR}"
mkdir -p "${ETCD_EXTRACT_DIR}"
ETCD_IMAGE="${ETCD_IMAGE:-$(oc adm release info "${OPENSHIFT_RELEASE}" --image-for=etcd)}"
oc image extract "${ETCD_IMAGE}" --path usr/bin/etcd:"${ETCD_EXTRACT_DIR}"
mv "${ETCD_EXTRACT_DIR}/etcd" "${ETCD}"
chmod +x "${ETCD}"
echo "etcd version:"
"${ETCD}" --version

OAUTH_APISERVER="${OAUTH_APISERVER:-${SCRIPT_ROOT}/oauth-apiserver}"
if [[ ! -f "${OAUTH_APISERVER}" ]]; then
  echo "ERROR: oauth-apiserver binary not found at ${OAUTH_APISERVER}"
  echo "Please build it first with: make build"
  exit 1
fi
echo "Using oauth-apiserver: ${OAUTH_APISERVER}"

echo "Generating TLS certificates..."
openssl req -x509 -newkey rsa:2048 -keyout "${CERT_DIR}/ca.key" -out "${CERT_DIR}/ca.crt" \
  -days 365 -nodes -subj "/CN=Test CA" 2>/dev/null
echo "Certificates generated in ${CERT_DIR}"

echo "Starting etcd on ${ETCD_HOST}:${ETCD_PORT}..."
"${ETCD}" \
  --data-dir="${ETCD_DATA_DIR}" \
  --listen-client-urls="http://${ETCD_HOST}:${ETCD_PORT}" \
  --advertise-client-urls="http://${ETCD_HOST}:${ETCD_PORT}" \
  >"${TMP_DIR}/etcd.log" 2>&1 &
ETCD_PID=$!
echo "etcd started (PID: ${ETCD_PID})"

# Wait for etcd to be ready
echo "Waiting for etcd to be ready..."
sleep 3
if ! wait_for_url "http://${ETCD_HOST}:${ETCD_PORT}/health" "etcd" 30; then
  echo "etcd failed to start. Check log at: ${TMP_DIR}/etcd.log"
  PRESERVE_TMP_DIR=true
  exit 1
fi

# Create a fake kubeconfig (not actually used, but required for startup)
kubeconfig_file="${CERT_DIR}/kubeconfig"
cat > "${kubeconfig_file}" <<EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: http://127.1.2.3:12345
  name: fake
contexts:
- context:
    cluster: fake
    user: fake
  name: fake
current-context: fake
users:
- name: fake
  user:
    username: fake
    password: fake
EOF

echo "Starting oauth-apiserver on ${OAUTH_API_HOST}:${OAUTH_API_PORT}..."
"${OAUTH_APISERVER}" start \
  --etcd-servers="http://${ETCD_HOST}:${ETCD_PORT}" \
  --secure-port="${OAUTH_API_PORT}" \
  --bind-address="${OAUTH_API_HOST}" \
  --cert-dir="${CERT_DIR}" \
  --client-ca-file="${CERT_DIR}/ca.crt" \
  --kubeconfig="${kubeconfig_file}" \
  --authentication-kubeconfig="${kubeconfig_file}" \
  --authentication-skip-lookup \
  --authorization-kubeconfig="${kubeconfig_file}" \
  --authorization-always-allow-paths="/healthz,/readyz,/livez,/openapi,/openapi/v2,/openapi/v3,/openapi/v3/*,/apis,/apis/*" \
  --disable-admission-plugins="NamespaceLifecycle,MutatingAdmissionWebhook,ValidatingAdmissionWebhook" \
  >"${TMP_DIR}/oauth-apiserver.log" 2>&1 &
OAUTH_APISERVER_PID=$!
echo "oauth-apiserver started (PID: ${OAUTH_APISERVER_PID})"

if ! wait_for_url "https://${OAUTH_API_HOST}:${OAUTH_API_PORT}/healthz" "oauth-apiserver" 120; then
  echo "Full log saved to: ${TMP_DIR}/oauth-apiserver.log"
  echo ""
  echo "Last 50 lines of log:"
  tail -50 "${TMP_DIR}/oauth-apiserver.log" || true
  echo ""
  echo "To inspect:"
  echo "  cat ${TMP_DIR}/oauth-apiserver.log"
  PRESERVE_TMP_DIR=true
  exit 1
fi

if ! wait_for_openapi_aggregation "https://${OAUTH_API_HOST}:${OAUTH_API_PORT}" 120; then
  echo "Full log saved to: ${TMP_DIR}/oauth-apiserver.log"
  PRESERVE_TMP_DIR=true
  exit 1
fi

# Fetch OpenAPI schemas
base_url="https://${OAUTH_API_HOST}:${OAUTH_API_PORT}"
echo "Fetching OpenAPI schemas from ${base_url}..."
echo ""

# Fetch OpenAPI v2 schema
echo "Updating ${OPENAPI_ROOT_DIR}/swagger.json"
mkdir -p "${OPENAPI_ROOT_DIR}"
curl -w "\n" -kfsS "${base_url}/openapi/v2" \
  | jq -S '.info.version="unversioned"' \
  > "${OPENAPI_ROOT_DIR}/swagger.json"

# Note: For discovery endpoints, we need authentication
# Create client certificates for authenticated access
openssl genrsa -out "${CERT_DIR}/client.key" 2048 2>/dev/null
openssl req -new -key "${CERT_DIR}/client.key" -out "${CERT_DIR}/client.csr" \
  -subj "/CN=admin/O=system:masters" 2>/dev/null
openssl x509 -req -in "${CERT_DIR}/client.csr" -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" \
  -CAcreateserial -out "${CERT_DIR}/client.crt" -days 365 2>/dev/null

# Fetch aggregated discovery
echo "Updating ${DISCOVERY_ROOT_DIR}/aggregated_v2.json"
mkdir -p "${DISCOVERY_ROOT_DIR}"
rm -rf "${DISCOVERY_ROOT_DIR:?}"/*
curl -w "\n" -kfsS --cert "${CERT_DIR}/client.crt" --key "${CERT_DIR}/client.key" \
  -H 'Accept: application/json;g=apidiscovery.k8s.io;v=v2;as=APIGroupDiscoveryList' \
  "${base_url}/apis" \
  | jq -S . \
  > "${DISCOVERY_ROOT_DIR}/aggregated_v2.json"

# Fetch /apis discovery (APIGroupList)
echo "Updating ${DISCOVERY_ROOT_DIR}/apis.json"
curl -w "\n" -kfsS --cert "${CERT_DIR}/client.crt" --key "${CERT_DIR}/client.key" \
  "${base_url}/apis" \
  | jq -S . \
  > "${DISCOVERY_ROOT_DIR}/apis.json"

# Fetch OpenAPI v3 discovery document
# Note: We strip the hash query parameters from serverRelativeURL values because
# these hashes are non-deterministic (generated at runtime by the OpenAPI aggregator)
# and would cause spurious diffs on every run even when the actual API content is unchanged.
echo "Updating ${DISCOVERY_ROOT_DIR}/v3-discovery.json"
curl -w "\n" -kfsS "${base_url}/openapi/v3" \
  | jq -S '.paths |= with_entries(.value.serverRelativeURL |= sub("\\?hash=.*$"; ""))' \
  > "${DISCOVERY_ROOT_DIR}/v3-discovery.json"

# Fetch all v3 group schemas
echo "Updating ${OPENAPI_ROOT_DIR}/v3 for OpenAPI v3"
echo ""
mkdir -p "${OPENAPI_ROOT_DIR}/v3"
rm -rf "${OPENAPI_ROOT_DIR:?}"/v3/* || true

curl -w "\n" -kfsS "${base_url}/openapi/v3" \
  | jq -r '.paths | to_entries | .[].key' \
  | while read -r group; do
    echo "Updating OpenAPI spec and discovery for group ${group}"
    openapi_filename="${group}_openapi.json"
    openapi_filename_escaped="${openapi_filename//\//__}"
    openapi_path="${OPENAPI_ROOT_DIR}/v3/${openapi_filename_escaped}"
    curl -w "\n" -kfsS "${base_url}/openapi/v3/${group}" \
      | jq -S '.info.version="unversioned"' \
      > "${openapi_path}"

    if [[ "${group}" == apis/* ]]; then
      discovery_filename="${group}.json"
      discovery_filename_escaped="${discovery_filename//\//__}"
      discovery_path="${DISCOVERY_ROOT_DIR}/${discovery_filename_escaped}"
      curl -w "\n" -kfsS --cert "${CERT_DIR}/client.crt" --key "${CERT_DIR}/client.key" "${base_url}/${group}" \
        | jq -S . \
        > "${discovery_path}"
    fi
  done

echo ""
echo "OpenAPI schemas and discovery files generated successfully:"
echo "  - ${OPENAPI_ROOT_DIR}/swagger.json ($(du -h "${OPENAPI_ROOT_DIR}/swagger.json" | cut -f1))"
echo "  - ${OPENAPI_ROOT_DIR}/v3/*.json ($(ls -1 "${OPENAPI_ROOT_DIR}/v3"/*.json 2>/dev/null | wc -l) OpenAPI v3 files)"
echo "  - ${DISCOVERY_ROOT_DIR}/aggregated_v2.json ($(du -h "${DISCOVERY_ROOT_DIR}/aggregated_v2.json" | cut -f1))"
echo "  - ${DISCOVERY_ROOT_DIR}/v3-discovery.json ($(du -h "${DISCOVERY_ROOT_DIR}/v3-discovery.json" | cut -f1))"
discovery_count=$(ls -1 "${DISCOVERY_ROOT_DIR}"/*.json 2>/dev/null | wc -l)
echo "  - ${DISCOVERY_ROOT_DIR}/*.json (${discovery_count} total discovery files)"
echo ""
echo "SUCCESS: OpenAPI schemas updated in ${OPENAPI_ROOT_DIR}"
