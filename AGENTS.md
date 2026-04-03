# OAuth API Server — AI Assistant Guidelines

OpenShift OAuth API server: OAuth 2.0 token management and authentication. Manages OAuthAccessTokens, OAuthAuthorizeTokens, user identity resources.

## Build & Test Commands

Run `make help` to discover all available targets. Common ones:

```bash
make build
make test-unit                  # unit tests (./pkg/... ./cmd/...)
make test-e2e                   # E2E (requires cluster, 3h timeout, sequential -p 1)
make run-e2e-test WHAT=<test-name>
make update                     # regenerate conversions, deepcopy, defaults, openapi
make verify                     # verify before commit
```

OTE framework (not standard go test):
```bash
./oauth-apiserver-tests-ext run-suite "openshift/oauth-apiserver/all"
./oauth-apiserver-tests-ext run-test "test-name"
```

## Code Layout

Key packages to navigate the codebase:

- `pkg/oauth/` — OAuthAccessToken storage and handlers
- `pkg/tokenvalidation/` — token expiration, timeout, UID, bootstrap validation
- `pkg/user/` — User and Identity resources
- `pkg/externaloidc/` — External OIDC integration
- `pkg/api/` — API types; after modifying run `make update && make verify`
- `test/e2e/` — Ginkgo + OTE E2E tests (`useroauthaccesstokens_test.go`, `tokenreviews.go`)

Generated files — never hand-edit:
`zz_generated.conversion.go`, `zz_generated.deepcopy.go`, `zz_generated.defaults.go`, `pkg/openapi/zz_generated.openapi.go`

## PR / Commit Conventions

All PRs MUST have exactly 2 commits:
1. **Code commit:** Infrastructure changes (exclude go.mod, go.sum, vendor/, generated files)
2. **Generated/vendor commit:** Dependencies (go.mod, go.sum, vendor/) OR generated artifacts (`make update` output)

Base on `upstream/main`, not `origin/main`.

## Debug Commands

```bash
oc get oauthaccesstokens
oc describe oauthaccesstoken/<name>
oc logs -n openshift-oauth-apiserver -l app=oauth-apiserver
```
