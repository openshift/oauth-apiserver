all: build
.PHONY: all

# Include the library makefile
include $(addprefix ./vendor/github.com/openshift/build-machinery-go/make/, \
	golang.mk \
	targets/openshift/deps.mk \
	targets/openshift/images.mk \
)

IMAGE_REGISTRY?=registry.svc.ci.openshift.org

# This will call a macro called "build-image" which will generate image specific targets based on the parameters:
# $0 - macro name
# $1 - target suffix
# $2 - Dockerfile path
# $3 - context directory for image build
# It will generate target "image-$(1)" for builing the image an binding it as a prerequisite to target "images".
$(call build-image,ocp-oauth-apiserver,$(IMAGE_REGISTRY)/ocp/4.3:oauth-apiserver,./images/Dockerfile.rhel7,.)

clean:
	$(RM) ./oauth-apiserver
.PHONY: clean

GO_TEST_PACKAGES :=./pkg/... ./cmd/...

update:
	hack/update-generated-conversions.sh
	hack/update-generated-deep-copies.sh
	hack/update-generated-defaulters.sh
	hack/update-generated-openapi.sh
.PHONY: update

verify:
	hack/verify-generated-conversions.sh
	hack/verify-generated-deep-copies.sh
	hack/verify-generated-defaulters.sh
	hack/verify-generated-openapi.sh
.PHONY: verify

test-e2e: GO_TEST_PACKAGES :=./test/e2e/...
test-e2e: GO_TEST_FLAGS += -v
test-e2e: GO_TEST_FLAGS += -timeout 3h
test-e2e: GO_TEST_FLAGS += -count 1
test-e2e: GO_TEST_FLAGS += -p 1
test-e2e: test-unit
.PHONY: test-e2e

run-e2e-test: GO_TEST_PACKAGES :=./test/e2e/...
run-e2e-test: GO_TEST_FLAGS += -run
run-e2e-test: GO_TEST_FLAGS += ^${WHAT}$$
run-e2e-test: GO_TEST_PACKAGES += -count 1
run-e2e-test: test-unit
.PHONY: run-e2e-test

