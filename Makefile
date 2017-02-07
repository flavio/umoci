# umoci: Umoci Modifies Open Containers' Images
# Copyright (C) 2016, 2017 SUSE LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Use bash, so that we can do process substitution.
SHELL = /bin/bash

# Go tools.
GO ?= go
GO_MD2MAN ?= go-md2man

# Set up the ... lovely ... GOPATH hacks.
PROJECT := github.com/openSUSE/umoci

# We use Docker because Go is just horrific to deal with.
UMOCI_IMAGE := umoci_dev

# Version information.
VERSION := $(shell cat ./VERSION)
COMMIT_NO := $(shell git rev-parse HEAD 2> /dev/null || true)
COMMIT := $(if $(shell git status --porcelain --untracked-files=no),"${COMMIT_NO}-dirty","${COMMIT_NO}")

.DEFAULT: umoci

GO_SRC =  $(shell find . -name \*.go)
umoci: $(GO_SRC)
	$(GO) build -ldflags "-s -w -X main.gitCommit=${COMMIT} -X main.version=${VERSION}" -tags "$(BUILDTAGS)" -o $@ $(PROJECT)/cmd/umoci

umoci.static: $(GO_SRC)
	CGO_ENABLED=0 $(GO) build -ldflags "-s -w -extldflags '-static' -X main.gitCommit=${COMMIT} -X main.version=${VERSION}" -tags "$(BUILDTAGS)" -o $@ $(PROJECT)/cmd/umoci

umoci.cover: $(GO_SRC)
	$(GO) test -c -cover -covermode=count -coverpkg=$(PROJECT)/... -ldflags "-s -w -X main.gitCommit=${COMMIT} -X main.version=${VERSION}" -tags "$(BUILDTAGS)" -o $@ $(PROJECT)/cmd/umoci

.PHONY: update-deps
update-deps:
	hack/vendor.sh
	hack/patch.sh

.PHONY: clean
clean:
	rm -f umoci umoci.static
	rm -f $(MANPAGES)

validate: umociimage
	docker run --rm -it -v $(PWD):/go/src/$(PROJECT) $(UMOCI_IMAGE) make local-validate

EPOCH_COMMIT ?= 97ecdbd53dcb72b7a0d62196df281f131dc9eb2f
.PHONY: local-validate
local-validate:
	test -z "$$(gofmt -s -l . | grep -v '^vendor/' | grep -v '^third_party/' | tee /dev/stderr)"
	out="$$(golint $(PROJECT)/... | grep -v '/vendor/' | grep -v '/third_party/' | grep -vE 'system/utils_linux.*ALL_CAPS|system/mknod_linux.*underscores')"; \
	if [ -n "$$out" ]; then \
		echo "$$out"; \
		exit 1; \
	fi
	go vet $(shell go list $(PROJECT)/... | grep -v /vendor/ | grep -v /third_party/)
	#@echo "git-validation"
	#@git-validation -v -run DCO,short-subject,dangling-whitespace $(EPOCH_COMMIT)..HEAD

MANPAGES_MD := $(wildcard man/*.md)
MANPAGES    := $(MANPAGES_MD:%.md=%)

man/%.1: man/%.1.md
	$(GO_MD2MAN) -in $< -out $@

.PHONY: doc
doc: $(MANPAGES)

# Used for tests.
DOCKER_IMAGE :=opensuse/amd64:tumbleweed

.PHONY: umociimage
umociimage:
	docker build -t $(UMOCI_IMAGE) --build-arg DOCKER_IMAGE=$(DOCKER_IMAGE) .

ifndef COVERAGE
COVERAGE := $(shell mktemp --dry-run umoci.cov.XXXXXX)
endif

.PHONY: test-unit
test-unit: umociimage
	touch $(COVERAGE)
	docker run --rm -it -v $(PWD):/go/src/$(PROJECT) -e COVERAGE=$(COVERAGE) --cap-add=SYS_ADMIN $(UMOCI_IMAGE) make local-test-unit
	docker run --rm -it -v $(PWD):/go/src/$(PROJECT) -e COVERAGE=$(COVERAGE) -u 1000:1000 --cap-drop=all $(UMOCI_IMAGE) make local-test-unit

.PHONY: local-test-unit
local-test-unit:
	GO=$(GO) COVER=1 hack/test-unit.sh

.PHONY: test-integration
test-integration: umociimage
	touch $(COVERAGE)
	docker run --rm -it -v $(PWD):/go/src/$(PROJECT) -e COVERAGE=$(COVERAGE) $(UMOCI_IMAGE) make local-test-integration
	docker run --rm -it -v $(PWD):/go/src/$(PROJECT) -e COVERAGE=$(COVERAGE) -u 1000:1000 --cap-drop=all $(UMOCI_IMAGE) make local-test-integration

.PHONY: local-test-integration
local-test-integration: umoci.cover
	COVER=1 hack/test-integration.sh

shell: umociimage
	docker run --rm -it -v $(PWD):/go/src/$(PROJECT) $(UMOCI_IMAGE) bash

.PHONY: ci
ci: umoci umoci.cover validate doc test-unit test-integration
	$(GO) tool cover -func <(egrep -v 'vendor|third_party' $(COVERAGE))
