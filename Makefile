# Makefile for Kubidm


CONTAINER_TOOL ?= docker
CONTAINER_TOOL_ARGS ?=
CONTAINER_BUILD_ARGS ?=
CONTAINER_IMAGE_BASE ?= kubidm
CONTAINER_IMAGE_VERSION ?= devel
CONTAINER_IMAGE_EXT_VERSION ?= $(shell cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.name == "daemon")  | .version')
# CONTAINER_BUILDX_ACTION is used to specify the action for buildx, e.g., --push or --load
CONTAINER_BUILDX_ACTION ?= --push
# CONTAINER_IMAGE_ARCH is used to specify the architectures for multi-arch docker builds
CONTAINER_IMAGE_ARCH ?= "linux/amd64,linux/arm64"
BUILDKIT_PROGRESS ?= plain

KUBIDM_FEATURES ?= ""

# MARKDOWN_FORMAT_ARGS is used to specify additional arguments for markdown formatting
MARKDOWN_FORMAT_ARGS ?=
BOOK_VERSION ?= master

GIT_COMMIT := $(shell git rev-parse HEAD)

.DEFAULT: help
.PHONY: help
help:
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'


.PHONY: config
config: ## Show makefile config things
config:
	@echo "CONTAINER_IMAGE_BASE: $(CONTAINER_IMAGE_BASE)"
	@echo "CONTAINER_IMAGE_VERSION: $(CONTAINER_IMAGE_VERSION)"
	@echo "CONTAINER_IMAGE_EXT_VERSION: $(CONTAINER_IMAGE_EXT_VERSION)"
	@echo "CONTAINER_TOOL: $(CONTAINER_TOOL)"
	@echo "CONTAINER_TOOL_ARGS: $(CONTAINER_TOOL_ARGS)"
	@echo "CONTAINER_BUILDX_ACTION: $(CONTAINER_BUILDX_ACTION)"
	@echo "CONTAINER_IMAGE_ARCH: $(CONTAINER_IMAGE_ARCH)"
	@echo "CONTAINER_BUILD_ARGS: $(CONTAINER_BUILD_ARGS)"
	@echo "MARKDOWN_FORMAT_ARGS: $(MARKDOWN_FORMAT_ARGS)"
	@echo "BUILDKIT_PROGRESS: $(BUILDKIT_PROGRESS)"
	@echo "BOOK_VERSION: $(BOOK_VERSION)"
	@echo "GIT_COMMIT: $(GIT_COMMIT)"

.PHONY: run
run: ## Run the test/dev server
run:
	scripts/run_insecure_dev_server.sh

.PHONY: run_htmx
run_htmx: ## Run in HTMX mode
run_htmx:
	KANI_CARGO_OPTS="--features kubidmd_core/ui_htmx" scripts/run_insecure_dev_server.sh

.PHONY: buildx/kubidmd
buildx/kubidmd: ## Build multiarch kubidm server images and push to docker hub
buildx/kubidmd:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull $(CONTAINER_BUILDX_ACTION) --platform $(CONTAINER_IMAGE_ARCH) \
		-f server/Dockerfile \
		-t $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_VERSION) \
		-t $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_EXT_VERSION) \
		--progress $(BUILDKIT_PROGRESS) \
		--build-arg "KUBIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KUBIDM_FEATURES=$(KUBIDM_FEATURES)" \
		--compress \
		--label "com.kubidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kubidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: buildx/kubidm_tools
buildx/kubidm_tools: ## Build multiarch kubidm tool images and push to docker hub
buildx/kubidm_tools:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull $(CONTAINER_BUILDX_ACTION) --platform $(CONTAINER_IMAGE_ARCH) \
		-f tools/Dockerfile \
		-t $(CONTAINER_IMAGE_BASE)/tools:$(CONTAINER_IMAGE_VERSION) \
		-t $(CONTAINER_IMAGE_BASE)/tools:$(CONTAINER_IMAGE_EXT_VERSION) \
		--progress $(BUILDKIT_PROGRESS) \
		--build-arg "KUBIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KUBIDM_FEATURES=$(KUBIDM_FEATURES)" \
		--label "com.kubidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kubidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: buildx/radiusd
buildx/radiusd_py: ## Build multi-arch radius docker images and push to docker hub
buildx/radiusd_py:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull $(CONTAINER_BUILDX_ACTION) --platform $(CONTAINER_IMAGE_ARCH) \
		-f rlm_python/Dockerfile \
		--progress $(BUILDKIT_PROGRESS) \
		--label "com.kubidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kubidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		-t $(CONTAINER_IMAGE_BASE)/radius:$(CONTAINER_IMAGE_VERSION) \
		-t $(CONTAINER_IMAGE_BASE)/radius:$(CONTAINER_IMAGE_EXT_VERSION) .

.PHONY: buildx/radiusd_rust
buildx/radiusd_rust: ## Build multi-arch radius docker images and push to docker hub
buildx/radiusd_rust:
	@$(CONTAINER_TOOL) buildx build $(CONTAINER_TOOL_ARGS) \
		--pull $(CONTAINER_BUILDX_ACTION) --platform $(CONTAINER_IMAGE_ARCH) \
		-f rlm_kubidm/Dockerfile \
		--progress $(BUILDKIT_PROGRESS) \
		--label "com.kubidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kubidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		-t $(CONTAINER_IMAGE_BASE)/radius:$(CONTAINER_IMAGE_VERSION) \
		-t $(CONTAINER_IMAGE_BASE)/radius:$(CONTAINER_IMAGE_EXT_VERSION) .

.PHONY: buildx
buildx: buildx/kubidmd buildx/kubidm_tools buildx/radiusd_rust

.PHONY: build/kubidmd
build/kubidmd:	## Build the kubidmd docker image locally
build/kubidmd:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) -f server/Dockerfile \
		-t $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_VERSION) \
		--build-arg "KUBIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KUBIDM_FEATURES=" \
		--label "com.kubidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kubidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .

.PHONY: build/orca
build/orca:	## Build the orca docker image locally
build/orca:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) -f tools/orca/Dockerfile \
		-t $(CONTAINER_IMAGE_BASE)/orca:$(CONTAINER_IMAGE_VERSION) \
		--build-arg "KUBIDM_BUILD_PROFILE=container_generic" \
		--build-arg "KUBIDM_FEATURES=$(KUBIDM_FEATURES)" \
		--label "com.kubidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kubidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .


# TODO remove this once the rust module's confirmed as working
.PHONY: build/radiusd
build/radiusd:	## Build the radiusd docker image locally - deprecated
build/radiusd:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) \
		-f rlm_python/Dockerfile \
		--label "com.kubidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kubidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		-t $(CONTAINER_IMAGE_BASE)/radius:$(CONTAINER_IMAGE_VERSION) .


.PHONY: build/radiusd_rust
build/radiusd_rust:	## Build the radiusd docker image locally
build/radiusd_rust:
	@$(CONTAINER_TOOL) build $(CONTAINER_TOOL_ARGS) \
		-f rlm_kubidm/Dockerfile \
		--label "com.kubidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kubidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		-t $(CONTAINER_IMAGE_BASE)/radius:$(CONTAINER_IMAGE_VERSION) .

.PHONY: build
build: build/kubidmd build/radiusd

.PHONY: test/kubidmd
test/kubidmd: ## Run cargo test in docker
test/kubidmd:
	@$(CONTAINER_TOOL) build \
		$(CONTAINER_TOOL_ARGS) -f server/Dockerfile \
		--target builder \
		-t $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_VERSION)-builder \
		--label "com.kubidm.git-commit=$(GIT_COMMIT)" \
		--label "com.kubidm.version=$(CONTAINER_IMAGE_EXT_VERSION)" \
		$(CONTAINER_BUILD_ARGS) .
	@$(CONTAINER_TOOL) run --rm $(CONTAINER_IMAGE_BASE)/server:$(CONTAINER_IMAGE_VERSION)-builder cargo test

.PHONY: test/radiusd
test/radiusd: ## Run a test radius server
test/radiusd: build/radiusd
	cd rlm_python && \
	./run_radius_container.sh

.PHONY: test/radius/e2e
test/radius/e2e: ## Run end-to-end RADIUS integration tests
test/radius/e2e:
	./scripts/test_radius.sh

.PHONY: test
test:
	cargo test

.PHONY: precommit
precommit: ## all the usual test things
precommit: test codespell test/pykubidm doc/format

.PHONY: vendor
vendor: ## Vendor required crates
vendor:
	cargo vendor > cargo_vendor_config

.PHONY: vendor-prep
vendor-prep: vendor
	tar -cJf vendor.tar.xz vendor

.PHONY: install-tools
install-tools: ## install kubidm_tools in your local environment
install-tools:
	cargo install --path tools/cli --force

.PHONY: codespell
codespell: ## spell-check things.
codespell:
	codespell -c \
	-D .codespell_dictionary \
	--ignore-words .codespell_ignore \
	--skip='./target,./pykubidm/.venv,./pykubidm/.mypy_cache,./.mypy_cache,./pykubidm/uv.lock' \
	--skip='./book/*.js' \
	--skip='./book/book/*' \
	--skip='./book/src/images/*' \
	--skip='./docs/*,./.git' \
	--skip='*.svg' \
	--skip='*.br' \
	--skip='./rlm_python/mods-available/eap' \
	--skip='./server/lib/src/constants/system_config.rs' \
	--skip='./pykubidm/site'

.PHONY: test/pykubidm/pytest
test/pykubidm/pytest: ## python library testing
	cd pykubidm && \
	uv run pytest -vv

.PHONY: test/pykubidm/lint
test/pykubidm/lint: ## python library linting
	cd pykubidm && \
	uv run ruff check tests kubidm

.PHONY: test/pykubidm/typecheck
test/pykubidm/typecheck: ## python library type checking
	cd pykubidm && \
	uv run ty check tests kubidm \
		--ignore unused-type-ignore-comment

.PHONY: test/pykubidm
test/pykubidm: ## run the kubidm python module test suite (typecheck/lint/pytest)
test/pykubidm: test/pykubidm/pytest test/pykubidm/typecheck test/pykubidm/lint

.PHONY: test/pykubidm/coverage
test/pykubidm/coverage: ## run the Kubidm Python module test suite with coverage
	cd pykubidm && \
	uv run coverage run -m pytest && \
	uv run coverage html

########################################################################

.PHONY: doc
doc: ## Build the rust documentation locally
doc:
	cargo doc --document-private-items

.PHONY: doc/find
doc/find: ## Find all markdown files for docs
	@find . -type f  \
		-not -path './target/*' \
		-not -path './docs/*' \
		-not -path '*/node_modules/*' \
		-not -path '*/.venv/*' -not -path './vendor/*'\
		-not -path '*/.*/*' \
		-name '*.md'

.PHONY: doc/format
doc/format: ## Format docs and the Kubidm book
	make doc/find | xargs deno fmt --check $(MARKDOWN_FORMAT_ARGS)

.PHONY: doc/format/fix
doc/format/fix: ## Fix docs and the Kubidm book
	make doc/find | xargs  deno fmt  $(MARKDOWN_FORMAT_ARGS)

.PHONY: book
book: ## Build the Kubidm book
book:
	echo "Building rust docs"
	cargo doc --no-deps --quiet
	mdbook build book
	rm -rf ./docs/
	mv ./book/book/ ./docs/
	mkdir -p $(PWD)/docs/rustdoc/${BOOK_VERSION}/
	rsync -a --delete $(PWD)/target/doc/ $(PWD)/docs/rustdoc/${BOOK_VERSION}/

.PHONY: book_versioned
book_versioned:
	echo "Book version: ${BOOK_VERSION}"
	rm -rf ./target/doc
	git switch -c "${BOOK_VERSION}"
	git pull origin "${BOOK_VERSION}"
	cargo doc --no-deps --quiet
	mdbook build book
	rm -rf ./docs/
	mkdir -p ./docs
	mv ./book/book/ ./docs/${BOOK_VERSION}/
	mkdir -p ./docs/${BOOK_VERSION}/rustdoc/
	mv ./target/doc/* ./docs/${BOOK_VERSION}/rustdoc/
	git switch master

.PHONY: clean_book
clean_book:
	rm -rf ./docs

.PHONY: docs/pykubidm/build
docs/pykubidm/build: ## Build the mkdocs
docs/pykubidm/build:
	cd pykubidm && \
	uv run --group docs mkdocs build

.PHONY: docs/pykubidm/serve
docs/pykubidm/serve: ## Run the local mkdocs server
docs/pykubidm/serve:
	cd pykubidm && \
	uv run --group docs mkdocs serve

########################################################################

.PHONY: release/prep
prep:
	cargo outdated -R
	cargo audit

.PHONY: release/kubidm
release/kubidm: ## Build the Kubidm CLI - ensure you include the environment variable KUBIDM_BUILD_PROFILE
	cargo build -p kubidm_tools --bin kubidm --release

.PHONY: release/kubidmd
release/kubidmd: ## Build the Kubidm daemon - ensure you include the environment variable KUBIDM_BUILD_PROFILE
	cargo build -p daemon --bin kubidmd --release

.PHONY: release/kubidm-ssh
release/kubidm-ssh: ## Build the Kubidm SSH tools - ensure you include the environment variable KUBIDM_BUILD_PROFILE
	cargo build --release \
		--bin kubidm_ssh_authorizedkeys \
		--bin kubidm_ssh_authorizedkeys_direct

.PHONY: release/kubidm-unixd
release/kubidm-unixd: ## Build the Kubidm UNIX tools - ensure you include the environment variable KUBIDM_BUILD_PROFILE
release/kubidm-unixd:
	cargo build -p pam_kubidm --release
	cargo build -p nss_kubidm --release
	cargo build --features unix -p kubidm_unix_int --release \
		--bin kubidm_unixd \
		--bin kubidm_unixd_tasks \
		--bin kubidm-unix

# cert things

.PHONY: cert/clean
cert/clean: ## clean out the insecure cert bits
cert/clean:
	rm -f /tmp/kubidm/*.pem
	rm -f /tmp/kubidm/*.cnf
	rm -f /tmp/kubidm/*.csr
	rm -f /tmp/kubidm/ca.txt*
	rm -f /tmp/kubidm/ca.{cnf,srl,srl.old}


.PHONY: coverage
coverage: ## Run the coverage tests using cargo-tarpaulin
	cargo tarpaulin --out Html
	@echo "Coverage file at file://$(PWD)/tarpaulin-report.html"


.PHONY: coveralls
coveralls: ## Run cargo tarpaulin and upload to coveralls
coveralls:
	cargo tarpaulin --coveralls $(COVERALLS_REPO_TOKEN)
	@echo "Coveralls repo information is at https://coveralls.io/github/kubidm/kubidm"


.PHONY: eslint
eslint: ## Run eslint on the UI javascript things
eslint:
	@echo "################################"
	@echo "   Running eslint..."
	@echo "################################"
	cd server/core && find ./static -name '*js' -not -path '*/external/*' -exec pnpm exec eslint "{}" \;
	@echo "################################"
	@echo "Done!"

.PHONY: prettier
prettier: ## Run prettier on the UI javascript things and write back changes
prettier:
	@echo "   Running prettier..."
	cd server/core && pnpm run prettier:fix
	@echo "Done!"

.PHONY: publish
publish: ## Publish to crates.io
publish:
	cargo publish -p sketching
	cargo publish -p scim_proto
	cargo publish -p kubidm_build_profiles
	cargo publish -p kubidm_proto
	cargo publish -p kubidm_utils_users
	cargo publish -p kubidm_lib_file_permissions
	cargo publish -p kubidm_lib_crypto
	cargo publish -p kubidm_client
	cargo publish -p kubidm_tools

.PHONY: rust_container
rust_container: # Build and run a container based on the Linux rust base container, with our requirements included
rust_container:
	docker build --pull -t kubidm_rust -f scripts/Dockerfile.devcontainer .
	docker run \
		--rm -it \
		--name kubidm \
		--mount type=bind,source=$(PWD),target=/kubidm -w /kubidm kubidm_rust:latest
