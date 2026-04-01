.PHONY: build test smoke ci-local clean docker-build docker-push helm-package terraform-init

# Build the detection engine
build:
	@echo "Building iota..."
	@mkdir -p bin
	@CGO_ENABLED=1 go build -o bin/iota ./cmd/iota
	@echo "✓ Built bin/iota"

# Run tests (unit / package tests; set CGO_ENABLED=1 locally if sqlite/duckdb tests fail)
test:
	@CGO_ENABLED=1 go test -v ./...

# End-to-end smoke: build + once mode on testdata (same as CI)
smoke:
	@chmod +x scripts/smoke.sh 2>/dev/null || true
	@./scripts/smoke.sh

# Clean build artifacts
clean:
	@rm -rf bin/
	@echo "✓ Cleaned build artifacts"

# Docker build
docker-build:
	@echo "Building Docker image..."
	@docker build -t iota:latest .
	@echo "✓ Built iota:latest"

# Docker push to Docker Hub (requires DOCKERHUB_USERNAME)
docker-push-dockerhub:
	@if [ -z "$(DOCKERHUB_USERNAME)" ]; then \
		echo "ERROR: DOCKERHUB_USERNAME not set"; \
		echo "Usage: make docker-push-dockerhub DOCKERHUB_USERNAME=yourusername IMAGE_TAG=v0.1.0"; \
		exit 1; \
	fi
	@IMAGE_TAG=$(or $(IMAGE_TAG),latest); \
	docker tag iota:latest $(DOCKERHUB_USERNAME)/iota:$$IMAGE_TAG; \
	docker push $(DOCKERHUB_USERNAME)/iota:$$IMAGE_TAG; \
	echo "✓ Pushed $(DOCKERHUB_USERNAME)/iota:$$IMAGE_TAG"

# Docker push to ECR (requires IMAGE_REPO variable)
docker-push-ecr:
	@if [ -z "$(IMAGE_REPO)" ]; then \
		echo "ERROR: IMAGE_REPO not set"; \
		echo "Usage: make docker-push-ecr IMAGE_REPO=123456789012.dkr.ecr.us-east-1.amazonaws.com/iota IMAGE_TAG=v0.1.0"; \
		exit 1; \
	fi
	@IMAGE_TAG=$(or $(IMAGE_TAG),latest); \
	docker tag iota:latest $(IMAGE_REPO):$$IMAGE_TAG; \
	docker push $(IMAGE_REPO):$$IMAGE_TAG; \
	echo "✓ Pushed $(IMAGE_REPO):$$IMAGE_TAG"

# Docker push to GitHub Container Registry (requires GITHUB_USERNAME)
docker-push-ghcr:
	@if [ -z "$(GITHUB_USERNAME)" ]; then \
		echo "ERROR: GITHUB_USERNAME not set"; \
		echo "Usage: make docker-push-ghcr GITHUB_USERNAME=yourusername IMAGE_TAG=v0.1.0"; \
		exit 1; \
	fi
	@IMAGE_TAG=$(or $(IMAGE_TAG),latest); \
	docker tag iota:latest ghcr.io/$(GITHUB_USERNAME)/iota:$$IMAGE_TAG; \
	docker push ghcr.io/$(GITHUB_USERNAME)/iota:$$IMAGE_TAG; \
	echo "✓ Pushed ghcr.io/$(GITHUB_USERNAME)/iota:$$IMAGE_TAG"

# Docker push (generic - requires IMAGE_REPO variable)
docker-push:
	@if [ -z "$(IMAGE_REPO)" ]; then \
		echo "ERROR: IMAGE_REPO not set"; \
		echo "Usage: make docker-push IMAGE_REPO=registry/namespace/iota IMAGE_TAG=v0.1.0"; \
		echo ""; \
		echo "Or use specific targets:"; \
		echo "  make docker-push-dockerhub DOCKERHUB_USERNAME=yourusername"; \
		echo "  make docker-push-ecr IMAGE_REPO=123456789012.dkr.ecr.us-east-1.amazonaws.com/iota"; \
		echo "  make docker-push-ghcr GITHUB_USERNAME=yourusername"; \
		exit 1; \
	fi
	@IMAGE_TAG=$(or $(IMAGE_TAG),latest); \
	docker tag iota:latest $(IMAGE_REPO):$$IMAGE_TAG; \
	docker push $(IMAGE_REPO):$$IMAGE_TAG; \
	echo "✓ Pushed $(IMAGE_REPO):$$IMAGE_TAG"

# Helm package
helm-package:
	@echo "Packaging Helm chart..."
	@helm package helm/iota
	@echo "✓ Packaged helm/iota"

# Terraform init
terraform-init:
	@echo "Initializing Terraform..."
	@cd terraform && terraform init
	@echo "✓ Terraform initialized"

# Run detection engine (once mode); build first: make build
run-once:
	@./bin/iota --mode=once --jsonl=testdata/sample.jsonl --rules=rules/aws_cloudtrail --python=python3 --engine=engines/iota/engine.py

# Run detection engine (watch mode)
run-watch:
	@./bin/iota --mode=watch --events-dir=./testdata/events --rules=rules/aws_cloudtrail --python=python3 --engine=engines/iota/engine.py

# Run all checks before commit (unit tests + smoke + release binary)
pre-commit: test smoke build
	@echo "✓ All pre-commit checks passed"

# Lint code
lint:
	@golangci-lint run

# Format code
fmt:
	@go fmt ./...
	@echo "✓ Formatted code"

# Run tests with coverage
test-coverage:
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report generated: coverage.html"

# Validate Dockerfile
docker-validate:
	@hadolint Dockerfile || echo "Install hadolint: https://github.com/hadolint/hadolint"

# Run all validation checks (fmt, lint, unit tests; no smoke)
validate: fmt lint test
	@echo "✓ All validation checks passed"

# Everything CI exercises locally: validate + smoke
ci-local: validate smoke
	@echo "✓ ci-local passed"
