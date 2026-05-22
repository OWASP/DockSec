.DEFAULT_GOAL := help

.PHONY: help install check test scan clean

##@ Getting Started

help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?## / { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

install: ## Install dependencies
	pip install -e .
	pip install -r requirements.txt
	pip install pytest pytest-cov black isort flake8 mypy

##@ Quality Control

check: ## Run all code quality checks (linters)
	black --check .
	isort --check-only .
	flake8 .
	mypy .

test: ## Run all tests
	pytest tests/

check-test: ## Run all checks and tests
	$(MAKE) check
	$(MAKE) test

##@ Security

scan: ## Run DockSec on its own Dockerfile (if exists)
	@if [ -f Dockerfile ]; then \
		docksec Dockerfile; \
	else \
		echo "No Dockerfile found in root."; \
	fi

security-scan: ## Run security scans (Semgrep and Trivy)
	@echo "Running Semgrep security scan..."
	semgrep --config p/ci .
	@echo "Running Trivy security scan..."
	trivy fs .

##@ Cleanup

clean: ## Remove generated files
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache
	rm -rf .mypy_cache
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name "__pycache__" -exec rm -rf {} +
