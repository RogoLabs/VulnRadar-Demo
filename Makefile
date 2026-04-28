.PHONY: help test lint fmt typecheck etl notify clean install dev

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install runtime dependencies
	pip install -r requirements.txt

dev: ## Install all dependencies (runtime + dev) in editable mode
	pip install -e ".[dev]"
	pre-commit install

test: ## Run tests
	pytest -v --tb=short

lint: ## Run linter
	ruff check .

fmt: ## Auto-format code
	ruff format .
	ruff check --fix .

typecheck: ## Run type checker
	mypy etl.py notify.py vulnradar/ --ignore-missing-imports

etl: ## Run ETL pipeline
	python etl.py

notify: ## Run notification pipeline
	python notify.py --in data/radar_data.json

clean: ## Remove caches and build artifacts
	rm -rf __pycache__ vulnradar/__pycache__ tests/__pycache__
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	rm -rf build/ dist/ *.egg-info
