.PHONY: release check test lint typecheck build clean help

VERSION ?=

help:
	@echo "Usage:"
	@echo "  make release VERSION=x.y.z  - Release a new version"
	@echo "  make check                  - Run all quality checks"
	@echo "  make test                   - Run tests"
	@echo "  make lint                   - Run linter"
	@echo "  make typecheck              - Run type checker"
	@echo "  make build                  - Build package"
	@echo "  make clean                  - Clean build artifacts"

release:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make release VERSION=x.y.z"; exit 1; fi
	@echo "🚀 Releasing v$(VERSION)..."
	@$(MAKE) check
	@python scripts/release.py $(VERSION)
	@git add -A
	@git commit -m "chore: release v$(VERSION)"
	@git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	@git push origin main --tags
	@echo ""
	@echo "✅ Release v$(VERSION) pushed!"
	@echo "   GitHub Actions will now:"
	@echo "   1. Run tests"
	@echo "   2. Create GitHub Release"
	@echo "   3. Publish to PyPI"

check: test lint typecheck
	@echo "✅ All checks passed"

test:
	@echo "🧪 Running tests..."
	@uv run pytest -v

lint:
	@echo "🔍 Running linter..."
	@uv run ruff check codesdevs_log_analyzer tests

typecheck:
	@echo "📝 Running type checker..."
	@uv run python -m mypy codesdevs_log_analyzer --strict

build:
	@echo "📦 Building package..."
	@uv build

clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf dist/ build/ *.egg-info .pytest_cache .mypy_cache .ruff_cache
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Clean complete"
