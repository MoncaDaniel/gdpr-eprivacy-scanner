.PHONY: install browsers lint fmt typecheck test test-unit test-integration cov check scan collect docs golden

install:
	uv sync --all-groups

browsers:
	uv run playwright install chromium

lint:
	uv run ruff check .
	uv run ruff format --check .

fmt:
	uv run ruff check --fix .
	uv run ruff format .

typecheck:
	uv run mypy

test:
	uv run pytest

test-unit:
	uv run pytest tests/unit tests/golden

# Regenerate golden reports after an intended rule/catalog/knowledge change.
golden:
	UPDATE_GOLDEN=1 uv run pytest tests/golden

test-integration:
	uv run pytest -m integration

cov:
	uv run pytest --cov --cov-report=term-missing

check: lint typecheck test

# make scan URL=https://www.cnil.fr
scan:
	uv run privacy-scanner scan $(URL)

# make collect URL=https://www.cnil.fr  (evidence only)
collect:
	uv run privacy-scanner collect $(URL)

# Regenerate docs/legal/rule-catalog.md from the YAML catalog.
docs:
	uv run python -m privacy_scanner.rules.catalog_docs > docs/legal/rule-catalog.md
