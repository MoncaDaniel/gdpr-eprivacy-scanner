.PHONY: install browsers lint fmt typecheck test test-unit test-integration cov check scan

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
	uv run pytest tests/unit

test-integration:
	uv run pytest -m integration

cov:
	uv run pytest --cov --cov-report=term-missing

check: lint typecheck test

# make scan URL=https://www.cnil.fr
scan:
	uv run privacy-scanner collect $(URL)
