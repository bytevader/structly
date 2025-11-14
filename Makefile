.PHONY: test install-rust ensure-maturin lint format format-rust typecheck

PYTHON ?= python3

test:
	PYTHONPATH=$(PWD) pytest --cov=structly --cov-report=term-missing --cov-report=xml

format: format-rust
	isort structly tests
	black structly tests

format-rust:
	cargo fmt -- src/lib.rs

install-rust: ensure-maturin
	$(PYTHON) -m maturin develop --release

ensure-maturin:
	@$(PYTHON) -m pip show maturin >/dev/null 2>&1 || $(PYTHON) -m pip install "maturin>=1.6"
