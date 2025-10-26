.PHONY: test install-rust ensure-maturin lint format typecheck

PYTHON ?= python3

test:
	PYTHONPATH=$(PWD) pytest --cov=structly --cov-report=term-missing

format:
	black structly tests

install-rust: ensure-maturin
	$(PYTHON) -m maturin develop --release

ensure-maturin:
	@$(PYTHON) -m pip show maturin >/dev/null 2>&1 || $(PYTHON) -m pip install "maturin>=1.6"
