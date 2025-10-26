.PHONY: test install-rust ensure-maturin

PYTHON ?= python3

test:
	PYTHONPATH=$(PWD) pytest --cov=structly --cov-report=term-missing

install-rust: ensure-maturin
	$(PYTHON) -m maturin develop --release

ensure-maturin:
	@$(PYTHON) -m pip show maturin >/dev/null 2>&1 || $(PYTHON) -m pip install "maturin>=1.6"
