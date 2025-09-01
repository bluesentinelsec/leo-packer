# Makefile for leo-packer

VENV = .venv
PYTHON = $(VENV)/bin/python3
PIP = $(VENV)/bin/pip
PYTEST = $(VENV)/bin/pytest

.PHONY: venv install test clean

venv:
	python3 -m venv $(VENV)

install: venv
	$(PIP) install --upgrade pip
	$(PIP) install -e .[dev]

test: install
	$(PYTEST)

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache dist build *.egg-info

