# Makefile for leo-packer

VENV = .venv
PYTHON = $(VENV)/bin/python3
PIP = $(VENV)/bin/pip
PYTEST = $(VENV)/bin/pytest

.PHONY: venv install test clean profile profile-report

venv:
	python3 -m venv $(VENV)

install: venv
	$(PIP) install --upgrade pip
	$(PIP) install -e .[dev]

test: install
	$(PYTEST)

clean:
	rm -rf $(VENV) .pytest_cache .mypy_cache dist build *.egg-info profile.out profile.txt

# ----------------------------------------------------------
# Profile the packer using cProfile.
# Usage example:
#   make profile ARGS="pack mydir out.leopack --compress"
# ----------------------------------------------------------
profile: install
	$(PYTHON) -m cProfile -o profile.out -m leo_packer.cli $(ARGS)
	@echo "Profile written to profile.out"
	@$(MAKE) profile-report

# ----------------------------------------------------------
# Generate a human-readable profile report
# ----------------------------------------------------------
profile-report:
	$(PYTHON) -c "import pstats; \
s=pstats.Stats('profile.out'); \
s.sort_stats('cumtime').print_stats(30)" > profile.txt
	@echo "Profile summary written to profile.txt"

