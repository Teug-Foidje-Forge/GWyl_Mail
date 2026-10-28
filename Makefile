.PHONY: help install dev test test-poc lint format clean run-tests doctor \
        integrity-install integrity-install-pre-commit integrity-install-pre-push \
        integrity-baseline integrity-commit

help:
	@echo "GWyl Mail - Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install     Install production dependencies"
	@echo "  dev         Install development dependencies"
	@echo "  test        Run tests with coverage"
	@echo "  test-poc    Run the PoC validation suite (tests + benchmarks when present)"
	@echo "  doctor      Check environment (cosign, ots, python packages, network)"
	@echo "  ui          Local interface on 127.0.0.1:8765"
	@echo "  lint        Run linters (ruff, black, mypy)"
	@echo "  format      Format code (black)"
	@echo "  clean       Clean build artifacts"
	@echo "  run-tests   Run specific test file (e.g., make run-tests TEST=test_canonical)"
	@echo "  integrity-install  Install local pre-commit & pre-push hooks"
	@echo "  integrity-install-pre-commit  Install only pre-commit hook"
	@echo "  integrity-install-pre-push    Install only pre-push hook (OTS upgrade)"
	@echo "  integrity-baseline Regenerate baseline + snapshot + meta (no commit)"
	@echo "  integrity-commit   Commit using commit_with_integrity.sh (MSG=...)"

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	pytest

test-poc:
	pytest
	@if [ -f scripts/benchmark.py ]; then \
	  echo "[test-poc] Running KPI benchmarks (KPI_POC.md thresholds)..."; \
	  python scripts/benchmark.py; \
	else \
	  echo "[test-poc] benchmarks not implemented yet (planned Sprint 10, scripts/benchmark.py)"; \
	fi

doctor:
	python -m gwyl_mail.cli doctor

ui:
	python -m gwyl_mail.cli ui

lint:
	ruff check gwyl_mail tests
	black --check gwyl_mail tests
	mypy gwyl_mail

format:
	black gwyl_mail tests

clean:
	rm -rf build/ dist/ *.egg-info
	rm -rf .pytest_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

run-tests:
	pytest tests/$(TEST).py -v

# ----------------------------------------------------------------------------
# Integrity helpers
# ----------------------------------------------------------------------------
integrity-install-pre-commit:
	@echo "[integrity] Installing local pre-commit hook (uses Temporary_Integrity/unified_integrity.py)"
	@mkdir -p .git/hooks
	@printf '#!/usr/bin/env bash\nset -euo pipefail\nTOOL="$$PWD/Temporary_Integrity/unified_integrity.py"\necho "[pre-commit] Running integrity check..."\npython "$$TOOL" check || { echo "[pre-commit] Integrity check failed. Aborting commit." >&2; exit 1; }\n' > .git/hooks/pre-commit
	@chmod +x .git/hooks/pre-commit
	@echo "[integrity] pre-commit installed."

integrity-install-pre-push:
	@echo "[integrity] Installing local pre-push hook (OTS upgrade)"
	@mkdir -p .git/hooks
	@printf '#!/usr/bin/env bash\nset -euo pipefail\ncount=0\nupgrade_dir() {\n  dir="$$1"\n  if [ -d "$$dir" ]; then\n    for f in "$$dir"/*.ots; do\n      [ -e "$$f" ] || continue\n      if command -v ots >/dev/null 2>&1; then\n        echo "[pre-push] ots upgrade $$f"\n        ots upgrade "$$f" || true\n        count=$$((count+1))\n      fi\n    done\n  fi\n}\nupgrade_dir logs/anchors/ots\nupgrade_dir .gwyl_mail/proofs/ots\nif [ "$$count" -gt 0 ]; then\n  echo "[pre-push] Upgraded $$count OTS proofs"\nelse\n  echo "[pre-push] No OTS proofs to upgrade"\nfi\n' > .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "[integrity] pre-push installed."

integrity-install: integrity-install-pre-commit integrity-install-pre-push

integrity-baseline:
	@echo "[integrity] Regenerating baseline (original + committed + meta)"
	@find . -type f \( -name "*.py" -o -name "*.md" -o -name "*.yml" -o -name "*.yaml" -o -name "*.json" -o -name "*.toml" -o -name "*.sh" -o -name "*.txt" \) \
	  -not -path "./.git/*" \
	  -not -path "./.venv/*" \
	  -not -path "./htmlcov/*" \
	  -not -path "./__pycache__/*" \
	  -not -path "./.pytest_cache/*" \
	  -not -path "./.gwyl_mail/*" \
	  -not -path "./logs/*" \
	  -not -path "./.claude/*" \
	  -print0 | sort -z | xargs -0 sha256sum > SECURITY_INTEGRITY_BASELINE.sha256
	@cp SECURITY_INTEGRITY_BASELINE.sha256 SECURITY_INTEGRITY_BASELINE.sha256.committed
	@cmp -s SECURITY_INTEGRITY_BASELINE.sha256 SECURITY_INTEGRITY_BASELINE.sha256.committed && echo "[integrity] Snapshot OK" || (echo "[integrity] Snapshot mismatch" >&2; exit 1)
	@NEW_COMMITTED_HASH=$$(sha256sum SECURITY_INTEGRITY_BASELINE.sha256.committed | cut -d' ' -f1); \
	  FILE_COUNT=$$(wc -l < SECURITY_INTEGRITY_BASELINE.sha256); \
	  { \
	    echo "baseline_committed_sha256=$$NEW_COMMITTED_HASH"; \
	    echo "baseline_committed_file=SECURITY_INTEGRITY_BASELINE.sha256.committed"; \
	    echo "baseline_committed_lines=$$FILE_COUNT"; \
	    echo "commit_hash=pending"; \
	    echo "committed_at=$$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
	  } > SECURITY_INTEGRITY_BASELINE.sha256.meta
	@echo "[integrity] Baseline + snapshot + meta ready. Stage and commit when ready."

integrity-commit:
	@[ -n "$(MSG)" ] || (echo "Usage: make integrity-commit MSG=\"your message\"" >&2; exit 1)
	./Temporary_Integrity/commit_with_integrity.sh "$(MSG)"
