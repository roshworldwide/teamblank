# SENTINELWIPE. Targets land phase by phase; every target here either does the
# real work or exits non-zero naming the phase that implements it. No target ever
# reports success for work that has not been done.

.DEFAULT_GOAL := help
.PHONY: help fixtures clean-fixtures test demo verify

# The fixture is generated from a seed and never committed. OUT is gitignored
# and is the ONLY path the Phase-0 write guard allows the builder to write to.
# The digests this seed must reproduce are committed in fixtures/manifest.json;
# `make fixtures` compares against them and EXITS 4 on a mismatch. A deliberate
# fixture change is rebuilt with CHECK= (which passes --no-check-expected) and
# updates that record in the same commit.
SEED ?= sentinelwipe/fixture/v1
# CHECK=--no-check-expected rebuilds a DELIBERATE change without failing.
CHECK ?=
SIZE ?= 256MiB
OUT  ?= out
IMAGE = $(OUT)/fixture.img
MANIFEST = $(OUT)/fixture.manifest.json

help:
	@echo "fixtures        build the deterministic loopback image + manifest   [Phase 1]"
	@echo "clean-fixtures  remove generated images                             [Phase 1]"
	@echo "test            pytest + cargo test                                 [Phase 2]"
	@echo "demo            the full adversarial loop, carve/wipe/carve/sign     [Phase 4]"
	@echo "verify          the pass/fail acceptance table                       [Phase 6]"
	@echo ""
	@echo "  make fixtures [SEED=... SIZE=256MiB OUT=out]"
	@echo "  -> $(IMAGE)"
	@echo "  -> $(MANIFEST)"

fixtures:
	uv run python fixtures/build_image.py --seed "$(SEED)" --size "$(SIZE)" --out "$(OUT)" $(CHECK)

# Reports what it actually removed. A message naming two files it never found
# is a claim the command did not verify, which is the shape rule 1 forbids.
clean-fixtures:
	@n=0; for f in "$(IMAGE)" "$(MANIFEST)"; do \
	  if [ -f "$$f" ]; then rm -f "$$f" && n=$$((n+1)) && echo "sentinelwipe: removed $$f"; fi; \
	done; \
	rmdir "$(OUT)" 2>/dev/null || true; \
	if [ "$$n" -eq 0 ]; then echo "sentinelwipe: nothing to remove under $(OUT)"; \
	else echo "sentinelwipe: removed $$n of 2 generated files"; fi
	@echo "sentinelwipe: fixtures/manifest.json is the committed digest record and is kept."

test:
	@echo "sentinelwipe: 'test' is implemented in Phase 2" >&2; exit 1

demo:
	@echo "sentinelwipe: 'demo' is implemented in Phase 4" >&2; exit 1

verify:
	@echo "sentinelwipe: 'verify' is implemented in Phase 6" >&2; exit 1
