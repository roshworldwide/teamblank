# SENTINELWIPE. Targets land phase by phase; every target here either does the
# real work or exits non-zero naming the phase that implements it. No target ever
# reports success for work that has not been done.

.DEFAULT_GOAL := help
.PHONY: help fixtures clean-fixtures build test ui ui-serve ui-check app demo verify

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
	@echo "fixtures        build the deterministic loopback image + manifest"
	@echo "clean-fixtures  remove generated images"
	@echo "build           cargo build --release (carve + wipe)"
	@echo "test            cargo test + pytest"
	@echo ""
	@echo "ui              run the engine, rebuild the pages from THAT run, open them"
	@echo "ui-serve        serve ui/ on http://localhost:8787 (no build step, no network)"
	@echo "ui-check        token-drift check + payload freshness, no engine run"
	@echo "demo            the adversarial loop end to end, then open the instrument"
	@echo "verify          the loop + signature + chain, clean passes and forged fails"
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

build:
	cd core && cargo build --release -p sentinelwipe-carve -p sentinelwipe-wipe

test:
	cd core && cargo test --release
	uv run pytest tests/ -q

# The pages are self-contained by design -- one file, no build step, no network,
# so they open from a USB stick on an air-gapped machine. That makes the payload
# and the token layer COPIES, so this is the regeneration step AND the drift
# detector: a page whose gold is one digit off from ui/tokens.css exits 4.
ui-check:
	uv run python ui/inline.py

# Runs the engine and rebuilds the pages from what it produced. The wipe targets
# a COPY under $(OUT)/ui-run; out/fixture.img is never a target and its sha256 is
# re-verified afterwards.
ui: build
	uv run python ui/refresh.py
	@echo ""
	@echo "sentinelwipe: opening the two surfaces"
	@open ui/approach.html ui/instrument.html 2>/dev/null || \
	 xdg-open ui/approach.html 2>/dev/null || \
	 echo "  open these by hand: ui/approach.html  ui/instrument.html"

# file:// is enough for both pages. This target exists for the case where a
# browser policy blocks local file reads; it serves the SAME files unchanged.
ui-serve:
	@echo "sentinelwipe: http://localhost:8787/instrument.html  (ctrl-C to stop)"
	@cd ui && uv run python -m http.server 8787 --bind 127.0.0.1

# CLAUDE.md's six steps, all real: the loop runs through core/verify with
# parameter identity by construction, the certificate is Ed25519-signed with
# the custody statement inside the signed bytes, and the chain head is
# published. The forge button edits the presented copy of the canonical
# bytes and the divergence is shown by name.
# The desktop shell: the two pages in a native window over the platform webview.
# No Chromium bundle, no network, runs on an air-gapped machine with nothing
# installed. Needs tauri-cli once: cargo install tauri-cli --locked
app:
	@command -v cargo-tauri >/dev/null || { \
	  echo "sentinelwipe: tauri-cli not installed. Once: cargo install tauri-cli --locked" >&2; exit 3; }
	uv run python desktop/stage.py
	cd desktop && cargo tauri build --bundles app
	@echo ""
	@ls -d desktop/target/release/bundle/macos/*.app 2>/dev/null | head -1 | \
	  xargs -I{} sh -c 'echo "sentinelwipe: {} ($$(du -sh "{}" | cut -f1))"'

demo: build
	@echo "── 1 · a 256 MB image, 40 planted files of known SHA-256. Nothing is mounted."
	@test -f "$(IMAGE)" || $(MAKE) --no-print-directory fixtures
	@echo "── 2 · carve  ── 3 · wipe with telemetry  ── 4 · carve again, same parameters"
	uv run python ui/refresh.py
	@echo "── 5 · sign            Ed25519 over RFC 8785 canonical bytes; chained."
	@echo "        Custody stated inside the signature: integrity since signing,"
	@echo "        not authority of the signer. Audit: verify --audit <bundle>."
	@echo "── 6 · tamper          open VERDICT, press 'Forge whole_medium_claim':"
	@echo "        signature invalid, field named, both digests, ledger intact."
	@echo ""
	@open ui/instrument.html 2>/dev/null || xdg-open ui/instrument.html 2>/dev/null || \
	 echo "open ui/instrument.html"

# The acceptance loop: carve, wipe, carve again with identical parameters,
# sign, chain — then audit the bundle from cold, twice: the clean bundle must
# pass and a forged copy must fail, so a broken auditor cannot pass quietly.
verify: build
	@test -f "$(IMAGE)" || $(MAKE) --no-print-directory fixtures
	@rm -rf $(OUT)/verify-run && mkdir -p $(OUT)/verify-run
	@cp "$(IMAGE)" $(OUT)/verify-run/medium.img
	./core/target/release/verify \
	  --target $(OUT)/verify-run/medium.img \
	  --allow-root $(OUT)/verify-run \
	  --i-understand $(OUT)/verify-run/medium.img \
	  --manifest "$(MANIFEST)" \
	  --chain $(OUT)/verify-run/chain.txt \
	  --key $(OUT)/verify-run/operator.key \
	  --out $(OUT)/verify-run/bundle.json
	./core/target/release/verify --audit $(OUT)/verify-run/bundle.json
	@sed 's/"whole_medium_claim":false/"whole_medium_claim":true/' \
	  $(OUT)/verify-run/bundle.json > $(OUT)/verify-run/bundle_forged.json
	@if ./core/target/release/verify --audit $(OUT)/verify-run/bundle_forged.json \
	    >/dev/null 2>&1; then \
	  echo "sentinelwipe: FORGED BUNDLE PASSED THE AUDIT — the verifier is broken" >&2; \
	  exit 1; \
	else \
	  echo "sentinelwipe: forged copy refused, clean bundle proved — verify PASS"; \
	fi
