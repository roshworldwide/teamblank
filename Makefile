.DEFAULT_GOAL := help
.PHONY: help fixtures clean-fixtures build test ui ui-serve ui-check ui-render app demo verify

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
	@echo "ui-render       render ui/recover.html in a browser and measure it"
	@echo "demo            the adversarial loop end to end, then open the instrument"
	@echo "verify          the loop + signature + chain, clean passes and forged fails"
	@echo ""
	@echo "  make fixtures [SEED=... SIZE=256MiB OUT=out]"
	@echo "  -> $(IMAGE)"
	@echo "  -> $(MANIFEST)"

fixtures:
	uv run python fixtures/build_image.py --seed "$(SEED)" --size "$(SIZE)" --out "$(OUT)" $(CHECK)

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

ui-check:
	uv run python ui/inline.py

ui-render:
	uv run --no-project --with playwright python -m playwright install chromium
	uv run --no-project --with playwright --with pytest python -m pytest \
	    tests/test_recover_render.py -q

ui: build
	uv run python ui/refresh.py
	@echo ""
	@echo "sentinelwipe: opening the two surfaces"
	@open ui/approach.html ui/instrument.html 2>/dev/null || \
	 xdg-open ui/approach.html 2>/dev/null || \
	 echo "  open these by hand: ui/approach.html  ui/instrument.html"

ui-serve:
	@echo "sentinelwipe: http://localhost:8787/instrument.html  (ctrl-C to stop)"
	@cd ui && uv run python -m http.server 8787 --bind 127.0.0.1

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
