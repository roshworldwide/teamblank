# SENTINELWIPE. Targets land phase by phase; every target here either does the
# real work or exits non-zero naming the phase that implements it. No target ever
# reports success for work that has not been done.

.DEFAULT_GOAL := help
.PHONY: help fixtures clean-fixtures test demo verify

help:
	@echo "fixtures        build the deterministic loopback image + manifest   [Phase 1]"
	@echo "clean-fixtures  remove generated images                             [Phase 1]"
	@echo "test            pytest + cargo test                                 [Phase 2]"
	@echo "demo            the full adversarial loop, carve/wipe/carve/sign     [Phase 4]"
	@echo "verify          the pass/fail acceptance table                       [Phase 6]"

fixtures clean-fixtures:
	@echo "sentinelwipe: '$@' is implemented in Phase 1" >&2; exit 1

test:
	@echo "sentinelwipe: 'test' is implemented in Phase 2" >&2; exit 1

demo:
	@echo "sentinelwipe: 'demo' is implemented in Phase 4" >&2; exit 1

verify:
	@echo "sentinelwipe: 'verify' is implemented in Phase 6" >&2; exit 1
