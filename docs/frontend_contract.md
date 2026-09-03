# Frontend contract

Every schema field the UI reads, so a schema change breaks a **documented** dependency
rather than a silent one. Generated from `ui/payload.json` by `ui/build_payload.py` —
never hand-maintained, so it cannot drift from what the pages actually bind to.

The UI reads **only** this payload. It never reads the engine directly, and it never reads
a field that is not listed below. Regenerate after any schema change:

```sh
uv run python ui/build_payload.py <live-artifact-dir>
```

**326 bound fields** across 17 blocks.

---


## `meta` — 6 fields

*source: (generated)*


| field | type | value on the fixture |
|---|---|---|
| `meta.note` | str | `'Every value in this file was read out` |
| `meta.sources.lie` | str | `'docs/evidence/fake_sanitize_run.txt'` |
| `meta.sources.carve` | str | `'fixtures/sample_output.json'` |
| `meta.sources.wipe` | str | `'a live run of core/target/release/wip` |
| `meta.schemas.carve` | str | `'sentinelwipe.carve.report/1'` |
| `meta.schemas.wipe` | str | `'sentinelwipe.wipe.report/1'` |


## `lie` — 54 fields

*source: docs/evidence/fake_sanitize_run.txt → sentinelwipe.wipe.report/1*


| field | type | value on the fixture |
|---|---|---|
| `lie.command` | str | `'wipe --target <root>/t2.img --allow-r` |
| `lie.primitive` | str | `'ata-sanitize-block-erase'` |
| `lie.device_reported_success` | bool | `True` |
| `lie.sanitize.operation` | str | `'ATA SANITIZE BLOCK ERASE (simulated)'` |
| `lie.sanitize.code` | str | `'UNVERIFIED_TIMING'` |
| `lie.sanitize.severity` | str | `'unverified'` |
| `lie.sanitize.simulated` | bool | `True` |
| `lie.sanitize.device_reported_success` | bool | `True` |
| `lie.sanitize.return_code_trusted` | bool | `False` |
| `lie.sanitize.work_bytes` | int | `268435456` |
| `lie.sanitize.capacity_bytes` | int | `268435456` |
| `lie.sanitize.passes` | int | `1` |
| `lie.sanitize.measured_ns` | int | `1000` |
| `lie.sanitize.floor_ns` | int | `431059458` |
| `lie.sanitize.ratio` | float | `2e-06` |
| `lie.sanitize.threshold` | float | `0.05` |
| `lie.sanitize.baseline_source` | str | `'observed_pass'` |
| `lie.sanitize.baseline_measured` | bool | `True` |
| `lie.sanitize.probe_bytes` | int | `268435456` |
| `lie.sanitize.probe_elapsed_ns` | int | `431059458` |
| `lie.sanitize.rate_bps` | float | `622734175.107695` |
| `lie.sanitize.note` | str | `'UNVERIFIED_TIMING · ATA SANITIZE BLOC` |
| `lie.overwrite.operation` | str | `'host overwrite: single_pass_seeded_ra` |
| `lie.overwrite.code` | str | `'VERIFIED_TIMING'` |
| `lie.overwrite.severity` | str | `'verified'` |
| `lie.overwrite.simulated` | bool | `False` |
| `lie.overwrite.device_reported_success` | bool | `True` |
| `lie.overwrite.return_code_trusted` | bool | `False` |
| `lie.overwrite.work_bytes` | int | `268435456` |
| `lie.overwrite.capacity_bytes` | int | `268435456` |
| `lie.overwrite.passes` | int | `1` |
| `lie.overwrite.measured_ns` | int | `432911500` |
| `lie.overwrite.floor_ns` | int | `451268000` |
| `lie.overwrite.ratio` | float | `0.959322` |
| `lie.overwrite.threshold` | float | `0.05` |
| `lie.overwrite.baseline_source` | str | `'calibration_probe'` |
| `lie.overwrite.baseline_measured` | bool | `True` |
| `lie.overwrite.probe_bytes` | int | `33554432` |
| `lie.overwrite.probe_elapsed_ns` | int | `56408500` |
| `lie.overwrite.rate_bps` | float | `594847088.647987` |
| `lie.overwrite.note` | str | `'VERIFIED_TIMING · host overwrite: sin` |
| `lie.witness.sectors` | int | `256` |
| `lie.witness.before` | str | `'c82e10f39199bc4fb1728f8bf12f304971780` |
| `lie.witness.after` | str | `'c82e10f39199bc4fb1728f8bf12f304971780` |
| `lie.witness.unchanged` | bool | `True` |
| `lie.device.kind` | str | `'image file'` |
| `lie.device.model` | str | `'unknown'` |
| `lie.device.serial` | str | `'unknown'` |
| `lie.device.transport` | str | `'file'` |
| `lie.device.medium` | str | `'image'` |
| `lie.device.is_physical_medium` | bool | `False` |
| `lie.device.logical_sector_bytes` | int | `512` |
| `lie.device.total_sectors` | int | `524288` |
| `lie.device.capacity_bytes` | int | `268435456` |


## `loop` — 13 fields

*source: carve reports + wipe report*


| field | type | value on the fixture |
|---|---|---|
| `loop.before.scanned` | int | `58` |
| `loop.before.admitted` | int | `33` |
| `loop.after.scanned` | int | `30` |
| `loop.after.admitted` | int | `0` |
| `loop.recall_before` | int | `28` |
| `loop.recall_after` | int | `0` |
| `loop.planted` | int | `40` |
| `loop.reachability.contiguous` | int | `28` |
| `loop.reachability.needs_bifragment_reassembly` | int | `5` |
| `loop.reachability.unreachable_by_construction` | int | `7` |
| `loop.entropy.before` | float | `7.06169` |
| `loop.entropy.after` | float | `7.999999` |
| `loop.entropy.estimator` | str | `'Shannon over a 256-bin byte histogram` |


## `device` — 14 fields

*source: wipe.report/1 §3.1*


| field | type | value on the fixture |
|---|---|---|
| `device.kind` | str | `'image file'` |
| `device.model` | str | `'unknown'` |
| `device.serial` | str | `'unknown'` |
| `device.firmware` | str | `'unknown'` |
| `device.transport` | str | `'file'` |
| `device.identity_source` | str | `'file-metadata'` |
| `device.is_physical_medium` | bool | `False` |
| `device.medium` | str | `'image'` |
| `device.has_hidden_regions` | bool | `False` |
| `device.logical_sector_bytes` | int | `512` |
| `device.physical_sector_bytes` | NoneType | `None` |
| `device.total_sectors` | int | `524288` |
| `device.capacity_bytes` | int | `268435456` |
| `device.writable` | bool | `True` |


## `dispatch` — 8 fields

*source: wipe.report/1 §3.2*


| field | type | value on the fixture |
|---|---|---|
| `dispatch.method` | str | `'single_pass_seeded_random_shake128'` |
| `dispatch.method_selected_by` | str | `'detected-medium'` |
| `dispatch.passes` | int | `1` |
| `dispatch.nist_category` | str | `'Clear'` |
| `dispatch.legacy_shape` | NoneType | `None` |
| `dispatch.sanitize_primitive` | NoneType | `None` |
| `dispatch.sanitize_selected_by` | str | `'detected-medium'` |
| `dispatch.rationale` | str | `'regular file standing in for a medium` |


## `authorization` — 3 fields

*source: wipe.report/1*


| field | type | value on the fixture |
|---|---|---|
| `authorization.decision_code` | str | `'ALLOW_FILE'` |
| `authorization.require_confirmation` | bool | `True` |
| `authorization.allowed_roots[]` | array[1] | |


## `run` — 4 fields

*source: wipe.report/1*


| field | type | value on the fixture |
|---|---|---|
| `run.run_id` | str | `'sentinelwipe/wipe/v1'` |
| `run.target_resolved` | str | `'/private/tmp/claude-501/-Users-rosh-P` |
| `run.elapsed_ns` | int | `748349416` |
| `run.elapsed_s` | float | `0.748349` |


## `overwrite` — 23 fields

*source: wipe.report/1 §3.3*


| field | type | value on the fixture |
|---|---|---|
| `overwrite.method` | str | `'single_pass_seeded_random_shake128'` |
| `overwrite.simulated` | bool | `False` |
| `overwrite.nist_category` | str | `'Clear'` |
| `overwrite.legacy_shape` | NoneType | `None` |
| `overwrite.bytes_written` | int | `268435456` |
| `overwrite.duration_ns` | int | `436719375` |
| `overwrite.duration_s` | float | `0.436719` |
| `overwrite.bytes_per_second` | float | `614663491.859046` |
| `overwrite.passes[]` | array[1] | |
| `overwrite.passes[].pass` | int | `1` |
| `overwrite.passes[].of` | int | `1` |
| `overwrite.passes[].pattern` | str | `'shake128_seeded_stream'` |
| `overwrite.passes[].sectors_written` | int | `524288` |
| `overwrite.passes[].bytes_written` | int | `268435456` |
| `overwrite.passes[].duration_ns` | int | `434824500` |
| `overwrite.passes[].sync_ns` | int | `5667333` |
| `overwrite.passes[].bytes_per_second` | float | `617342067.891759` |
| `overwrite.passes[].chunk_writes` | int | `256` |
| `overwrite.passes[].chunk_sectors_first` | int | `2048` |
| `overwrite.passes[].chunk_sectors_final` | int | `2048` |
| `overwrite.passes[].chunk_resizes` | int | `0` |
| `overwrite.passes[].max_chunk_ns` | int | `2606500` |
| `overwrite.scope_limit` | str | `'An overwrite pass against an image fi` |


## `verification` — 23 fields

*source: wipe.report/1 §3.5*


| field | type | value on the fixture |
|---|---|---|
| `verification.mode` | str | `'sampled'` |
| `verification.all_passes_verified` | bool | `True` |
| `verification.coverage_fraction` | float | `0.001953` |
| `verification.sectors_verified_min` | int | `1024` |
| `verification.sectors_unverified_max` | int | `523264` |
| `verification.largest_unsampled_run_sectors` | int | `2815` |
| `verification.passes[]` | array[1] | |
| `verification.passes[].pass` | int | `1` |
| `verification.passes[].of` | int | `1` |
| `verification.passes[].mode` | str | `'sampled_read_back'` |
| `verification.passes[].pattern` | str | `'shake128_seeded_stream'` |
| `verification.passes[].verdict` | str | `'PATTERN_CONFIRMED_ON_SAMPLE'` |
| `verification.passes[].sectors_verified` | int | `1024` |
| `verification.passes[].sectors_unverified` | int | `523264` |
| `verification.passes[].bytes_verified` | int | `524288` |
| `verification.passes[].coverage_fraction` | float | `0.001953` |
| `verification.passes[].largest_unsampled_run_sectors` | int | `2815` |
| `verification.passes[].mismatched_sectors` | int | `0` |
| `verification.passes[].mismatches_truncated` | bool | `False` |
| `verification.passes[].duration_ns` | int | `1869458` |
| `verification.passes[].bytes_per_second` | float | `280449199.71457` |
| `verification.passes[].sample_digest_hex` | str | `'09a55d5416c2db9d58c60411505fe89c68ac6` |
| `verification.passes[].claim` | str | `'Pass 1 of 1: 1024 of 524288 sectors w` |


## `audit` — 21 fields

*source: wipe.report/1 §3.4*


| field | type | value on the fixture |
|---|---|---|
| `audit.overwrite.operation` | str | `'host overwrite: single_pass_seeded_ra` |
| `audit.overwrite.code` | str | `'VERIFIED_TIMING'` |
| `audit.overwrite.severity` | str | `'verified'` |
| `audit.overwrite.simulated` | bool | `False` |
| `audit.overwrite.device_reported_success` | bool | `True` |
| `audit.overwrite.return_code_trusted` | bool | `False` |
| `audit.overwrite.work_bytes` | int | `268435456` |
| `audit.overwrite.capacity_bytes` | int | `268435456` |
| `audit.overwrite.passes` | int | `1` |
| `audit.overwrite.measured_ns` | int | `436719375` |
| `audit.overwrite.floor_ns` | int | `495316000` |
| `audit.overwrite.ratio` | float | `0.881699` |
| `audit.overwrite.threshold` | float | `0.05` |
| `audit.overwrite.baseline_source` | str | `'calibration_probe'` |
| `audit.overwrite.baseline_measured` | bool | `True` |
| `audit.overwrite.probe_bytes` | int | `33554432` |
| `audit.overwrite.probe_elapsed_ns` | int | `61914500` |
| `audit.overwrite.rate_bps` | float | `541947879.73738` |
| `audit.overwrite.note` | str | `'VERIFIED_TIMING · host overwrite: sin` |
| `audit.sanitize` | NoneType | `None` |
| `audit.return_code_trusted` | bool | `False` |


## `telemetry` — 12 fields

*source: wipe.report/1 §3.3*


| field | type | value on the fixture |
|---|---|---|
| `telemetry.schema` | str | `'sentinelwipe.wipe.telemetry/1'` |
| `telemetry.period_ms` | int | `8` |
| `telemetry.events` | int | `48` |
| `telemetry.wall_ms` | float | `436.720417` |
| `telemetry.achieved_hz` | float | `109.910135` |
| `telemetry.min_gap_ms` | float | `6.198958` |
| `telemetry.max_gap_ms` | float | `10.167833` |
| `telemetry.rate_floor_hz` | float | `20.0` |
| `telemetry.met_rate_floor` | bool | `True` |
| `telemetry.longest_uninstrumented_interval_ns` | int | `7536791` |
| `telemetry.longest_uninstrumented_interval_ms` | float | `7.536791` |
| `telemetry.note` | str | `'met_rate_floor is the verdict, not ac` |


## `limits` — 1 fields

*source: wipe.report/1 §3.6*


| field | type | value on the fixture |
|---|---|---|
| `limits[]` | array[4] | |


## `outcome` — 7 fields

*source: wipe.report/1 §3.6*


| field | type | value on the fixture |
|---|---|---|
| `outcome.code` | str | `'OVERWRITE_VERIFIED_ON_SAMPLE'` |
| `outcome.passes_verified` | bool | `True` |
| `outcome.whole_medium_claim` | bool | `False` |
| `outcome.verification_coverage_fraction` | float | `0.001953` |
| `outcome.sanitized` | bool | `True` |
| `outcome.sanitized_scope` | str | `'sampled_sectors_only'` |
| `outcome.evidence` | str | `'read-back verification of the pattern` |


## `entropy` — 5 fields

*source: wipe.report/1*


| field | type | value on the fixture |
|---|---|---|
| `entropy.before` | float | `7.06169` |
| `entropy.after` | float | `7.999999` |
| `entropy.delta` | float | `0.938309` |
| `entropy.bytes_measured` | int | `268435456` |
| `entropy.estimator` | str | `'Shannon over a 256-bin byte histogram` |


## `probe` — 10 fields

*source: wipe.report/1*


| field | type | value on the fixture |
|---|---|---|
| `probe.bytes` | int | `33554432` |
| `probe.sectors` | int | `65536` |
| `probe.pattern` | str | `'shake128_seeded_stream'` |
| `probe.duration_ns` | int | `61914500` |
| `probe.duration_s` | float | `0.061914` |
| `probe.sync_ns` | int | `9245292` |
| `probe.bytes_per_second` | float | `541947879.73738` |
| `probe.admitted_as_baseline` | bool | `True` |
| `probe.refusal` | NoneType | `None` |
| `probe.note` | str | `"Written before pass 1 with the FINAL ` |


## `frames` — 9 fields

*source: --trace JSONL (progress events)*


| field | type | value on the fixture |
|---|---|---|
| `frames[]` | array[48] | |
| `frames[].t` | float | `9.319` |
| `frames[].fs` | int | `0` |
| `frames[].n` | int | `12288` |
| `frames[].bd` | int | `6291456` |
| `frames[].bps` | float | `675118322.2` |
| `frames[].en` | float | `7.9959` |
| `frames[].hs` | int | `10240` |
| `frames[].hx` | str | `'4449ea1f2dc5e50c7f0c575354c85de2dce61` |


## `carve` — 113 fields

*source: carve.report/1*


| field | type | value on the fixture |
|---|---|---|
| `carve.policy.formula` | str | `'confidence = 0.40*signature_integrity` |
| `carve.policy.weights.signature_integrity` | float | `0.4` |
| `carve.policy.weights.structural_validity` | float | `0.35` |
| `carve.policy.weights.entropy_consistency` | float | `0.15` |
| `carve.policy.weights.size_plausibility` | float | `0.1` |
| `carve.policy.weights_sum` | float | `1.0` |
| `carve.policy.min_confidence` | float | `0.75` |
| `carve.policy.non_structure_ceiling` | float | `0.65` |
| `carve.policy.structural_breach_point` | float | `0.285714` |
| `carve.policy.signature_ladder.header-mismatch` | float | `0.0` |
| `carve.policy.signature_ladder.header-only` | float | `0.5` |
| `carve.policy.signature_ladder.no-footer-defined` | float | `0.75` |
| `carve.policy.signature_ladder.header-and-footer` | float | `1.0` |
| `carve.policy.entropy_min_sample_bytes` | int | `1024` |
| `carve.policy.entropy_unknown` | float | `0.5` |
| `carve.counts.records` | int | `56` |
| `carve.counts.admitted` | int | `35` |
| `carve.counts.rejected` | int | `21` |
| `carve.counts.sha256_matches_planted` | int | `35` |
| `carve.counts.by_kind.JPEG.records` | int | `13` |
| `carve.counts.by_kind.JPEG.admitted` | int | `5` |
| `carve.counts.by_kind.JPEG.rejected` | int | `8` |
| `carve.counts.by_kind.PNG.records` | int | `5` |
| `carve.counts.by_kind.PNG.admitted` | int | `5` |
| `carve.counts.by_kind.PNG.rejected` | int | `0` |
| `carve.counts.by_kind.PDF.records` | int | `5` |
| `carve.counts.by_kind.PDF.admitted` | int | `5` |
| `carve.counts.by_kind.PDF.rejected` | int | `0` |
| `carve.counts.by_kind.ZIP.records` | int | `5` |
| `carve.counts.by_kind.ZIP.admitted` | int | `5` |
| `carve.counts.by_kind.ZIP.rejected` | int | `0` |
| `carve.counts.by_kind.SQLITE.records` | int | `5` |
| `carve.counts.by_kind.SQLITE.admitted` | int | `5` |
| `carve.counts.by_kind.SQLITE.rejected` | int | `0` |
| `carve.counts.by_kind.MP4.records` | int | `5` |
| `carve.counts.by_kind.MP4.admitted` | int | `5` |
| `carve.counts.by_kind.MP4.rejected` | int | `0` |
| `carve.counts.by_kind.GZIP.records` | int | `18` |
| `carve.counts.by_kind.GZIP.admitted` | int | `5` |
| `carve.counts.by_kind.GZIP.rejected` | int | `13` |
| `carve.counts.by_assembly.contiguous` | int | `28` |
| `carve.counts.by_assembly.reassembled` | int | `7` |
| `carve.counts.by_assembly.signature-span` | int | `21` |
| `carve.margin.lowest_admitted` | float | `0.9` |
| `carve.margin.highest_rejected` | float | `0.65` |
| `carve.margin.population_gap` | float | `0.25` |
| `carve.margin.gate_headroom` | float | `0.1` |
| `carve.margin.worst_rejected_structural_validity` | float | `0.25` |
| `carve.margin.structural_breach_point` | float | `0.285714` |
| `carve.margin.structural_headroom` | float | `0.035714` |
| `carve.margin.binds` | str | `'structural_headroom'` |
| `carve.ground_truth.manifest_path` | str | `'out/fixture.manifest.json'` |
| `carve.ground_truth.manifest_sha256` | str | `'1808494ecc3cd5e21d0d9790af5478cda6aa7` |
| `carve.ground_truth.planted_total` | int | `40` |
| `carve.ground_truth.reachability.contiguous` | int | `28` |
| `carve.ground_truth.reachability.needs_bifragment_reassembly` | int | `5` |
| `carve.ground_truth.reachability.unreachable_by_construction` | int | `7` |
| `carve.ground_truth.unreachable[]` | array[7] | |
| `carve.ground_truth.unreachable[].path` | str | `'/evidence_log_2026-01-14.txt'` |
| `carve.ground_truth.unreachable[].kind` | str | `'TXT'` |
| `carve.ground_truth.unreachable[].reason` | str | `'kind TXT has no row in signature::SIG` |
| `carve.ground_truth.recall_measured` | bool | `False` |
| `carve.ground_truth.demonstrated_recall` | NoneType | `None` |
| `carve.ground_truth.demonstrated_recall_note` | str | `"null because no carve run produced on` |
| `carve.provenance.producer` | str | `'core/carve/examples/gen_sample_output` |
| `carve.provenance.command` | str | `'cargo run --release -p sentinelwipe-c` |
| `carve.provenance.is_carve_run` | bool | `False` |
| `carve.provenance.notes[]` | array[6] | |
| `carve.kind_policy.JPEG.defines_footer` | bool | `True` |
| `carve.kind_policy.JPEG.entropy_band_bits_per_byte[]` | array[4] | |
| `carve.kind_policy.JPEG.size_bounds_bytes[]` | array[4] | |
| `carve.kind_policy.PNG.defines_footer` | bool | `True` |
| `carve.kind_policy.PNG.entropy_band_bits_per_byte[]` | array[4] | |
| `carve.kind_policy.PNG.size_bounds_bytes[]` | array[4] | |
| `carve.kind_policy.PDF.defines_footer` | bool | `True` |
| `carve.kind_policy.PDF.entropy_band_bits_per_byte[]` | array[4] | |
| `carve.kind_policy.PDF.size_bounds_bytes[]` | array[4] | |
| `carve.kind_policy.ZIP.defines_footer` | bool | `True` |
| `carve.kind_policy.ZIP.entropy_band_bits_per_byte[]` | array[4] | |
| `carve.kind_policy.ZIP.size_bounds_bytes[]` | array[4] | |
| `carve.kind_policy.SQLITE.defines_footer` | bool | `False` |
| `carve.kind_policy.SQLITE.entropy_band_bits_per_byte[]` | array[4] | |
| `carve.kind_policy.SQLITE.size_bounds_bytes[]` | array[4] | |
| `carve.kind_policy.MP4.defines_footer` | bool | `False` |
| `carve.kind_policy.MP4.entropy_band_bits_per_byte[]` | array[4] | |
| `carve.kind_policy.MP4.size_bounds_bytes[]` | array[4] | |
| `carve.kind_policy.GZIP.defines_footer` | bool | `False` |
| `carve.kind_policy.GZIP.entropy_band_bits_per_byte[]` | array[4] | |
| `carve.kind_policy.GZIP.size_bounds_bytes[]` | array[4] | |
| `carve.records[]` | array[56] | |
| `carve.records[].kind` | str | `'ZIP'` |
| `carve.records[].offset` | int | `1069056` |
| `carve.records[].length` | int | `79397` |
| `carve.records[].admitted` | bool | `True` |
| `carve.records[].reason_code` | NoneType | `None` |
| `carve.records[].reason` | NoneType | `None` |
| `carve.records[].assembly` | str | `'reassembled'` |
| `carve.records[].total` | float | `1.0` |
| `carve.records[].terms.signature_integrity` | float | `1.0` |
| `carve.records[].terms.structural_validity` | float | `1.0` |
| `carve.records[].terms.entropy_consistency` | float | `1.0` |
| `carve.records[].terms.size_plausibility` | float | `1.0` |
| `carve.records[].weighted.signature_integrity` | float | `0.4` |
| `carve.records[].weighted.structural_validity` | float | `0.35` |
| `carve.records[].weighted.entropy_consistency` | float | `0.15` |
| `carve.records[].weighted.size_plausibility` | float | `0.1` |
| `carve.records[].sha256` | str | `'8b3d1dd7bce506e8'` |
| `carve.records[].ladder` | str | `'header-and-footer'` |
| `carve.records[].path` | str | `'/media_inventory.docx'` |
| `carve.records[].expected_recoverable` | str | `'unrecoverable-by-design'` |
| `carve.records[].sha256_matches` | bool | `True` |
| `carve.records[].structure_valid` | bool | `True` |
| `carve.records[].structure_detail` | str | `'ooxml entries=7 xcheck=7/7 payload=7/` |


---

## Fields the UI must NOT render

These do not exist in either schema. Rendering one is a fabrication, not a bug:

| field | why |
|---|---|
| any Ed25519 signature | `core/ledger` is a one-line stub. Phase 4. |
| any Merkle root or chain anchor | same. |
| `deterministic_core` / `measurement_envelope` as emitted regions | a CLAUDE.md rule-6 decision, not yet a structure. A UI may group these fields itself **only if it says the grouping is the UI's own**. |
| device bus | no such field. `device.transport` is `"file"`. |
| device mount state | nothing is ever mounted — D1. |
| `demonstrated_recall` | `null`, with `recall_measured: false`. Substituting `counts.admitted` is forbidden by `output_schema.md` §8 in those words. |
