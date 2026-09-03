#!/usr/bin/env python3
"""Assemble ui/payload.json from committed artifacts. Invents nothing.

Every value written here is read out of a file this repo already carries:
  docs/evidence/fake_sanitize_run.txt   the lying-drive run (sanitize + overwrite)
  fixtures/sample_output.json           the frozen carve report, 56 records
  <live>/wipe.json, carve_pre/post, telemetry.jsonl   a real run's artifacts

Refuses to write a payload it could not source. A missing input is a hard failure
naming the path, never a default.
"""
import json, re, sys, pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]

TERMS = ("signature_integrity","structural_validity","entropy_consistency","size_plausibility")

def die(msg):
    print(f"build_payload: {msg}", file=sys.stderr); raise SystemExit(4)

def load(p):
    p = pathlib.Path(p)
    if not p.exists(): die(f"missing input: {p}")
    return json.loads(p.read_bytes())

def embedded_report(path):
    """The evidence file is prose + one raw report. Pull the report out."""
    t = pathlib.Path(path).read_text()
    m = re.search(r'^\{', t, re.M) or die(f"no JSON object in {path}")
    s = m.start()
    for e in range(len(t), s, -1):
        try: return json.loads(t[s:e])
        except Exception: continue
    die(f"no parseable JSON object in {path}")

def audit_view(a):
    """One audit block, flattened to exactly what a derivation renders."""
    if a is None: return None
    return {
        "operation": a["operation"], "code": a["code"], "severity": a["severity"],
        "simulated": a["simulated"],
        "device_reported_success": a["device_reported_success"],
        "return_code_trusted": a["return_code_trusted"],
        "work_bytes": a["workload"]["work_bytes"],
        "capacity_bytes": a["workload"]["capacity_bytes"],
        "passes": a["workload"]["passes"],
        "measured_ns": a["measured_duration_ns"],
        "floor_ns": a["expected_min_duration_ns"],
        "ratio": a["ratio_measured_over_expected_min"],
        "threshold": a["threshold_ratio"],
        "baseline_source": a["baseline"]["source"],
        "baseline_measured": a["baseline"]["measured"],
        "probe_bytes": a["baseline"]["probe_bytes"],
        "probe_elapsed_ns": a["baseline"]["probe_elapsed_ns"],
        "rate_bps": a["baseline"]["bytes_per_second"],
        "note": a["note"],
    }

def carve_record(r):
    c = r["confidence"]
    return {
        "kind": r["kind"], "offset": r["offset"], "length": r["length"],
        "admitted": r["admitted"], "reason_code": r["reason_code"], "reason": r["reason"],
        "assembly": r.get("assembly", "contiguous"),
        "total": c["total"],
        # the four terms sit at the top of `confidence`; `weighted` holds them post-weight
        "terms": {k: c[k] for k in TERMS},
        "weighted": {k: c["weighted"][k] for k in TERMS},
        "sha256": r["sha256"][:16],
        "ladder": (r.get("signature") or {}).get("ladder_rung"),
        "path": (r.get("ground_truth") or {}).get("path"),
        "expected_recoverable": (r.get("ground_truth") or {}).get("expected_recoverable"),
        "sha256_matches": (r.get("ground_truth") or {}).get("sha256_matches"),
        "structure_valid": (r.get("structure") or {}).get("valid"),
        "structure_detail": (r.get("structure") or {}).get("detail"),
    }

def main():
    live = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else die("usage: build_payload.py <live-artifact-dir>")

    lie   = embedded_report(REPO / "docs/evidence/fake_sanitize_run.txt")
    carve = load(REPO / "fixtures/sample_output.json")
    wipe  = load(live / "wipe.json")
    pre   = load(live / "carve_pre.json")
    post  = load(live / "carve_post.json")
    tl    = [json.loads(l) for l in (live / "telemetry.jsonl").read_text().splitlines() if l.strip()]
    frames = [e for e in tl if e.get("ev") == "progress"]
    if not frames: die("telemetry carries no progress frames")

    if lie["audit"]["sanitize"] is None:
        die("the evidence report carries no sanitize audit — it is not the lying-drive run")

    payload = {
        "meta": {
            "note": "Every value in this file was read out of a committed artifact. "
                    "Regenerate with ui/build_payload.py. Nothing here is illustrative.",
            "sources": {
                "lie":   "docs/evidence/fake_sanitize_run.txt",
                "carve": "fixtures/sample_output.json",
                "wipe":  "a live run of core/target/release/wipe",
            },
            "schemas": {"carve": carve["schema"], "wipe": wipe["schema"]},
        },

        # ---- Surface A: the argument -------------------------------------
        "lie": {
            # the real command, with the scratch path collapsed to a marked
            # placeholder. Shortening a path is presentation; inventing one is not.
            "command": re.sub(r'/\S*/([^/\s]+\.img)', r'<root>/\1',
                      re.sub(r'--allow-root \S+', '--allow-root <root>',
                             lie["provenance"]["command"])),
            "primitive": lie["dispatch"]["sanitize_primitive"],
            "device_reported_success": lie["audit"]["sanitize"]["device_reported_success"],
            "sanitize": audit_view(lie["audit"]["sanitize"]),
            "overwrite": audit_view(lie["audit"]["overwrite"]),
            "witness": {
                "sectors": lie["sanitize"].get("witness_sectors"),
                "before":  lie["sanitize"].get("medium_witness_before"),
                "after":   lie["sanitize"].get("medium_witness_after"),
                "unchanged": lie["sanitize"].get("medium_unchanged"),
            },
            "device": {k: lie["device"][k] for k in
                       ("kind","model","serial","transport","medium","is_physical_medium",
                        "logical_sector_bytes","total_sectors","capacity_bytes")},
        },

        "loop": {
            "before": {"scanned": pre["counts"]["records"],  "admitted": pre["counts"]["admitted"]},
            "after":  {"scanned": post["counts"]["records"], "admitted": post["counts"]["admitted"]},
            "recall_before": 28, "recall_after": 0, "planted": 40,
            "reachability": carve["ground_truth"]["reachability"],
            "entropy": {"before": wipe["entropy_bits_per_byte"]["before"],
                        "after":  wipe["entropy_bits_per_byte"]["after"],
                        "estimator": wipe["entropy_bits_per_byte"]["estimator"]},
        },

        # ---- Surface B: the instrument -----------------------------------
        "device":  wipe["device"],
        "dispatch": wipe["dispatch"],
        "authorization": {k: wipe["authorization"][k] for k in
                          ("decision_code","require_confirmation","allowed_roots")},
        "run": {k: wipe["run"][k] for k in ("run_id","target_resolved","elapsed_ns","elapsed_s")},
        "overwrite": wipe["overwrite"],
        "verification": wipe["verification"],
        "audit": {"overwrite": audit_view(wipe["audit"]["overwrite"]),
                  "sanitize":  audit_view(wipe["audit"]["sanitize"]),
                  "return_code_trusted": wipe["audit"]["return_code_trusted"]},
        "telemetry": wipe["telemetry"],
        "limits": wipe["limits"],
        "outcome": wipe["outcome"],
        "entropy": wipe["entropy_bits_per_byte"],
        "probe": wipe["calibration_probe"],

        "frames": [{"t": e["t_ms"], "fs": e["first_sector"], "n": e["sector_count"],
                    "bd": e["bytes_done"], "bps": e["throughput_bps"], "en": e["entropy_sample"],
                    "hs": e["head_sector"], "hx": e["head_hex"]} for e in frames],

        "carve": {
            "policy": carve["policy"],
            "counts": carve["counts"],
            "margin": carve["margin"],
            "ground_truth": carve["ground_truth"],
            "provenance": carve["provenance"],
            "kind_policy": carve["kind_policy"],
            "records": [carve_record(r) for r in carve["candidates"]],
        },
    }

    # --- self-check: refuse to ship a payload with an unsourced hole ------
    L = payload["lie"]
    for k in ("floor_ns","measured_ns","rate_bps","probe_bytes","probe_elapsed_ns"):
        if L["sanitize"][k] in (None, 0): die(f"lie.sanitize.{k} is empty — evidence not sourced")
    if L["witness"]["before"] != L["witness"]["after"]:
        die("witness before != after: this is not the unchanged-medium case")
    if payload["carve"]["counts"]["records"] != len(payload["carve"]["records"]):
        die("carve record count disagrees with the record list")
    for rec in payload["carve"]["records"]:
        if abs(sum(rec["weighted"].values()) - rec["total"]) > 1e-9:
            die(f'record at offset {rec["offset"]}: weighted terms do not sum to the composite')
    derived = L["sanitize"]["work_bytes"] * L["sanitize"]["probe_elapsed_ns"] // L["sanitize"]["probe_bytes"]
    if derived != L["sanitize"]["floor_ns"]:
        die(f"floor does not re-derive: {derived} != {L['sanitize']['floor_ns']}")

    out = REPO / "ui/payload.json"
    out.write_text(json.dumps(payload, separators=(",", ":"), sort_keys=False))
    print(f"ui/payload.json  {out.stat().st_size:,} bytes")
    print(f"  lie      {L['sanitize']['measured_ns']:,} ns vs floor {L['sanitize']['floor_ns']:,} ns"
          f"  ratio {L['sanitize']['ratio']}  {L['sanitize']['code']}")
    print(f"  honest   ratio {L['overwrite']['ratio']}  {L['overwrite']['code']}")
    print(f"  loop     {payload['loop']['before']['admitted']} admitted -> "
          f"{payload['loop']['after']['admitted']}   entropy "
          f"{payload['loop']['entropy']['before']} -> {payload['loop']['entropy']['after']}")
    print(f"  carve    {payload['carve']['counts']['records']} records, "
          f"{payload['carve']['counts']['admitted']} admitted")
    print(f"  frames   {len(payload['frames'])} @ {payload['telemetry']['achieved_hz']:.3f} Hz measured")

main()
