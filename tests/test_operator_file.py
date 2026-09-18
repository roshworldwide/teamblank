from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import zipfile

import pytest

from fixtures import build_image as build_mod
from fixtures import plant_operator_file as plant_mod

OUT = "out"
IMAGE = os.path.join(OUT, build_mod.IMAGE_NAME)
MANIFEST = os.path.join(OUT, build_mod.MANIFEST_NAME)
SENTENCE = b"A sentence the judge typed at 14:32 that nobody had seen before."


@pytest.fixture
def pristine(tmp_path):
    if not (os.path.exists(IMAGE) and os.path.exists(MANIFEST)):
        pytest.skip("out/fixture.img is absent; run `make fixtures`")
    d = tmp_path / "out"
    d.mkdir()
    shutil.copy2(IMAGE, d / build_mod.IMAGE_NAME)
    shutil.copy2(MANIFEST, d / build_mod.MANIFEST_NAME)
    return str(d)


def _plant(out_dir, text=SENTENCE, name="operator_note.txt"):
    payload = plant_mod.build_container(text, name)
    return plant_mod.plant(
        os.path.join(out_dir, build_mod.IMAGE_NAME),
        os.path.join(out_dir, build_mod.MANIFEST_NAME),
        payload, out_dir, text, name, quiet=True)


def test_the_planted_bytes_are_at_the_offset_the_sidecar_claims(pristine):
    sc = _plant(pristine)
    img = open(os.path.join(pristine, build_mod.IMAGE_NAME), "rb").read()
    blob = img[sc["offset"]:sc["offset"] + sc["size"]]
    assert hashlib.sha256(blob).hexdigest() == sc["container_sha256"]
    assert blob[:4] == b"PK\x03\x04", "a carver's signature sweep must be able to find it"


def test_the_crc_proves_the_recovered_bytes_are_the_originals(pristine):
    sc = _plant(pristine)
    img = open(os.path.join(pristine, build_mod.IMAGE_NAME), "rb").read()
    z = zipfile.ZipFile(io.BytesIO(img[sc["offset"]:sc["offset"] + sc["size"]]))
    assert z.testzip() is None, "CRC-32 over the payload must verify"
    recovered = z.read(z.namelist()[0])
    assert recovered == SENTENCE
    assert hashlib.sha256(recovered).hexdigest() == sc["plaintext_sha256"]


def test_planting_touches_none_of_the_forty(pristine):
    sc = _plant(pristine)
    man = json.load(open(os.path.join(pristine, build_mod.MANIFEST_NAME)))
    assert len(man["files"]) == 40
    lo, hi = sc["offset"], sc["offset"] + sc["size"]
    for f in man["files"]:
        for e in f["extents"]:
            a, b = e["byte_offset"], e["byte_offset"] + e["byte_length"]
            assert hi <= a or lo >= b, f"the overlay landed inside {f['path']}"


def test_every_planted_file_still_reads_back_byte_for_byte(pristine):
    before = open(os.path.join(pristine, build_mod.IMAGE_NAME), "rb").read()
    man = json.load(open(os.path.join(pristine, build_mod.MANIFEST_NAME)))
    _plant(pristine)
    after = open(os.path.join(pristine, build_mod.IMAGE_NAME), "rb").read()
    for f in man["files"]:
        for e in f["extents"]:
            a, b = e["byte_offset"], e["byte_offset"] + e["byte_length"]
            assert before[a:b] == after[a:b], f"{f['path']} changed"


def test_it_refuses_to_plant_twice(pristine):
    _plant(pristine)
    with pytest.raises(plant_mod.PlantError, match="does not match its manifest digest"):
        _plant(pristine, b"a second sentence")


def test_it_refuses_a_payload_larger_than_the_free_run(pristine):
    oversized = b"\x00" * (64 << 20)
    with pytest.raises(plant_mod.PlantError, match="largest free run"):
        plant_mod.plant(
            os.path.join(pristine, build_mod.IMAGE_NAME),
            os.path.join(pristine, build_mod.MANIFEST_NAME),
            oversized, pristine, b"x", "x.txt", quiet=True)


def test_the_sidecar_records_that_seed_identity_is_broken(pristine):
    sc = _plant(pristine)
    assert sc["seed_identity"].startswith("BROKEN")
    assert sc["image_sha256_before"] != sc["image_sha256_after"]
    on_disk = json.load(open(os.path.join(pristine, plant_mod.SIDECAR_NAME)))
    assert on_disk["schema"] == plant_mod.SIDECAR_SCHEMA


def test_the_free_run_is_cluster_aligned_and_clear_of_the_reserved_region(pristine):
    man = json.load(open(os.path.join(pristine, build_mod.MANIFEST_NAME)))
    start, room = plant_mod.largest_free_run(man)
    assert start % man["bytes_per_cluster"] == 0
    assert start >= plant_mod.FLOOR_BYTES, "must not land on the FATs or the root dir"
    assert room > 0
