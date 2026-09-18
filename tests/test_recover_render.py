import pathlib

import pytest

pytest.importorskip("playwright", reason="playwright is not installed; see module docstring")

from playwright.sync_api import sync_playwright  # noqa: E402

REPO = pathlib.Path(__file__).resolve().parents[1]
PAGE = REPO / "ui" / "recover.html"
GB = 8 * 10**9

VIEWPORTS = [(1600, 1000), (1440, 780)]


def _fixture():
    hits = [
        {
            "path": "/photo_%02d.jpg" % i, "kind": "JPEG",
            "offset": int(GB * 0.12) + i * 40_000_000,
            "length": 220_000, "candidate_length": 220_000,
            "sha256": "%064x" % (0xABC0 + i), "admitted": True,
            "confidence": 0.94, "assembly": "contiguous",
            "enrolled_size": 220_000, "mode": "exact", "overrun_bytes": 0,
        }
        for i in range(9)
    ]
    hits.append({
        "path": "/report.pdf", "kind": "PDF", "offset": int(GB * 0.55),
        "length": 90_000, "candidate_length": 140_000,
        "sha256": "%064x" % 0xDEF0, "admitted": True, "confidence": 0.88,
        "assembly": "contiguous", "enrolled_size": 90_000,
        "mode": "over-run", "overrun_bytes": 50_000,
    })
    compare = {
        "enrolled": 12, "enrolled_carvable": 11, "records": 30, "admitted": 11,
        "byte_exact_matches": 10, "byte_exact_and_admitted": 10, "hits": hits,
        "scope": "whole volume", "whole_volume": True,
        "not_recovered": [
            {"path": "/notes.txt", "size": 1400, "ext": ".txt",
             "carvable": False, "reason": "kind TXT has no header to scan for"},
            {"path": "/split.mov", "size": 9_000_000, "ext": ".mov",
             "carvable": True,
             "reason": "3 extents; bifragment reassembles at most 2"},
        ],
    }
    enrolment = {
        "count": 12, "carvable": 11,
        "files": [
            {"path": h["path"], "name": h["path"][1:], "size": h["enrolled_size"],
             "sha256": h["sha256"], "ext": ".jpg", "kind": h["kind"],
             "carvable": True}
            for h in hits
        ] + [
            {"path": "/notes.txt", "name": "notes.txt", "size": 1400,
             "sha256": "%064x" % 0x111, "ext": ".txt", "kind": None,
             "carvable": False},
            {"path": "/split.mov", "name": "split.mov", "size": 9_000_000,
             "sha256": "%064x" % 0x222, "ext": ".mov", "kind": "MP4",
             "carvable": True},
        ],
    }
    return enrolment, compare


PROBE = """() => {
  const tw  = document.querySelector('.tw');
  const bar = document.querySelector('.bar').getBoundingClientRect();
  const of  = document.querySelector('#hero .of');
  const doc = document.documentElement;
  const rows = document.querySelectorAll('#rows tr[data-sha]');
  const last = rows[rows.length - 1];
  return {
    peak:     document.getElementById('stage').getAttribute('data-peak'),
    heroCls:  document.getElementById('hero').className,
    hero:     document.getElementById('hero').innerText.split('\\n').join(' '),
    back:     document.querySelectorAll('tr[data-back]').length,
    ok:       document.querySelectorAll('td.v.ok').length,
    warn:     document.querySelectorAll('td.v.warn').length,
    no:       document.querySelectorAll('td.v.no').length,
    pairs:    document.querySelectorAll('td.h .pair').length,
    scale:    document.getElementById('mScale').textContent,

    /* the hero caption must not be truncated: an ellipsis lands on the word
       "byte-exact", which is the claim the whole page exists to make */
    ofClipW:  of.scrollWidth  - of.clientWidth,
    ofClipH:  of.scrollHeight - of.clientHeight,
    ofText:   of.innerText,

    /* content spilling past the stage paints over the control bar without
       ever moving it, so the panel is what must be measured, not the stage */
    panelOverBar: Math.round(
      document.querySelector('.panel').getBoundingClientRect().bottom - bar.top),
    twScrolls: tw.scrollHeight > tw.clientHeight + 1,

    /* the cascade must settle on the tail: the over-run and the two files we
       did not recover are the rows the claim is priced against */
    atTail: tw.scrollTop + tw.clientHeight >= tw.scrollHeight - 4,
    lastRowVisible: (() => {
      const r = last.getBoundingClientRect(), c = tw.getBoundingClientRect();
      return r.top >= c.top - 1 && r.bottom <= c.bottom + 1;
    })(),
    tailVerdict: last.querySelector('td.v').textContent.trim(),

    /* the map must be painted in the token's own value, not a forked literal */
    tokenCells: (() => {
      const hx = getComputedStyle(doc).getPropertyValue('--sig-nominal')
                   .trim().replace('#','');
      const want = [0,2,4].map(i => parseInt(hx.substr(i,2),16));
      const cv = document.getElementById('mediumCv');
      const d = cv.getContext('2d').getImageData(0,0,cv.width,cv.height).data;
      let n = 0;
      for (let i = 0; i < d.length; i += 4)
        if (d[i]===want[0] && d[i+1]===want[1] && d[i+2]===want[2] && d[i+3]===255) n++;
      return n;
    })(),

    /* a readout column that sizes to its content drags the track with it,
       and a track whose length depends on the number is the number reflowing */
    trackWidths: [...document.querySelectorAll('.track')]
                   .map(e => Math.round(e.getBoundingClientRect().width)),

    /* The sticky header must occlude the rows passing under it. The
       returning rows carry a transform animation, which promotes them into
       their own stacking context; without an explicit index on the header the
       evidence scrolls straight through the column names. Compare the header
       band's own rect against the topmost row that overlaps it. */
    headerOccludes: (() => {
      const th = document.querySelector('thead th');
      const hr = th.getBoundingClientRect();
      const probe = document.elementFromPoint(hr.left + 4, hr.top + hr.height / 2);
      return probe ? probe.closest('thead') !== null : false;
    })(),

    bodyScrollX: doc.scrollWidth  - doc.clientWidth,
    bodyScrollY: doc.scrollHeight - doc.clientHeight,
  };
}"""


@pytest.fixture(scope="module")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture(scope="module", params=VIEWPORTS, ids=lambda v: "%dx%d" % v)
def rendered(request, browser):
    enrolment, compare = _fixture()
    w, h = request.param
    page = browser.new_page(viewport={"width": w, "height": h})
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(PAGE.as_uri())
    page.wait_for_timeout(500)

    page.evaluate(
        """(d) => { __rec.setVol({letter:"E", capacity_bytes:8e9, label:"DEMO"});
                    __rec.setEnrol(d); __rec.renderEnrolment(); __rec.MAP.init(8e9); }""",
        enrolment,
    )
    for f in (0.18, 0.46, 0.78):
        page.evaluate("(f) => __rec.MAP.progress(Math.floor(8e9*f), 8e9)", f)
        page.wait_for_timeout(60)
    page.evaluate("() => __rec.MAP.imaged()")

    page.evaluate("(d) => __rec.paintResult(d)", compare)
    page.wait_for_timeout(2400)
    result = page.evaluate(PROBE)
    result["errors"] = errors
    result["viewport"] = (w, h)
    yield result
    page.close()


def test_no_page_errors(rendered):
    assert rendered["errors"] == []


def test_hero_caption_is_not_truncated(rendered):
    assert rendered["ofClipW"] <= 0, "caption clipped horizontally"
    assert rendered["ofClipH"] <= 0, "caption clipped vertically"
    assert "byte-exact" in rendered["ofText"]


def test_panel_does_not_paint_over_the_control_bar(rendered):
    assert rendered["panelOverBar"] <= 0
    assert rendered["twScrolls"], "the table grew instead of scrolling"


def test_rows_do_not_scroll_through_the_column_headers(rendered):
    assert rendered["headerOccludes"]


def test_page_itself_never_scrolls(rendered):
    assert rendered["bodyScrollX"] == 0
    assert rendered["bodyScrollY"] == 0


def test_cascade_settles_on_the_admitted_failures(rendered):
    assert rendered["atTail"]
    assert rendered["lastRowVisible"]
    assert rendered["tailVerdict"] == "∅ not recovered"


def test_the_peak_lands_last(rendered):
    assert rendered["peak"] == "1"
    assert rendered["heroCls"] == "hero peak"
    assert rendered["hero"] == "10 of 12 enrolled files, byte-exact"


def test_every_hit_returns_with_both_hashes(rendered):
    assert rendered["back"] == 10
    assert rendered["pairs"] == 20


def test_verdicts_match_the_fixture(rendered):
    assert (rendered["ok"], rendered["warn"], rendered["no"]) == (9, 1, 2)


def test_the_map_is_painted_in_the_design_tokens(rendered):
    assert rendered["tokenCells"] > 0


def test_the_map_states_its_own_scale(rendered):
    assert rendered["scale"] == "16,384 blocks · 488,281 B each"


def test_progress_tracks_do_not_reflow(rendered):
    assert len(set(rendered["trackWidths"])) == 1


def test_the_carve_never_draws_a_percentage_it_does_not_have(browser):
    page = browser.new_page(viewport={"width": 1600, "height": 1000})
    page.goto(PAGE.as_uri())
    page.wait_for_timeout(400)
    state = page.evaluate("""() => {
      document.getElementById('bars').hidden = false;
      const b = document.getElementById('barCarve');
      b.style.width = ''; b.parentNode.setAttribute('data-indet','1');
      document.getElementById('valCarve').textContent =
        'scanning \\u00b7 no progress is reported';
      return {indet: b.parentNode.getAttribute('data-indet'),
              anim: getComputedStyle(b).animationName,
              value: document.getElementById('valCarve').textContent};
    }""")
    assert state["indet"] == "1"
    assert state["anim"] == "shuttle", "the indicator must not rest at a position"
    assert "%" not in state["value"]
    page.close()


def test_the_page_exposes_exactly_the_seam_this_file_uses(browser):
    page = browser.new_page()
    page.goto(PAGE.as_uri())
    page.wait_for_timeout(300)
    keys = page.evaluate("() => Object.keys(window.__rec).sort()")
    assert keys == ["MAP", "paintResult", "renderEnrolment", "setEnrol", "setVol"]
    page.close()
