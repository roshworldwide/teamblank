//! The wipe telemetry stream: what the instrument watches while a medium is destroyed.
//!
//! CLAUDE.md fixes the path as `Rust -> Tauri events -> React`, *live, not polled*.
//! That single word decides the whole shape of this module. A poller asks "where are
//! you now?" and gets one answer per ask; the regions between two asks are never
//! painted and the hex pane shows whatever happened to be under the head at sample
//! time. A push stream can promise something a poller cannot: **every sector of the
//! medium appears in exactly one delivered event, in order, even when the consumer
//! is too slow to keep up.** The sector map is a canvas of the entire medium, so an
//! unpainted region is a visible lie about work that was actually done.
//!
//! ## The three decisions this module makes
//!
//! **1 · What carries the events: a sink trait, with a channel behind it.**
//!
//! Three carriers were considered.
//!
//! * A **callback** (`FnMut(&Event)`) is the cheapest — no allocation, no queue —
//!   and it is wrong here. It runs the consumer *on the write loop's thread*. A UI
//!   that takes 8 ms to repaint a 100k-block canvas would then stall a destructive
//!   operation for 8 ms per frame, and a panic in the consumer would unwind through
//!   a half-written sector range. The engine must never be able to be slowed, or
//!   killed, by its own instrument.
//! * A **writer** (`impl Write`, JSONL) is the right shape for the *recording*, and
//!   nothing else: it is synchronous, it can block on disk, and it cannot be read
//!   live by a UI thread.
//! * A **channel** decouples correctly, but committing the engine to
//!   `std::sync::mpsc` bakes one transport into a signature that Tauri, a file
//!   recorder, and every test would all have to pretend to be.
//!
//! So the engine sees exactly one thing: [`EventSink`], one object-safe method. The
//! channel ([`ChannelSink`]) is the live carrier, [`RecorderSink`] is the writer,
//! [`FanoutSink`] runs both at once, and that composition — not a bespoke code path —
//! is the production wiring. Zero new dependencies: `std::sync::mpsc::sync_channel`
//! is the bounded queue, so no `crossbeam`.
//!
//! **2 · Backpressure: lossy on frames, lossless on coverage.**
//!
//! The queue is bounded ([`DEFAULT_CHANNEL_CAPACITY`]) and the producer *never*
//! blocks on a progress event. When the queue is full, [`ChannelSink`] does not drop
//! the event: it **merges** it into the next one. The merged event keeps the newest
//! head bytes, entropy, byte count and throughput, and takes the **union** of the two
//! sector ranges. A slow consumer therefore sees fewer, wider frames — never a hole.
//! [`Trace::coverage_gaps`] is the assertion of that invariant, and it is a test in
//! this file rather than a claim in this comment.
//!
//! Two events are exempt from merging: the [`Header`], which defines the canvas the
//! UI is about to allocate, and the [`End`], which is the terminal state. Losing
//! either is not a dropped frame, it is a broken UI. They are delivered with a
//! *bounded* wait ([`TERMINAL_SEND_TIMEOUT_MS`]), never an unbounded `send` — an
//! unbounded one deadlocked the wipe outright against a consumer that stopped
//! reading, and no property of the instrument may be able to prevent a destructive
//! operation from finishing. Past the bound the event is abandoned and counted in
//! [`ChannelSink::abandoned`]; the recorded trace still holds it.
//!
//! Pass boundaries are also exempt from merging: a range from pass 1 and a range
//! from pass 2 paint different canvas layers and their union is meaningless, so a
//! pending event from the previous pass is flushed with a blocking send instead.
//!
//! **3 · Recording and replay, which are not optional.**
//!
//! `demo_script.md`: *"Demo mode replays a recorded telemetry trace. A live
//! filesystem operation never stands between the team and a working demo."*
//!
//! The recorder is deliberately wired **upstream of the coalescing**, on its own
//! branch of the fanout. The channel is lossy-by-design because a human consumer is
//! slow; a file is not, so the trace holds the full-rate stream. This matters: if the
//! trace recorded the post-coalesce stream, its contents would depend on how busy the
//! UI thread happened to be, and Phase 6's demo would differ run to run for reasons
//! nobody could see. Replay pushes the recorded full-rate stream back through the
//! same [`EventSink`] the live engine uses, so the coalescing policy applies again on
//! replay exactly as it did live.
//!
//! The wire format is JSON Lines, one flat object per line, no nesting: the React
//! side reads it with `JSON.parse` per line and needs no schema library, and this
//! module parses it back with a strict reader ([`TraceReader`]) small enough to keep
//! the zero-dependency rule.
//!
//! **The trace is not byte-reproducible and is not a certificate input.** It carries
//! wall-clock timings and measured throughput, which differ per run by construction.
//! CLAUDE.md rule 6 constrains the *certificate*; the trace is an observation of one
//! run and is labelled with the run's start time. Anything reproducible that is
//! derived from a wipe must be derived from the wipe, not from this stream.
//!
//! ## What the event has to carry, and why each field is there
//!
//! The instrument has two live panes and neither may read the device itself — the
//! device is mid-destruction and a second reader would both perturb the measured
//! throughput and race the writer.
//!
//! * *Sector map* — a canvas of the whole medium with a write head sweeping it.
//!   Needs `total_sectors` once (in the [`Header`]) and then, per event,
//!   `first_sector` + `sector_count` + `pass`.
//! * *Hex pane* — the bytes under the head right now. Needs the bytes themselves:
//!   [`Progress::head`], [`HEAD_BYTES`] of the buffer that was just written, at
//!   [`Progress::head_sector`]. 256 bytes is 16 rows of 16, one conventional hex
//!   page, and it is the single largest contributor to event size — see the module
//!   tests for the measured figure.
//! * Everything else — `bytes_done`, `throughput_bps`, `entropy_sample` — is the
//!   numeric readout, and CLAUDE.md rule 2 applies to every one of them.
//!
//! `entropy_sample` is a **real Shannon measurement of the pattern written to the
//! sectors that frame covers** — the source buffer, not a read-back — and it is not a
//! constant and not a property of the method name: a zero-fill pass reads 0.0000 and
//! a seeded random pass reads ~7.99. What is on the medium is a separate claim, made
//! by [`crate::verify`] and by the certificate's whole-medium entropy figures, both of
//! which read the sectors back. Every chunk contributes
//! [`ENTROPY_CHUNK_SAMPLE_BYTES`] of strided sample to the frame's histogram, which
//! is reset at each frame — so a frame forced at a pass boundary, with no chunk in
//! hand, still reports the range it claims instead of a false zero. The estimator's
//! finite-sample bias is stated on [`entropy_sampled`], because the demo quotes the
//! number on screen.
//!
//! ## Measured, 2026-09-03, 256 MiB scratchpad copy of the fixture, arm64 release
//!
//! | run | wall | events | achieved | max gap | trace |
//! |---|---|---|---|---|---|
//! | 40 ms period, 1 MiB chunk, buffered | 228.6 ms | 6 | 26.25 Hz | 43.98 ms | 5,597 B |
//! | 40 ms period, 1 MiB chunk, `sync_data` per 4 MiB | 514.2 ms | 12 | 23.34 Hz | 46.01 ms | 10,558 B |
//! | 4 ms period, 256 KiB chunk | 167.3 ms | 38 | 227.16 Hz | 6.25 ms | 32,145 B |
//! | 40 ms period, 3-pass NIST Clear (768 MiB written) | 260.4 ms | 5 | see below | 40.10 ms | 4,767 B |
//!
//! A progress frame is **810-833 bytes** on the wire, mean 827-831 across runs; the
//! header is 411-412 and the end record 209-216. 512 of those bytes are the hex page,
//! which is 62% of the frame and the only thing worth shrinking if size ever matters.
//! [`Telemetry::wrote`] costs **0.26% to 2.82% of wall clock** at the default period,
//! and 4.65% only when forced to emit on every one of 1,024 chunks.
//!
//! **20 Hz is met and is not the interesting constraint.** The interesting number is
//! that a 256 MiB single-pass wipe finishes in 114-514 ms on this hardware, so the
//! *whole sweep* is 3 to 12 frames long. The rate floor holds; the sweep is simply
//! over before a human sees it. Do not slow the engine to fix that — a wipe throttled
//! for a demo is a lie about throughput, and the behavioural audit reads the same
//! clock. Record at a shorter period and replay slower instead: the 4 ms recording
//! above, replayed at 0.10x, measured **1,677.9 ms of sweep at 22.65 frames per second
//! on screen**, with `coverage_gaps()` empty, while `t_ms` and the certificate still
//! carry the true 167.3 ms.
//!
//! One caution on `achieved_hz`, which is `events / wall`: the 3-pass run reports
//! 19.20 Hz because a 91.2 ms trailing `sync_all` counted into `wall_ms` while
//! emitting nothing. Every real inter-frame gap in that run was 40.10 ms or less.
//! `max_gap_ms` is the rate verdict; `achieved_hz` is a job average.
//!
//! Entropy tracks the data and not the method name: the 3-pass run's first frame
//! measured **0.0000** bits/byte over pass 1's zero fill and its last **7.9998** over
//! pass 3's random, sampling 843,776 to 2,097,152 bytes per frame.
//!
//! Backpressure, measured: forced to 1,024 frames against a consumer taking 2 ms
//! each, the producer emitted **1,024** and the consumer received **53**, with
//! **971 coalesced away** — and `Trace::coverage_gaps()` on what the consumer
//! actually received was **empty**. Frames were lost; not one sector was.

use std::fmt;
use std::io::{self, BufRead, Write};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Wire-format identifier. Moves only with the same ceremony as a confidence weight.
pub const SCHEMA: &str = "sentinelwipe.wipe.telemetry/1";

/// The floor the build pack sets: progress events at >= 20 Hz.
pub const MIN_RATE_HZ: f64 = 20.0;

/// Nominal emit period. 40 ms is 25 Hz — the 20 Hz floor plus 25% margin, so a
/// single late chunk does not put the achieved rate under the requirement. Going
/// faster buys nothing: the canvas repaints at display rate and a 100k-block sector
/// map cannot show a finer sweep than one event per ~4 ms anyway.
pub const DEFAULT_PERIOD_MS: u64 = 40;

/// Bytes of the just-written buffer carried in every event for the hex pane.
/// 16 rows x 16 columns = one hex page.
pub const HEAD_BYTES: usize = 256;

/// Budget for a one-shot [`entropy_sampled`] call over a single buffer.
pub const ENTROPY_SAMPLE_BYTES: usize = 65_536;

/// Bytes [`Telemetry::wrote`] samples from **every** chunk into the frame's
/// histogram.
///
/// The frame's entropy is therefore measured over the whole sector range the frame
/// claims, not over whichever chunk happened to trip the clock — and it exists even
/// on a frame forced at a pass boundary, where there is no "current" chunk at all.
/// An earlier design measured only the emitting chunk and published `0.0000` on
/// forced frames, which is the single most misleading number this instrument could
/// show: it is exactly what a zero-fill produces.
///
/// 8 KiB per chunk costs one strided pass over 1/128th of a 1 MiB chunk. Measured
/// against a page-cache-backed image at ~2 GB/s it is under 2% of wall clock, and
/// against any real medium it disappears. The per-frame sample size is published in
/// `entropy_sample_bytes`, because the plug-in estimator's bias depends on it.
pub const ENTROPY_CHUNK_SAMPLE_BYTES: usize = 8_192;

/// How long a terminal event — the [`Header`], the [`End`], a pass-boundary flush —
/// waits for room in a full queue before it is abandoned.
///
/// It is a bound, not a blocking send, and the difference is not theoretical: an
/// unbounded `send` here **deadlocked the wipe** against a consumer that stopped
/// reading. Three tests in this file hung for over sixty seconds before the timeout
/// was introduced. Nothing about an instrument may be able to stop a destructive
/// operation from finishing, and "the receiver still exists" is not the same
/// condition as "the receiver is reading".
///
/// 100 ms is two and a half emit periods. A consumer that cannot take one event in
/// that time is not rendering anything a person is watching, and the recorded trace
/// still holds every event regardless — see [`ChannelSink::abandoned`].
///
/// Implemented as `try_send` polled every [`TERMINAL_RETRY_MS`] rather than
/// `SyncSender::send_timeout`, which is still unstable in `std` and would need a
/// nightly feature this project does not take.
pub const TERMINAL_SEND_TIMEOUT_MS: u64 = 100;

/// Poll interval while a terminal event waits for room.
pub const TERMINAL_RETRY_MS: u64 = 1;

/// Bounded queue depth for [`ChannelSink`]. 8 frames is ~320 ms of slack at 25 Hz:
/// long enough to absorb a garbage-collection pause in the UI, short enough that a
/// consumer which stops entirely starts coalescing within a third of a second
/// instead of growing an unbounded backlog behind a destructive operation.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 8;

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Opens the stream. Everything the UI needs to allocate its canvas before a single
/// sector has been touched.
#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    pub schema: String,
    /// Identity of the medium as the device layer named it. Never a runtime
    /// `/dev/diskN` this project invented; see architecture D1.
    pub device: String,
    pub sector_size: u32,
    pub total_sectors: u64,
    /// The method label. If the operation is simulated the word `simulated` is in
    /// this string, enforced by [`Telemetry::start`] — operator decision 3 requires
    /// it in the field itself, never in a footnote.
    pub method: String,
    pub simulated: bool,
    pub passes: u32,
    /// Hex seed of the pattern generator, so a run is describable. Empty for
    /// patterns that take no seed (zero fill).
    pub pattern_seed_hex: String,
    /// Wall clock at start. The trace is an observation of one run and says which.
    pub started_unix_ms: u128,
    /// The emit period this run targeted, so a replay can tell an intended gap from
    /// a stall.
    pub period_ms: u64,
}

/// One frame of the sweep.
#[derive(Debug, Clone, PartialEq)]
pub struct Progress {
    /// Monotone from 0 across the whole job, including coalesced-away frames, so a
    /// consumer can tell how many frames it never saw without trusting `coalesced`.
    pub seq: u64,
    /// Milliseconds since [`Telemetry::start`], monotonic. Replay paces on this.
    pub t_ms: f64,
    /// 1-based.
    pub pass: u32,
    pub passes: u32,
    /// Sector range covered since the last *delivered* event: `[first_sector,
    /// first_sector + sector_count)`. Under backpressure this is the union of
    /// several frames, which is what makes the map complete.
    pub first_sector: u64,
    pub sector_count: u64,
    /// Cumulative over the whole job, all passes.
    pub bytes_done: u64,
    /// `total_sectors * sector_size * passes`.
    pub bytes_total: u64,
    /// Mean over the job so far.
    pub throughput_bps: f64,
    /// Over the interval since the previous emitted frame. This is the one the
    /// behavioural audit's plausibility bound is built from; the mean hides a stall.
    pub throughput_inst_bps: f64,
    /// Shannon entropy, bits/byte, of the **pattern written to** the sectors this
    /// frame covers: [`ENTROPY_CHUNK_SAMPLE_BYTES`] strided out of every source
    /// buffer handed to `write_sectors` since the previous frame. Real, never a
    /// constant, and never a property of the method name — a zero-fill pass reads
    /// 0.0000 and a seeded random pass reads ~7.99.
    ///
    /// **It is a measurement of what was sent, not of what is on the medium**, and
    /// the distinction is not pedantic: a device that accepted a write and discarded
    /// it would leave this pane reading 7.999 over untouched sectors. Evidence about
    /// the medium comes from reads — `verify::verify_pass`, and the whole-medium
    /// `entropy_bits_per_byte.before`/`.after` in the certificate, both of which read
    /// the sectors back. Reading back here instead would put a read in the middle of
    /// the write loop and perturb the very throughput the behavioural audit measures
    /// off this same clock, so the live pane states what it has.
    pub entropy_sample: f64,
    /// How many bytes that measurement read. Published because a bits/byte figure
    /// without its sample size is not a measurement (CLAUDE.md rule 2).
    pub entropy_sample_bytes: u32,
    /// Where [`Progress::head`] was read from.
    pub head_sector: u64,
    /// Valid prefix length of `head`.
    pub head_len: u16,
    /// The bytes now under the write head, for the hex pane. Inline, so the hot path
    /// allocates nothing.
    pub head: [u8; HEAD_BYTES],
    /// Frames merged into this one by backpressure. 0 on a healthy consumer.
    pub coalesced: u32,
}

impl Progress {
    /// The valid prefix of [`Progress::head`].
    pub fn head_bytes(&self) -> &[u8] {
        &self.head[..(self.head_len as usize).min(HEAD_BYTES)]
    }

    /// Exclusive end of the covered sector range.
    pub fn sector_end(&self) -> u64 {
        self.first_sector.saturating_add(self.sector_count)
    }

    #[cfg(test)]
    fn blank() -> Self {
        Progress {
            seq: 0,
            t_ms: 0.0,
            pass: 1,
            passes: 1,
            first_sector: 0,
            sector_count: 0,
            bytes_done: 0,
            bytes_total: 0,
            throughput_bps: 0.0,
            throughput_inst_bps: 0.0,
            entropy_sample: 0.0,
            entropy_sample_bytes: 0,
            head_sector: 0,
            head_len: 0,
            head: [0u8; HEAD_BYTES],
            coalesced: 0,
        }
    }
}

/// Closes the stream. Carries the stream's own self-measurement, so a consumer can
/// state the achieved event rate without timing the events itself.
#[derive(Debug, Clone, PartialEq)]
pub struct End {
    pub seq: u64,
    pub t_ms: f64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    /// Progress events emitted by the producer (before any coalescing).
    pub events: u64,
    pub wall_ms: f64,
    pub mean_throughput_bps: f64,
    /// `events / (wall_ms/1000)`.
    ///
    /// **Not the figure that decides whether the rate floor held.** It is a job
    /// average, and any stretch where nothing was written deflates it: a measured
    /// 3-pass run here reported 12.50 Hz because a 215.8 ms trailing `sync_all`
    /// counted into `wall_ms` while emitting no frames, with every actual
    /// inter-frame gap at 40.18 ms or less. Read [`End::max_gap_ms`] for the floor.
    pub achieved_hz: f64,
    /// Largest gap between two consecutive emitted frames. This is the figure that
    /// decides whether the >= 20 Hz floor held: a single 300 ms gap is invisible in
    /// a mean and very visible on a sector map.
    pub max_gap_ms: f64,
    /// `complete`, or `aborted:<reason>`.
    pub outcome: String,
}

/// One item on the wire.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    Header(Header),
    Progress(Progress),
    End(End),
}

// ---------------------------------------------------------------------------
// The sink seam
// ---------------------------------------------------------------------------

/// Where events go. The engine holds exactly one of these and knows nothing else
/// about the transport.
///
/// Object safe on purpose: `Box<dyn EventSink>` is how the Tauri layer, the
/// recorder, and a test collector all reach the same engine without generics
/// leaking into the wipe API.
pub trait EventSink {
    fn emit(&mut self, ev: &Event);
    /// Called once at the end of a job. Recorders flush here; a channel is a no-op.
    fn flush(&mut self) {}
}

impl<T: EventSink + ?Sized> EventSink for Box<T> {
    fn emit(&mut self, ev: &Event) {
        (**self).emit(ev)
    }
    fn flush(&mut self) {
        (**self).flush()
    }
}

impl<T: EventSink + ?Sized> EventSink for &mut T {
    fn emit(&mut self, ev: &Event) {
        (**self).emit(ev)
    }
    fn flush(&mut self) {
        (**self).flush()
    }
}

/// Discards everything. For a wipe run with no instrument attached.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&mut self, _ev: &Event) {}
}

/// Keeps every event in memory. The test and verification sink; also how a replay
/// consumer materialises a stream it wants to assert over.
#[derive(Debug, Default, Clone)]
pub struct CollectSink {
    pub events: Vec<Event>,
    pub flushes: u32,
}

impl CollectSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn progress(&self) -> Vec<&Progress> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::Progress(p) => Some(p),
                _ => None,
            })
            .collect()
    }
}

impl EventSink for CollectSink {
    fn emit(&mut self, ev: &Event) {
        self.events.push(ev.clone());
    }
    fn flush(&mut self) {
        self.flushes += 1;
    }
}

/// Sends to any number of sinks. The production wiring is
/// `Fanout[ChannelSink, RecorderSink]`, which is what puts the recorder upstream of
/// the channel's coalescing.
#[derive(Default)]
pub struct FanoutSink {
    sinks: Vec<Box<dyn EventSink>>,
}

impl FanoutSink {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(mut self, s: Box<dyn EventSink>) -> Self {
        self.sinks.push(s);
        self
    }
    pub fn push(&mut self, s: Box<dyn EventSink>) {
        self.sinks.push(s);
    }
    pub fn len(&self) -> usize {
        self.sinks.len()
    }
    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }
}

impl EventSink for FanoutSink {
    fn emit(&mut self, ev: &Event) {
        for s in self.sinks.iter_mut() {
            s.emit(ev);
        }
    }
    fn flush(&mut self) {
        for s in self.sinks.iter_mut() {
            s.flush();
        }
    }
}

// ---------------------------------------------------------------------------
// The live carrier, and the backpressure policy
// ---------------------------------------------------------------------------

/// Bounded, non-blocking-on-progress channel sink. This is the whole backpressure
/// policy, in one place.
pub struct ChannelSink {
    tx: SyncSender<Event>,
    pending: Option<Progress>,
    coalesced_total: u64,
    delivered: u64,
    abandoned: u64,
    disconnected: bool,
}

/// Build the live carrier. The [`Receiver`] is handed to the UI thread (or the Tauri
/// event bridge); the [`ChannelSink`] goes to the engine.
pub fn channel(capacity: usize) -> (ChannelSink, Receiver<Event>) {
    let (tx, rx) = sync_channel(capacity.max(1));
    (
        ChannelSink {
            tx,
            pending: None,
            coalesced_total: 0,
            delivered: 0,
            abandoned: 0,
            disconnected: false,
        },
        rx,
    )
}

impl ChannelSink {
    /// Frames merged away by backpressure over the life of the sink.
    pub fn coalesced_total(&self) -> u64 {
        self.coalesced_total
    }
    /// Events actually handed to the receiver.
    pub fn delivered(&self) -> u64 {
        self.delivered
    }
    /// Terminal events given up on after [`TERMINAL_SEND_TIMEOUT_MS`] because the
    /// consumer had stopped reading. Non-zero means the live view is incomplete and
    /// the recorded trace is the authority.
    pub fn abandoned(&self) -> u64 {
        self.abandoned
    }
    /// True once the receiver has been dropped. Every later emit is a no-op; a
    /// closed instrument must not be able to stall or fail a wipe.
    pub fn disconnected(&self) -> bool {
        self.disconnected
    }

    /// Deliver an event that must not be coalesced away, waiting at most
    /// [`TERMINAL_SEND_TIMEOUT_MS`] for room. Never waits indefinitely: see that
    /// constant for the deadlock this replaced.
    fn send_terminal(&mut self, ev: Event) {
        if self.disconnected {
            return;
        }
        let deadline = Instant::now() + Duration::from_millis(TERMINAL_SEND_TIMEOUT_MS);
        let mut ev = ev;
        loop {
            match self.tx.try_send(ev) {
                Ok(()) => {
                    self.delivered += 1;
                    return;
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.disconnected = true;
                    return;
                }
                Err(TrySendError::Full(back)) => {
                    if Instant::now() >= deadline {
                        self.abandoned += 1;
                        return;
                    }
                    ev = back;
                    std::thread::sleep(Duration::from_millis(TERMINAL_RETRY_MS));
                }
            }
        }
    }

    fn send_progress(&mut self, p: Progress) {
        if self.disconnected {
            return;
        }
        match self.tx.try_send(Event::Progress(p)) {
            Ok(()) => self.delivered += 1,
            Err(TrySendError::Full(Event::Progress(p))) => {
                // Hold it. The next frame will absorb it, range and all.
                self.pending = Some(p);
            }
            Err(TrySendError::Full(_)) => unreachable!("only Progress is try_sent"),
            Err(TrySendError::Disconnected(_)) => self.disconnected = true,
        }
    }

    /// Push a held frame out without merging. Used when the next frame belongs to a
    /// different pass, where a union would be meaningless.
    fn flush_pending_terminal(&mut self) {
        if let Some(p) = self.pending.take() {
            self.send_terminal(Event::Progress(p));
        }
    }
}

/// Merge `prev` (older) into `next` (newer), preserving coverage.
///
/// The newer frame wins on everything instantaneous — head bytes, entropy,
/// `bytes_done`, throughput, `t_ms`, `seq` — because a UI showing a *stale* hex page
/// would be worse than showing fewer of them. The sector range is the union, because
/// that is the one property the canvas cannot reconstruct from a later frame.
fn merge_progress(prev: Progress, next: Progress) -> Progress {
    debug_assert_eq!(prev.pass, next.pass, "merge across passes is not meaningful");
    let mut out = next;
    let lo = prev.first_sector.min(out.first_sector);
    let hi = prev.sector_end().max(out.sector_end());
    out.first_sector = lo;
    out.sector_count = hi - lo;
    out.coalesced = out.coalesced.saturating_add(prev.coalesced).saturating_add(1);
    out
}

impl EventSink for ChannelSink {
    fn emit(&mut self, ev: &Event) {
        match ev {
            // The header defines the canvas and the end is the terminal state.
            // Neither is a frame; neither may be dropped.
            Event::Header(_) => self.send_terminal(ev.clone()),
            Event::End(_) => {
                self.flush_pending_terminal();
                self.send_terminal(ev.clone());
            }
            Event::Progress(p) => {
                let mut p = p.clone();
                if let Some(prev) = self.pending.take() {
                    if prev.pass == p.pass {
                        self.coalesced_total += 1;
                        p = merge_progress(prev, p);
                    } else {
                        self.send_terminal(Event::Progress(prev));
                    }
                }
                self.send_progress(p);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The recorder
// ---------------------------------------------------------------------------

/// Writes the stream as JSON Lines. Wrap the writer in a `BufWriter`: this sink
/// issues one `write_all` per event and does not buffer for you.
///
/// I/O errors are captured, not propagated: a failing trace file must not abort a
/// destructive operation half way through a sector range. [`RecorderSink::error`]
/// reports it afterwards, and the wipe result should carry it.
pub struct RecorderSink<W: Write> {
    w: W,
    bytes: u64,
    lines: u64,
    err: Option<io::Error>,
}

impl<W: Write> RecorderSink<W> {
    pub fn new(w: W) -> Self {
        RecorderSink {
            w,
            bytes: 0,
            lines: 0,
            err: None,
        }
    }
    /// Bytes written to the trace so far.
    pub fn bytes_written(&self) -> u64 {
        self.bytes
    }
    pub fn lines_written(&self) -> u64 {
        self.lines
    }
    /// The first I/O error, if the trace is incomplete.
    pub fn error(&self) -> Option<&io::Error> {
        self.err.as_ref()
    }
    pub fn into_inner(self) -> W {
        self.w
    }
}

impl<W: Write> EventSink for RecorderSink<W> {
    fn emit(&mut self, ev: &Event) {
        if self.err.is_some() {
            return;
        }
        let line = to_json_line(ev);
        match self.w.write_all(line.as_bytes()) {
            Ok(()) => {
                self.bytes += line.len() as u64;
                self.lines += 1;
            }
            Err(e) => self.err = Some(e),
        }
    }
    fn flush(&mut self) {
        if self.err.is_none() {
            if let Err(e) = self.w.flush() {
                self.err = Some(e);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entropy
// ---------------------------------------------------------------------------

/// Shannon entropy in bits/byte over a strided sample of `buf`.
///
/// One-shot form, used by callers outside the frame loop and by the tests.
/// [`Telemetry`] does not call this: it accumulates across every chunk of a frame
/// with [`sample_into`] instead. Both share the same strided sampling.
///
/// Returns `(bits_per_byte, bytes_sampled)`.
///
/// **Finite-sample bias, because the demo quotes this number on screen.** The
/// plug-in estimator is biased low by about `(K-1) / (2 N ln 2)` bits for `K` = 256
/// symbols and `N` samples: 0.0028 bits at 64 KiB, 0.0225 bits at 8 KiB. A perfectly
/// uniform stream therefore measures ~7.997 at the one-shot budget and never 8.0000.
/// Say 7.997, not "8.0" — and note that the whole-image figure the demo compares
/// against (7.0617 bits/byte, `fixture.manifest.json`) is computed over all
/// 268,435,456 bytes, where the same bias is 0.0000007 bits and vanishes. The two
/// figures are not measured over the same support and a slide must not subtract them
/// as if they were.
pub fn entropy_sampled(buf: &[u8], sector_size: usize, budget: usize) -> (f64, u32) {
    let mut hist = [0u64; 256];
    let n = sample_into(buf, sector_size, budget, &mut hist);
    (shannon(&hist, n), n as u32)
}

/// Add a strided, non-overlapping sample of `buf` to `hist`, spending at most
/// `budget` bytes, and return how many bytes were counted.
///
/// The windows are sector-sized and spread evenly across the whole buffer, so a
/// chunk that is half zeroes and half random reads as such. Taking the first
/// `budget` bytes instead would be a measurement of the head, described as a
/// measurement of the chunk.
pub fn sample_into(buf: &[u8], sector_size: usize, budget: usize, hist: &mut [u64; 256]) -> usize {
    if buf.is_empty() || budget == 0 {
        return 0;
    }
    if buf.len() <= budget {
        for &b in buf {
            hist[b as usize] += 1;
        }
        return buf.len();
    }
    let win = sector_size.max(1).min(budget).min(buf.len());
    let windows = (budget / win).max(1);
    let span = buf.len() - win;
    let mut n = 0usize;
    for i in 0..windows {
        let off = if windows == 1 {
            0
        } else {
            span * i / (windows - 1)
        };
        for &b in &buf[off..off + win] {
            hist[b as usize] += 1;
        }
        n += win;
    }
    n
}

/// Shannon entropy in bits/byte of a 256-bin byte histogram holding `n` counts.
pub fn shannon(hist: &[u64; 256], n: usize) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let nf = n as f64;
    let mut h = 0.0f64;
    for &c in hist.iter() {
        if c > 0 {
            let p = c as f64 / nf;
            h -= p * p.log2();
        }
    }
    // A single-symbol buffer would otherwise render as `-0.0000` in a hex readout.
    if h == 0.0 {
        0.0
    } else {
        h
    }
}

// ---------------------------------------------------------------------------
// The producer
// ---------------------------------------------------------------------------

/// Everything the [`Header`] needs that the wipe engine knows and telemetry does not.
#[derive(Debug, Clone)]
pub struct WipeSpec {
    pub device: String,
    pub sector_size: u32,
    pub total_sectors: u64,
    pub method: String,
    /// True for ATA Secure Erase / NVMe Sanitize / crypto-erase against an image
    /// file, where the command is not issued to any controller. Operator decision 3.
    pub simulated: bool,
    pub passes: u32,
    pub pattern_seed_hex: String,
}

impl WipeSpec {
    /// The label that goes on the wire. Operator decision 3: a simulated operation
    /// carries the word in the field itself, so a consumer cannot render the method
    /// without rendering the caveat.
    pub fn method_label(&self) -> String {
        if self.simulated && !self.method.to_ascii_lowercase().contains("simulated") {
            format!("simulated:{}", self.method)
        } else {
            self.method.clone()
        }
    }
}

/// What the stream measured about itself. Returned by [`Telemetry::finish`] and
/// mirrored into the [`End`] event, so the achieved rate is never something a slide
/// asserts.
#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    pub events: u64,
    pub wall_ms: f64,
    pub bytes_done: u64,
    pub mean_throughput_bps: f64,
    /// Job average. See [`End::achieved_hz`]: a trailing flush deflates it.
    /// [`Summary::max_gap_ms`] and [`Summary::met_rate_floor`] are the rate verdict.
    pub achieved_hz: f64,
    pub min_gap_ms: f64,
    pub max_gap_ms: f64,
    /// True when no gap between consecutive frames exceeded `1000 / MIN_RATE_HZ`.
    pub met_rate_floor: bool,
}

/// The engine's handle on the stream. Hold one per wipe job.
///
/// Contract with the wipe engine, which owns the write loop:
///
/// ```ignore
/// let mut tm = Telemetry::start(spec, sink, None);
/// for pass in 1..=passes {
///     for chunk in chunks {
///         device.write_sectors(first, &buf)?;
///         tm.wrote(pass, first, &buf);      // after the write, never before
///     }
///     tm.end_pass(pass);                    // forces a frame; closes the canvas layer
/// }
/// let summary = tm.finish("complete");
/// ```
///
/// `wrote` is called once per written chunk and costs one `Instant::now` plus a few
/// integer updates on the frames it does not emit — at a 1 MiB chunk and 1 GB/s that
/// is ~1000 calls/s of ~25 ns each. It does **not** hash, allocate, or touch the
/// device.
pub struct Telemetry<S: EventSink> {
    sink: S,
    period: Duration,
    t0: Instant,

    sector_size: u64,
    total_sectors: u64,
    passes: u32,
    bytes_total: u64,

    seq: u64,
    events: u64,
    cur_pass: u32,

    // Coverage accumulated since the last emitted frame.
    span_lo: u64,
    span_hi: u64,
    have_span: bool,

    bytes_done: u64,
    last_emit: Instant,
    last_emit_bytes: u64,
    last_emit_at_ms: f64,

    head: [u8; HEAD_BYTES],
    head_len: u16,
    head_sector: u64,

    // Byte histogram over every chunk written since the last frame, so the frame's
    // entropy describes the sector range the frame actually claims — and exists even
    // on a frame forced at a pass boundary, where there is no current chunk.
    hist: [u64; 256],
    hist_n: u64,

    min_gap_ms: f64,
    max_gap_ms: f64,

    finished: bool,
}

impl<S: EventSink> Telemetry<S> {
    /// Emits the [`Header`] immediately and starts the clock.
    ///
    /// `period` defaults to [`DEFAULT_PERIOD_MS`]. A zero period emits on every
    /// `wrote` call, which is what the deterministic tests use.
    pub fn start(spec: WipeSpec, mut sink: S, period: Option<Duration>) -> Self {
        let period = period.unwrap_or(Duration::from_millis(DEFAULT_PERIOD_MS));
        let sector_size = spec.sector_size.max(1) as u64;
        let passes = spec.passes.max(1);
        let bytes_total = spec
            .total_sectors
            .saturating_mul(sector_size)
            .saturating_mul(passes as u64);

        let header = Header {
            schema: SCHEMA.to_string(),
            device: spec.device.clone(),
            sector_size: spec.sector_size.max(1),
            total_sectors: spec.total_sectors,
            method: spec.method_label(),
            simulated: spec.simulated,
            passes,
            pattern_seed_hex: spec.pattern_seed_hex.clone(),
            started_unix_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            period_ms: period.as_millis() as u64,
        };
        sink.emit(&Event::Header(header));

        let now = Instant::now();
        Telemetry {
            sink,
            period,
            t0: now,
            sector_size,
            total_sectors: spec.total_sectors,
            passes,
            bytes_total,
            seq: 0,
            events: 0,
            cur_pass: 1,
            span_lo: 0,
            span_hi: 0,
            have_span: false,
            bytes_done: 0,
            last_emit: now,
            last_emit_bytes: 0,
            last_emit_at_ms: 0.0,
            head: [0u8; HEAD_BYTES],
            head_len: 0,
            head_sector: 0,
            hist: [0u64; 256],
            hist_n: 0,
            min_gap_ms: f64::INFINITY,
            max_gap_ms: 0.0,
            finished: false,
        }
    }

    /// Record one completed chunk write. Call **after** the bytes are on the medium:
    /// telemetry that runs ahead of the device is a progress bar, not an instrument.
    ///
    /// `buf` is the buffer that was just written. It is read for the hex-pane head
    /// and, on emitting frames only, for the entropy sample.
    pub fn wrote(&mut self, pass: u32, first_sector: u64, buf: &[u8]) {
        if self.finished {
            return;
        }
        let pass = pass.max(1);
        if pass != self.cur_pass {
            // Close the previous layer before any of the new pass lands in the span.
            self.emit_now(self.cur_pass);
            self.cur_pass = pass;
            self.have_span = false;
        }

        let sectors = (buf.len() as u64).div_ceil(self.sector_size);
        let hi = first_sector.saturating_add(sectors);
        if self.have_span {
            self.span_lo = self.span_lo.min(first_sector);
            self.span_hi = self.span_hi.max(hi);
        } else {
            self.span_lo = first_sector;
            self.span_hi = hi;
            self.have_span = true;
        }
        self.bytes_done = self.bytes_done.saturating_add(buf.len() as u64);

        let n = buf.len().min(HEAD_BYTES);
        self.head[..n].copy_from_slice(&buf[..n]);
        self.head_len = n as u16;
        self.head_sector = first_sector;

        // Every chunk contributes to the frame's entropy, not just the one that
        // happens to trip the clock.
        self.hist_n += sample_into(
            buf,
            self.sector_size as usize,
            ENTROPY_CHUNK_SAMPLE_BYTES,
            &mut self.hist,
        ) as u64;

        if self.last_emit.elapsed() >= self.period {
            self.emit_now(pass);
        }
    }

    /// Force a frame at the end of a pass, so the canvas layer is complete before the
    /// next pass starts overwriting it.
    pub fn end_pass(&mut self, pass: u32) {
        if self.finished {
            return;
        }
        self.emit_now(pass.max(1));
    }

    /// Force a frame now, whatever the clock says. For the wipe engine to call at a
    /// state change worth showing — a method switch, a retry, a verification start.
    ///
    /// **Call this immediately before any blocking call longer than the emit
    /// period.** Measured on this machine: a write loop issuing `sync_data()` every
    /// 4 MiB produced a 50.05 ms inter-frame gap and missed the 20 Hz floor, because
    /// a frame can only be emitted from a `wrote` call and the sync sat between two
    /// of them. Either `tick` before the sync, or sync at a granularity whose
    /// duration is under the period.
    pub fn tick(&mut self, pass: u32) {
        if self.finished {
            return;
        }
        self.emit_now(pass.max(1));
    }

    fn emit_now(&mut self, pass: u32) {
        if !self.have_span {
            return; // nothing painted since the last frame; an empty range is noise
        }
        let now = Instant::now();
        let t_ms = dur_ms(now.duration_since(self.t0));
        let gap_ms = t_ms - self.last_emit_at_ms;
        if self.events > 0 {
            if gap_ms < self.min_gap_ms {
                self.min_gap_ms = gap_ms;
            }
            if gap_ms > self.max_gap_ms {
                self.max_gap_ms = gap_ms;
            }
        }

        // The frame's own histogram, accumulated over every chunk it covers. A frame
        // forced at a pass boundary carries no current chunk and would otherwise
        // publish 0.0000 bits/byte for sectors that in fact hold a high-entropy
        // pattern — the single most misleading number this instrument could show.
        let entropy = shannon(&self.hist, self.hist_n as usize);
        let esz = self.hist_n.min(u32::MAX as u64) as u32;
        let inst = if gap_ms > 0.0 {
            (self.bytes_done - self.last_emit_bytes) as f64 * 1000.0 / gap_ms
        } else {
            0.0
        };
        let mean = if t_ms > 0.0 {
            self.bytes_done as f64 * 1000.0 / t_ms
        } else {
            0.0
        };

        let p = Progress {
            seq: self.seq,
            t_ms,
            pass,
            passes: self.passes,
            first_sector: self.span_lo,
            sector_count: self.span_hi - self.span_lo,
            bytes_done: self.bytes_done,
            bytes_total: self.bytes_total,
            throughput_bps: mean,
            throughput_inst_bps: inst,
            entropy_sample: entropy,
            entropy_sample_bytes: esz,
            head_sector: self.head_sector,
            head_len: self.head_len,
            head: self.head,
            coalesced: 0,
        };
        self.sink.emit(&Event::Progress(p));

        self.seq += 1;
        self.events += 1;
        self.have_span = false;
        self.hist = [0u64; 256];
        self.hist_n = 0;
        self.last_emit = now;
        self.last_emit_at_ms = t_ms;
        self.last_emit_bytes = self.bytes_done;
    }

    /// Emit any pending coverage, then the [`End`], then flush the sink.
    ///
    /// `outcome` is `complete`, or `aborted:<reason>` — the caller's words, carried
    /// verbatim to the certificate writer.
    pub fn finish(mut self, outcome: &str) -> Summary {
        if self.have_span {
            self.emit_now(self.cur_pass);
        }
        let wall_ms = dur_ms(self.t0.elapsed());
        let mean = if wall_ms > 0.0 {
            self.bytes_done as f64 * 1000.0 / wall_ms
        } else {
            0.0
        };
        let achieved_hz = if wall_ms > 0.0 {
            self.events as f64 * 1000.0 / wall_ms
        } else {
            0.0
        };
        let min_gap = if self.min_gap_ms.is_finite() {
            self.min_gap_ms
        } else {
            0.0
        };
        let end = End {
            seq: self.seq,
            t_ms: wall_ms,
            bytes_done: self.bytes_done,
            bytes_total: self.bytes_total,
            events: self.events,
            wall_ms,
            mean_throughput_bps: mean,
            achieved_hz,
            max_gap_ms: self.max_gap_ms,
            outcome: outcome.to_string(),
        };
        self.sink.emit(&Event::End(end));
        self.sink.flush();
        self.finished = true;

        Summary {
            events: self.events,
            wall_ms,
            bytes_done: self.bytes_done,
            mean_throughput_bps: mean,
            achieved_hz,
            min_gap_ms: min_gap,
            max_gap_ms: self.max_gap_ms,
            met_rate_floor: self.events < 2 || self.max_gap_ms <= 1000.0 / MIN_RATE_HZ,
        }
    }

    /// Total sectors, as declared in the header. Handy for a caller sanity check.
    pub fn total_sectors(&self) -> u64 {
        self.total_sectors
    }
    pub fn bytes_done(&self) -> u64 {
        self.bytes_done
    }
    /// Borrow the sink, e.g. to read [`ChannelSink::coalesced_total`] mid-run.
    pub fn sink(&self) -> &S {
        &self.sink
    }
}

fn dur_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

// ---------------------------------------------------------------------------
// JSON Lines: writing
// ---------------------------------------------------------------------------

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_into(bytes: &[u8], out: &mut String) {
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
}

fn esc_into(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// JSON has no NaN and no Infinity. A non-finite throughput is a division artifact,
/// not a measurement, and is written as 0 rather than as a token no parser accepts.
fn f(v: f64, places: usize) -> String {
    if !v.is_finite() {
        return "0".to_string();
    }
    format!("{:.*}", places, v)
}

/// Serialise one event as a JSON Lines record, newline included.
pub fn to_json_line(ev: &Event) -> String {
    let mut s = String::with_capacity(1024);
    match ev {
        Event::Header(h) => {
            s.push_str("{\"ev\":\"header\",\"schema\":");
            esc_into(&h.schema, &mut s);
            s.push_str(",\"device\":");
            esc_into(&h.device, &mut s);
            s.push_str(&format!(",\"sector_size\":{}", h.sector_size));
            s.push_str(&format!(",\"total_sectors\":{}", h.total_sectors));
            s.push_str(",\"method\":");
            esc_into(&h.method, &mut s);
            s.push_str(&format!(",\"simulated\":{}", h.simulated));
            s.push_str(&format!(",\"passes\":{}", h.passes));
            s.push_str(",\"pattern_seed_hex\":");
            esc_into(&h.pattern_seed_hex, &mut s);
            s.push_str(&format!(",\"started_unix_ms\":{}", h.started_unix_ms));
            s.push_str(&format!(",\"period_ms\":{}", h.period_ms));
            s.push('}');
        }
        Event::Progress(p) => {
            s.push_str("{\"ev\":\"progress\"");
            s.push_str(&format!(",\"seq\":{}", p.seq));
            s.push_str(&format!(",\"t_ms\":{}", f(p.t_ms, 3)));
            s.push_str(&format!(",\"pass\":{}", p.pass));
            s.push_str(&format!(",\"passes\":{}", p.passes));
            s.push_str(&format!(",\"first_sector\":{}", p.first_sector));
            s.push_str(&format!(",\"sector_count\":{}", p.sector_count));
            s.push_str(&format!(",\"bytes_done\":{}", p.bytes_done));
            s.push_str(&format!(",\"bytes_total\":{}", p.bytes_total));
            s.push_str(&format!(",\"throughput_bps\":{}", f(p.throughput_bps, 1)));
            s.push_str(&format!(
                ",\"throughput_inst_bps\":{}",
                f(p.throughput_inst_bps, 1)
            ));
            s.push_str(&format!(",\"entropy_sample\":{}", f(p.entropy_sample, 4)));
            s.push_str(&format!(
                ",\"entropy_sample_bytes\":{}",
                p.entropy_sample_bytes
            ));
            s.push_str(&format!(",\"head_sector\":{}", p.head_sector));
            s.push_str(&format!(",\"coalesced\":{}", p.coalesced));
            s.push_str(",\"head_hex\":\"");
            hex_into(p.head_bytes(), &mut s);
            s.push_str("\"}");
        }
        Event::End(e) => {
            s.push_str("{\"ev\":\"end\"");
            s.push_str(&format!(",\"seq\":{}", e.seq));
            s.push_str(&format!(",\"t_ms\":{}", f(e.t_ms, 3)));
            s.push_str(&format!(",\"bytes_done\":{}", e.bytes_done));
            s.push_str(&format!(",\"bytes_total\":{}", e.bytes_total));
            s.push_str(&format!(",\"events\":{}", e.events));
            s.push_str(&format!(",\"wall_ms\":{}", f(e.wall_ms, 3)));
            s.push_str(&format!(
                ",\"mean_throughput_bps\":{}",
                f(e.mean_throughput_bps, 1)
            ));
            s.push_str(&format!(",\"achieved_hz\":{}", f(e.achieved_hz, 3)));
            s.push_str(&format!(",\"max_gap_ms\":{}", f(e.max_gap_ms, 3)));
            s.push_str(",\"outcome\":");
            esc_into(&e.outcome, &mut s);
            s.push('}');
        }
    }
    s.push('\n');
    s
}

// ---------------------------------------------------------------------------
// JSON Lines: reading (replay)
// ---------------------------------------------------------------------------

/// Why a trace line could not be read. Always names the field, because a trace is
/// read at demo time when nobody is going to debug a parser.
#[derive(Debug, Clone, PartialEq)]
pub enum TraceError {
    /// (line number, message)
    Syntax(u64, String),
    /// (line number, field name)
    MissingField(u64, String),
    /// (line number, field name, what was there)
    BadType(u64, String, String),
    /// (line number, the `ev` value)
    UnknownEvent(u64, String),
    /// The trace did not open with a header.
    NoHeader,
    /// The schema string in the header is not one this build reads.
    SchemaMismatch(String),
    Io(String),
}

impl fmt::Display for TraceError {
    fn fmt(&self, fo: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceError::Syntax(l, m) => write!(fo, "trace line {}: {}", l, m),
            TraceError::MissingField(l, k) => {
                write!(fo, "trace line {}: missing field `{}`", l, k)
            }
            TraceError::BadType(l, k, v) => {
                write!(fo, "trace line {}: field `{}` is not the expected type: {}", l, k, v)
            }
            TraceError::UnknownEvent(l, e) => write!(fo, "trace line {}: unknown ev `{}`", l, e),
            TraceError::NoHeader => write!(fo, "trace has no header record"),
            TraceError::SchemaMismatch(s) => {
                write!(fo, "trace schema `{}`, this build reads `{}`", s, SCHEMA)
            }
            TraceError::Io(e) => write!(fo, "trace io: {}", e),
        }
    }
}

impl std::error::Error for TraceError {}

#[derive(Debug, Clone, PartialEq)]
enum Val {
    Str(String),
    Num(f64),
    Bool(bool),
}

/// Strict reader for the flat objects this module writes. Deliberately not a general
/// JSON parser: the format has no nesting and no arrays, so a general parser would be
/// a hundred lines of capability nobody uses. Unknown keys are ignored, so a later
/// schema can add a field without breaking an older replayer.
fn parse_flat(line: &str, lineno: u64) -> Result<Vec<(String, Val)>, TraceError> {
    let b: Vec<char> = line.chars().collect();
    let mut i = 0usize;
    let syn = |m: &str| TraceError::Syntax(lineno, m.to_string());

    let skip_ws = |i: &mut usize| {
        while *i < b.len() && (b[*i] == ' ' || b[*i] == '\t' || b[*i] == '\r' || b[*i] == '\n') {
            *i += 1;
        }
    };

    skip_ws(&mut i);
    if i >= b.len() || b[i] != '{' {
        return Err(syn("expected `{`"));
    }
    i += 1;

    let read_string = |i: &mut usize| -> Result<String, TraceError> {
        if *i >= b.len() || b[*i] != '"' {
            return Err(TraceError::Syntax(lineno, "expected a string".into()));
        }
        *i += 1;
        let mut out = String::new();
        loop {
            if *i >= b.len() {
                return Err(TraceError::Syntax(lineno, "unterminated string".into()));
            }
            let c = b[*i];
            *i += 1;
            match c {
                '"' => return Ok(out),
                '\\' => {
                    if *i >= b.len() {
                        return Err(TraceError::Syntax(lineno, "dangling escape".into()));
                    }
                    let e = b[*i];
                    *i += 1;
                    match e {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'b' => out.push('\u{8}'),
                        'f' => out.push('\u{c}'),
                        'u' => {
                            if *i + 4 > b.len() {
                                return Err(TraceError::Syntax(lineno, "short \\u escape".into()));
                            }
                            let h: String = b[*i..*i + 4].iter().collect();
                            *i += 4;
                            let cp = u32::from_str_radix(&h, 16)
                                .map_err(|_| TraceError::Syntax(lineno, "bad \\u escape".into()))?;
                            out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err(TraceError::Syntax(lineno, "unknown escape".into())),
                    }
                }
                c => out.push(c),
            }
        }
    };

    let mut out: Vec<(String, Val)> = Vec::with_capacity(20);
    skip_ws(&mut i);
    if i < b.len() && b[i] == '}' {
        return Ok(out);
    }
    loop {
        skip_ws(&mut i);
        let key = read_string(&mut i)?;
        skip_ws(&mut i);
        if i >= b.len() || b[i] != ':' {
            return Err(syn("expected `:`"));
        }
        i += 1;
        skip_ws(&mut i);
        if i >= b.len() {
            return Err(syn("expected a value"));
        }
        let v = match b[i] {
            '"' => Val::Str(read_string(&mut i)?),
            't' | 'f' => {
                let rest: String = b[i..].iter().take(5).collect();
                if rest.starts_with("true") {
                    i += 4;
                    Val::Bool(true)
                } else if rest.starts_with("false") {
                    i += 5;
                    Val::Bool(false)
                } else {
                    return Err(syn("expected true or false"));
                }
            }
            'n' => {
                let rest: String = b[i..].iter().take(4).collect();
                if rest == "null" {
                    i += 4;
                    Val::Num(0.0)
                } else {
                    return Err(syn("expected null"));
                }
            }
            _ => {
                let start = i;
                while i < b.len()
                    && (b[i].is_ascii_digit()
                        || b[i] == '-'
                        || b[i] == '+'
                        || b[i] == '.'
                        || b[i] == 'e'
                        || b[i] == 'E')
                {
                    i += 1;
                }
                if i == start {
                    return Err(syn("expected a value"));
                }
                let t: String = b[start..i].iter().collect();
                Val::Num(
                    t.parse::<f64>()
                        .map_err(|_| TraceError::Syntax(lineno, format!("bad number `{}`", t)))?,
                )
            }
        };
        out.push((key, v));
        skip_ws(&mut i);
        if i < b.len() && b[i] == ',' {
            i += 1;
            continue;
        }
        if i < b.len() && b[i] == '}' {
            return Ok(out);
        }
        return Err(syn("expected `,` or `}`"));
    }
}

fn get<'a>(kv: &'a [(String, Val)], k: &str) -> Option<&'a Val> {
    kv.iter().find(|(n, _)| n == k).map(|(_, v)| v)
}

fn need_num(kv: &[(String, Val)], k: &str, l: u64) -> Result<f64, TraceError> {
    match get(kv, k) {
        Some(Val::Num(n)) => Ok(*n),
        Some(v) => Err(TraceError::BadType(l, k.into(), format!("{:?}", v))),
        None => Err(TraceError::MissingField(l, k.into())),
    }
}

fn need_str(kv: &[(String, Val)], k: &str, l: u64) -> Result<String, TraceError> {
    match get(kv, k) {
        Some(Val::Str(s)) => Ok(s.clone()),
        Some(v) => Err(TraceError::BadType(l, k.into(), format!("{:?}", v))),
        None => Err(TraceError::MissingField(l, k.into())),
    }
}

fn need_bool(kv: &[(String, Val)], k: &str, l: u64) -> Result<bool, TraceError> {
    match get(kv, k) {
        Some(Val::Bool(b)) => Ok(*b),
        Some(v) => Err(TraceError::BadType(l, k.into(), format!("{:?}", v))),
        None => Err(TraceError::MissingField(l, k.into())),
    }
}

fn unhex(s: &str, l: u64) -> Result<(usize, [u8; HEAD_BYTES]), TraceError> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(TraceError::BadType(
            l,
            "head_hex".into(),
            "odd number of hex digits".into(),
        ));
    }
    let n = (bytes.len() / 2).min(HEAD_BYTES);
    let mut out = [0u8; HEAD_BYTES];
    for i in 0..n {
        let hi = (bytes[2 * i] as char).to_digit(16);
        let lo = (bytes[2 * i + 1] as char).to_digit(16);
        match (hi, lo) {
            (Some(h), Some(x)) => out[i] = ((h << 4) | x) as u8,
            _ => {
                return Err(TraceError::BadType(
                    l,
                    "head_hex".into(),
                    "non-hex digit".into(),
                ))
            }
        }
    }
    Ok((n, out))
}

/// Parse one JSON Lines record.
pub fn from_json_line(line: &str, lineno: u64) -> Result<Event, TraceError> {
    let kv = parse_flat(line, lineno)?;
    let ev = need_str(&kv, "ev", lineno)?;
    match ev.as_str() {
        "header" => Ok(Event::Header(Header {
            schema: need_str(&kv, "schema", lineno)?,
            device: need_str(&kv, "device", lineno)?,
            sector_size: need_num(&kv, "sector_size", lineno)? as u32,
            total_sectors: need_num(&kv, "total_sectors", lineno)? as u64,
            method: need_str(&kv, "method", lineno)?,
            simulated: need_bool(&kv, "simulated", lineno)?,
            passes: need_num(&kv, "passes", lineno)? as u32,
            pattern_seed_hex: need_str(&kv, "pattern_seed_hex", lineno)?,
            started_unix_ms: need_num(&kv, "started_unix_ms", lineno)? as u128,
            period_ms: need_num(&kv, "period_ms", lineno)? as u64,
        })),
        "progress" => {
            // Fields are read in wire order so a truncated line names the first
            // field it is actually missing, not whichever the compiler evaluated.
            let mut pr = Progress {
                seq: need_num(&kv, "seq", lineno)? as u64,
                t_ms: need_num(&kv, "t_ms", lineno)?,
                pass: need_num(&kv, "pass", lineno)? as u32,
                passes: need_num(&kv, "passes", lineno)? as u32,
                first_sector: need_num(&kv, "first_sector", lineno)? as u64,
                sector_count: need_num(&kv, "sector_count", lineno)? as u64,
                bytes_done: need_num(&kv, "bytes_done", lineno)? as u64,
                bytes_total: need_num(&kv, "bytes_total", lineno)? as u64,
                throughput_bps: need_num(&kv, "throughput_bps", lineno)?,
                throughput_inst_bps: need_num(&kv, "throughput_inst_bps", lineno)?,
                entropy_sample: need_num(&kv, "entropy_sample", lineno)?,
                entropy_sample_bytes: need_num(&kv, "entropy_sample_bytes", lineno)? as u32,
                head_sector: need_num(&kv, "head_sector", lineno)? as u64,
                coalesced: need_num(&kv, "coalesced", lineno)? as u32,
                head_len: 0,
                head: [0u8; HEAD_BYTES],
            };
            let (n, head) = unhex(&need_str(&kv, "head_hex", lineno)?, lineno)?;
            pr.head_len = n as u16;
            pr.head = head;
            Ok(Event::Progress(pr))
        }
        "end" => Ok(Event::End(End {
            seq: need_num(&kv, "seq", lineno)? as u64,
            t_ms: need_num(&kv, "t_ms", lineno)?,
            bytes_done: need_num(&kv, "bytes_done", lineno)? as u64,
            bytes_total: need_num(&kv, "bytes_total", lineno)? as u64,
            events: need_num(&kv, "events", lineno)? as u64,
            wall_ms: need_num(&kv, "wall_ms", lineno)?,
            mean_throughput_bps: need_num(&kv, "mean_throughput_bps", lineno)?,
            achieved_hz: need_num(&kv, "achieved_hz", lineno)?,
            max_gap_ms: need_num(&kv, "max_gap_ms", lineno)?,
            outcome: need_str(&kv, "outcome", lineno)?,
        })),
        other => Err(TraceError::UnknownEvent(lineno, other.to_string())),
    }
}

/// Streaming reader over a JSON Lines trace. Blank lines are skipped.
pub struct TraceReader<R: BufRead> {
    r: R,
    lineno: u64,
}

impl<R: BufRead> TraceReader<R> {
    pub fn new(r: R) -> Self {
        TraceReader { r, lineno: 0 }
    }
}

impl<R: BufRead> Iterator for TraceReader<R> {
    type Item = Result<Event, TraceError>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let mut line = String::new();
            match self.r.read_line(&mut line) {
                Ok(0) => return None,
                Ok(_) => {
                    self.lineno += 1;
                    if line.trim().is_empty() {
                        continue;
                    }
                    return Some(from_json_line(line.trim(), self.lineno));
                }
                Err(e) => return Some(Err(TraceError::Io(e.to_string()))),
            }
        }
    }
}

/// A whole trace, in memory. A 256 MiB wipe's trace is a few hundred kilobytes, so
/// the demo loads it whole rather than streaming it.
#[derive(Debug, Clone, PartialEq)]
pub struct Trace {
    pub header: Header,
    pub progress: Vec<Progress>,
    pub end: Option<End>,
}

impl Trace {
    pub fn read<R: BufRead>(r: R) -> Result<Trace, TraceError> {
        let mut header: Option<Header> = None;
        let mut progress = Vec::new();
        let mut end = None;
        for ev in TraceReader::new(r) {
            match ev? {
                Event::Header(h) => {
                    if h.schema != SCHEMA {
                        return Err(TraceError::SchemaMismatch(h.schema));
                    }
                    header = Some(h);
                }
                Event::Progress(p) => progress.push(p),
                Event::End(e) => end = Some(e),
            }
        }
        match header {
            Some(h) => Ok(Trace {
                header: h,
                progress,
                end,
            }),
            None => Err(TraceError::NoHeader),
        }
    }

    /// Duration the recorded run took, in ms, from the last event's timestamp.
    pub fn duration_ms(&self) -> f64 {
        self.end
            .as_ref()
            .map(|e| e.t_ms)
            .or_else(|| self.progress.last().map(|p| p.t_ms))
            .unwrap_or(0.0)
    }

    /// Event rate the recording actually achieved.
    pub fn achieved_hz(&self) -> f64 {
        let d = self.duration_ms();
        if d > 0.0 {
            self.progress.len() as f64 * 1000.0 / d
        } else {
            0.0
        }
    }

    /// Largest gap between consecutive progress frames, in ms.
    pub fn max_gap_ms(&self) -> f64 {
        let mut prev = 0.0f64;
        let mut max = 0.0f64;
        for p in &self.progress {
            let g = p.t_ms - prev;
            if g > max {
                max = g;
            }
            prev = p.t_ms;
        }
        max
    }

    /// **The invariant that makes lossy backpressure safe.**
    ///
    /// Returns every `(pass, first_sector, sector_count)` region of the medium that
    /// no delivered frame claimed. An empty result means the sector map was painted
    /// completely: no consumer, however slow, left a region of the canvas showing
    /// untouched when it had in fact been overwritten.
    ///
    /// Sectors beyond `header.total_sectors` are ignored; a wipe that overruns the
    /// declared capacity is a device-layer defect, not a telemetry one.
    pub fn coverage_gaps(&self) -> Vec<(u32, u64, u64)> {
        let total = self.header.total_sectors;
        let mut gaps = Vec::new();
        for pass in 1..=self.header.passes.max(1) {
            let mut spans: Vec<(u64, u64)> = self
                .progress
                .iter()
                .filter(|p| p.pass == pass && p.sector_count > 0)
                .map(|p| (p.first_sector, p.sector_end().min(total)))
                .filter(|(a, b)| b > a)
                .collect();
            spans.sort_unstable();
            let mut cursor = 0u64;
            for (a, b) in spans {
                if a > cursor {
                    gaps.push((pass, cursor, a - cursor));
                }
                if b > cursor {
                    cursor = b;
                }
            }
            if cursor < total {
                gaps.push((pass, cursor, total - cursor));
            }
        }
        gaps
    }
}

/// Replay a recorded trace into a sink, pacing on the recorded `t_ms`.
///
/// This is Phase 6's demo path: no device, no engine, no filesystem operation on
/// stage. `speed` is a multiplier — 1.0 for real time, 2.0 for twice as fast, and
/// any non-finite or non-positive value for as-fast-as-possible (what tests use).
///
/// The sink is the same [`EventSink`] the live engine drives, so a replayed run goes
/// through the same coalescing policy as a live one. A demo that bypassed the
/// backpressure path would be a demo of a code path that does not ship.
pub fn replay<S: EventSink>(trace: &Trace, sink: &mut S, speed: f64) -> usize {
    let paced = speed.is_finite() && speed > 0.0;
    let start = Instant::now();
    let mut n = 0usize;
    sink.emit(&Event::Header(trace.header.clone()));
    n += 1;
    for p in &trace.progress {
        if paced {
            let due = Duration::from_secs_f64((p.t_ms / 1000.0 / speed).max(0.0));
            let now = start.elapsed();
            if due > now {
                std::thread::sleep(due - now);
            }
        }
        sink.emit(&Event::Progress(p.clone()));
        n += 1;
    }
    if let Some(e) = &trace.end {
        if paced {
            let due = Duration::from_secs_f64((e.t_ms / 1000.0 / speed).max(0.0));
            let now = start.elapsed();
            if due > now {
                std::thread::sleep(due - now);
            }
        }
        sink.emit(&Event::End(e.clone()));
        n += 1;
    }
    sink.flush();
    n
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A tiny deterministic byte source. Not a wipe pattern — the seeded SHAKE-128
    /// stream is the pattern generator's job and lives in another module. This exists
    /// so entropy tests are reproducible.
    fn pseudo(seed: u64, n: usize) -> Vec<u8> {
        let mut s = seed | 1;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            out.push((s >> 24) as u8);
        }
        out
    }

    fn spec() -> WipeSpec {
        WipeSpec {
            device: "image:/scratch/copy.img".into(),
            sector_size: 512,
            total_sectors: 2048,
            method: "random-seeded-shake128".into(),
            simulated: false,
            passes: 1,
            pattern_seed_hex: "00112233".into(),
        }
    }

    // -- entropy ----------------------------------------------------------

    #[test]
    fn entropy_of_zeroes_is_zero() {
        let (h, n) = entropy_sampled(&[0u8; 4096], 512, ENTROPY_SAMPLE_BYTES);
        assert_eq!(h, 0.0);
        assert_eq!(n, 4096);
    }

    #[test]
    fn entropy_of_a_uniform_byte_sweep_is_exactly_eight() {
        let mut buf = Vec::new();
        for _ in 0..16 {
            for b in 0..=255u8 {
                buf.push(b);
            }
        }
        let (h, n) = entropy_sampled(&buf, 512, ENTROPY_SAMPLE_BYTES);
        assert_eq!(n, 4096);
        assert!((h - 8.0).abs() < 1e-12, "expected 8.0 exactly, got {}", h);
    }

    #[test]
    fn entropy_is_not_a_constant_and_tracks_the_data() {
        let zeros = entropy_sampled(&[0u8; 65536], 512, ENTROPY_SAMPLE_BYTES).0;
        let rand = entropy_sampled(&pseudo(7, 65536), 512, ENTROPY_SAMPLE_BYTES).0;
        let ascii = entropy_sampled(&b"abcdefgh".repeat(8192), 512, ENTROPY_SAMPLE_BYTES).0;
        assert_eq!(zeros, 0.0);
        assert!((ascii - 3.0).abs() < 1e-9, "8 equiprobable symbols is 3 bits, got {}", ascii);
        assert!(rand > 7.9, "pseudo-random should be near 8, got {}", rand);
        assert!(rand < 8.0);
    }

    /// The documented finite-sample bias. If this drifts, the figure in the module
    /// doc and anything a slide quotes drifts with it.
    #[test]
    fn finite_sample_bias_at_the_budget_is_about_three_thousandths_of_a_bit() {
        let (h, n) = entropy_sampled(&pseudo(0xC0FFEE, ENTROPY_SAMPLE_BYTES), 512, ENTROPY_SAMPLE_BYTES);
        assert_eq!(n as usize, ENTROPY_SAMPLE_BYTES);
        let deficit = 8.0 - h;
        let predicted = 255.0 / (2.0 * ENTROPY_SAMPLE_BYTES as f64 * std::f64::consts::LN_2);
        assert!(
            (deficit - predicted).abs() < 0.004,
            "deficit {:.6} vs predicted {:.6}",
            deficit,
            predicted
        );
        assert!(h > 7.99 && h < 8.0, "got {}", h);
    }

    /// The sample must span the chunk, not read its head. A buffer that is zeroes for
    /// its first half and random for its second must not measure as either one.
    #[test]
    fn the_entropy_sample_spans_the_chunk_rather_than_its_head() {
        let mut buf = vec![0u8; 512 * 1024];
        let tail = pseudo(99, 512 * 1024);
        buf.extend_from_slice(&tail);
        let (h, n) = entropy_sampled(&buf, 512, ENTROPY_SAMPLE_BYTES);
        assert_eq!(n as usize, ENTROPY_SAMPLE_BYTES);
        // Half zeroes, half uniform: H = 0.5*log2(2) + 0.5*(log2(512)) ... measured,
        // and the only claim that matters is that it is neither endpoint.
        assert!(h > 1.0, "head-only sampling would read ~0.0, got {}", h);
        assert!(h < 7.0, "tail-only sampling would read ~8.0, got {}", h);
    }

    #[test]
    fn entropy_of_an_empty_buffer_is_zero_and_reports_zero_samples() {
        assert_eq!(entropy_sampled(&[], 512, ENTROPY_SAMPLE_BYTES), (0.0, 0));
        assert_eq!(entropy_sampled(&[1, 2, 3], 512, 0), (0.0, 0));
    }

    // -- operator decision 3 ---------------------------------------------

    #[test]
    fn a_simulated_method_carries_the_word_in_the_field_itself() {
        let mut s = spec();
        s.simulated = true;
        s.method = "ata-secure-erase".into();
        assert_eq!(s.method_label(), "simulated:ata-secure-erase");

        let mut sink = CollectSink::new();
        let tm = Telemetry::start(s, &mut sink, Some(Duration::ZERO));
        drop(tm);
        match &sink.events[0] {
            Event::Header(h) => {
                assert!(h.simulated);
                assert!(h.method.contains("simulated"), "method was `{}`", h.method);
            }
            e => panic!("first event was {:?}", e),
        }
    }

    #[test]
    fn a_method_that_already_says_simulated_is_not_double_prefixed() {
        let mut s = spec();
        s.simulated = true;
        s.method = "nvme-sanitize (simulated on image)".into();
        assert_eq!(s.method_label(), "nvme-sanitize (simulated on image)");
    }

    // -- the producer -----------------------------------------------------

    #[test]
    fn the_header_is_the_first_event_and_declares_the_canvas() {
        let mut sink = CollectSink::new();
        let tm = Telemetry::start(spec(), &mut sink, Some(Duration::ZERO));
        drop(tm);
        match &sink.events[0] {
            Event::Header(h) => {
                assert_eq!(h.schema, SCHEMA);
                assert_eq!(h.total_sectors, 2048);
                assert_eq!(h.sector_size, 512);
                assert_eq!(h.passes, 1);
            }
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn every_written_sector_appears_in_exactly_one_frame() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::ZERO));
        let chunk = vec![0xA5u8; 512 * 64];
        for i in 0..32u64 {
            tm.wrote(1, i * 64, &chunk);
        }
        tm.end_pass(1);
        let s = tm.finish("complete");
        assert_eq!(s.bytes_done, 2048 * 512);
        assert_eq!(s.events, 32);

        let trace = collected_trace(&sink);
        assert_eq!(trace.coverage_gaps(), vec![], "the canvas has an unpainted hole");
        let mut cursor = 0u64;
        for p in &trace.progress {
            assert_eq!(p.first_sector, cursor, "frames must tile, not overlap");
            cursor = p.sector_end();
        }
        assert_eq!(cursor, 2048);
    }

    #[test]
    fn a_frame_carries_the_bytes_under_the_head_for_the_hex_pane() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::ZERO));
        let chunk = pseudo(5, 512 * 8);
        tm.wrote(1, 1024, &chunk);
        tm.finish("complete");
        let p = match &sink.events[1] {
            Event::Progress(p) => p.clone(),
            e => panic!("{:?}", e),
        };
        assert_eq!(p.head_len as usize, HEAD_BYTES);
        assert_eq!(p.head_bytes(), &chunk[..HEAD_BYTES]);
        assert_eq!(p.head_sector, 1024);
    }

    #[test]
    fn a_short_final_chunk_reports_only_the_bytes_it_has() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::ZERO));
        tm.wrote(1, 0, &[0xEEu8; 16]);
        tm.finish("complete");
        match &sink.events[1] {
            Event::Progress(p) => {
                assert_eq!(p.head_len, 16);
                assert_eq!(p.head_bytes(), &[0xEEu8; 16]);
                assert_eq!(p.sector_count, 1, "16 bytes still occupies one sector");
            }
            e => panic!("{:?}", e),
        }
    }

    #[test]
    fn a_pass_change_closes_the_previous_layer_before_the_new_one_opens() {
        let mut s = spec();
        s.passes = 3;
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(s, &mut sink, Some(Duration::from_secs(3600)));
        let chunk = vec![0u8; 512 * 1024];
        for pass in 1..=3u32 {
            tm.wrote(pass, 0, &chunk);
            tm.wrote(pass, 1024, &chunk);
        }
        tm.end_pass(3);
        tm.finish("complete");

        let trace = collected_trace(&sink);
        assert_eq!(trace.progress.len(), 3, "one frame per pass at a 1 h period");
        assert_eq!(
            trace.progress.iter().map(|p| p.pass).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(trace.coverage_gaps(), vec![]);
    }

    /// A frame forced at a pass boundary has no "current" chunk. It must still
    /// publish a real measurement over the sectors it covers. Publishing 0.0000
    /// bits/byte there would be the single most misleading number this instrument
    /// could show, because it is exactly what a zero-fill produces.
    #[test]
    fn a_frame_with_no_current_chunk_still_measures_the_sectors_it_covers() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::from_secs(3600)));
        let chunk = pseudo(21, 512 * 1024);
        tm.wrote(1, 0, &chunk);
        tm.wrote(1, 1024, &chunk);
        tm.end_pass(1); // forced: nothing under the head at this instant
        tm.finish("complete");
        let ps = sink.progress();
        assert_eq!(ps.len(), 1, "one forced frame at a 1 h period");
        let p = ps[0];
        assert!(
            p.entropy_sample > 7.9,
            "forced frame published {:.4} bits/byte for random data",
            p.entropy_sample
        );
        assert_eq!(
            p.entropy_sample_bytes as usize,
            2 * ENTROPY_CHUNK_SAMPLE_BYTES,
            "both chunks of the frame contributed"
        );
        assert_eq!(p.first_sector, 0);
        assert_eq!(p.sector_count, 2048, "and it covers both of them");
    }

    #[test]
    fn a_zero_fill_pass_reports_zero_entropy_truthfully() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::from_secs(3600)));
        tm.wrote(1, 0, &[0u8; 512 * 2048]);
        tm.end_pass(1);
        tm.finish("complete");
        let ps = sink.progress();
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].entropy_sample, 0.0);
        assert_eq!(
            ps[0].entropy_sample_bytes as usize,
            ENTROPY_CHUNK_SAMPLE_BYTES
        );
    }

    /// The histogram must be reset at every frame, or entropy would be a running
    /// average over the whole job and a 3-pass wipe would show pass 1's zeroes
    /// bleeding into pass 3's random.
    #[test]
    fn each_frame_measures_only_its_own_sectors() {
        let mut s = spec();
        s.passes = 3;
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(s, &mut sink, Some(Duration::from_secs(3600)));
        let zeros = vec![0u8; 512 * 2048];
        let ones = vec![0xFFu8; 512 * 2048];
        let rand = pseudo(31, 512 * 2048);
        tm.wrote(1, 0, &zeros);
        tm.wrote(2, 0, &ones);
        tm.wrote(3, 0, &rand);
        tm.end_pass(3);
        tm.finish("complete");
        let ps = sink.progress();
        assert_eq!(ps.len(), 3);
        assert_eq!(ps[0].entropy_sample, 0.0, "zero fill");
        assert_eq!(ps[1].entropy_sample, 0.0, "0xFF fill is also one symbol");
        assert!(ps[2].entropy_sample > 7.9, "random pass: {}", ps[2].entropy_sample);
    }

    #[test]
    fn nothing_written_means_no_empty_frames() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::ZERO));
        tm.end_pass(1);
        tm.tick(1);
        let s = tm.finish("aborted:guard-refused");
        assert_eq!(s.events, 0);
        assert_eq!(sink.events.len(), 2, "header and end only");
        match &sink.events[1] {
            Event::End(e) => assert_eq!(e.outcome, "aborted:guard-refused"),
            e => panic!("{:?}", e),
        }
    }

    /// Real wall-clock: drive a short run at the default period and assert the rate
    /// floor from the stream's own self-measurement.
    #[test]
    fn the_default_period_clears_the_twenty_hertz_floor() {
        let mut s = spec();
        s.total_sectors = 1 << 20;
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(s, &mut sink, None);
        let chunk = vec![0x5Au8; 512 * 32];
        let start = Instant::now();
        let mut sector = 0u64;
        while start.elapsed() < Duration::from_millis(600) {
            tm.wrote(1, sector, &chunk);
            sector += 32;
            std::thread::sleep(Duration::from_millis(2));
        }
        let sum = tm.finish("complete");
        assert!(sum.events >= 10, "only {} events in 600 ms", sum.events);
        assert!(
            sum.achieved_hz >= MIN_RATE_HZ,
            "achieved {:.2} Hz, floor is {}",
            sum.achieved_hz,
            MIN_RATE_HZ
        );
        assert!(
            sum.met_rate_floor,
            "max gap {:.2} ms exceeds the {:.1} ms floor",
            sum.max_gap_ms,
            1000.0 / MIN_RATE_HZ
        );
    }

    // -- backpressure -----------------------------------------------------

    /// Drain a receiver on its own thread, taking `per_event_ms` to "repaint" each
    /// frame, and hand back everything that arrived. This is what a real consumer
    /// looks like; a test that holds a `Receiver` and never reads it is not a slow
    /// consumer, it is a dead one, and the two must be distinguished.
    fn drain_slowly(rx: Receiver<Event>, per_event_ms: u64) -> std::thread::JoinHandle<Vec<Event>> {
        std::thread::spawn(move || {
            let mut got = Vec::new();
            for ev in rx.iter() {
                if per_event_ms > 0 {
                    std::thread::sleep(Duration::from_millis(per_event_ms));
                }
                got.push(ev);
            }
            got
        })
    }

    fn trace_of(events: &[Event]) -> Trace {
        let mut buf = Vec::new();
        for e in events {
            buf.extend_from_slice(to_json_line(e).as_bytes());
        }
        Trace::read(Cursor::new(buf)).expect("events must parse")
    }

    fn collected_trace(sink: &CollectSink) -> Trace {
        let mut buf = Vec::new();
        for e in &sink.events {
            buf.extend_from_slice(to_json_line(e).as_bytes());
        }
        Trace::read(Cursor::new(buf)).expect("collected events must parse")
    }

    #[test]
    fn a_slow_consumer_loses_frames_but_never_loses_coverage() {
        let (sink, rx) = channel(2);
        let consumer = drain_slowly(rx, 2);
        let mut tm = Telemetry::start(spec(), sink, Some(Duration::ZERO));
        let chunk = vec![0x11u8; 512 * 16];
        // 128 frames as fast as the loop can emit them, against a consumer that
        // takes 2 ms each. The queue fills; frames merge rather than disappear.
        for i in 0..128u64 {
            tm.wrote(1, i * 16, &chunk);
        }
        let sum = tm.finish("complete");
        assert_eq!(sum.events, 128, "the producer emitted every frame");
        let got = consumer.join().unwrap();

        let trace = trace_of(&got);
        assert!(
            trace.progress.len() < 128,
            "expected coalescing, delivered {} of 128",
            trace.progress.len()
        );
        assert!(!trace.progress.is_empty());
        assert_eq!(
            trace.coverage_gaps(),
            vec![],
            "a coalesced stream still painted the whole canvas"
        );
        assert!(
            trace.progress.iter().any(|p| p.coalesced > 0),
            "coalesced frames must say so"
        );
        let merged: u32 = trace.progress.iter().map(|p| p.coalesced).sum();
        assert_eq!(
            merged as usize + trace.progress.len(),
            128,
            "every emitted frame is either delivered or accounted for in `coalesced`"
        );
        assert!(trace.end.is_some(), "the end event is never coalesced away");
    }

    /// **The deadlock this module had.** A consumer that holds its `Receiver` and
    /// stops reading is not disconnected, so every "is it still there?" check says
    /// yes — and an unbounded `send` of the terminal event then waits forever, with
    /// a half-finished destructive operation behind it. The wipe must complete.
    ///
    /// Written so it cannot hang the suite: the wipe runs on its own thread and this
    /// one waits on a bounded `recv_timeout`.
    #[test]
    fn a_consumer_that_stops_reading_cannot_hang_the_wipe() {
        let (sink, rx) = channel(2);
        let (done_tx, done_rx) = std::sync::mpsc::channel::<Summary>();
        let worker = std::thread::spawn(move || {
            let mut tm = Telemetry::start(spec(), sink, Some(Duration::ZERO));
            let chunk = vec![0x22u8; 512 * 64];
            for i in 0..32u64 {
                tm.wrote(1, i * 64, &chunk);
            }
            let s = tm.finish("complete");
            let _ = done_tx.send(s);
        });
        // `rx` is alive and never read: the queue is full and stays full.
        let s = done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("finish() blocked on a stalled consumer: the wipe cannot complete");
        assert_eq!(s.bytes_done, 2048 * 512, "the whole medium was still written");
        worker.join().unwrap();
        drop(rx);
    }

    #[test]
    fn a_merged_frame_keeps_the_newest_head_and_the_widest_range() {
        let mut a = Progress::blank();
        a.first_sector = 100;
        a.sector_count = 50;
        a.head[0] = 0xAA;
        a.head_len = 1;
        a.bytes_done = 1000;
        let mut b = Progress::blank();
        b.first_sector = 150;
        b.sector_count = 25;
        b.head[0] = 0xBB;
        b.head_len = 1;
        b.bytes_done = 2000;
        b.seq = 1;

        let m = merge_progress(a, b);
        assert_eq!(m.first_sector, 100);
        assert_eq!(m.sector_count, 75);
        assert_eq!(m.head_bytes(), &[0xBB]);
        assert_eq!(m.bytes_done, 2000);
        assert_eq!(m.seq, 1);
        assert_eq!(m.coalesced, 1);
    }

    #[test]
    fn a_closed_instrument_cannot_stall_or_fail_a_wipe() {
        let (sink, rx) = channel(1);
        drop(rx);
        let mut tm = Telemetry::start(spec(), sink, Some(Duration::ZERO));
        let chunk = vec![0u8; 512 * 64];
        for i in 0..32u64 {
            tm.wrote(1, i * 64, &chunk);
        }
        assert!(tm.sink().disconnected());
        let s = tm.finish("complete");
        assert_eq!(s.bytes_done, 2048 * 512, "the wipe still completed");
    }

    #[test]
    fn a_pass_boundary_is_never_merged_across() {
        let mut s = spec();
        s.passes = 2;
        s.total_sectors = 64;
        let (sink, rx) = channel(1);
        let consumer = drain_slowly(rx, 1);
        let mut tm = Telemetry::start(s, sink, Some(Duration::ZERO));
        let chunk = vec![0u8; 512 * 8];
        for pass in 1..=2u32 {
            for i in 0..8u64 {
                tm.wrote(pass, i * 8, &chunk);
            }
        }
        tm.end_pass(2);
        tm.finish("complete");
        let trace = trace_of(&consumer.join().unwrap());
        assert!(trace.progress.iter().any(|p| p.pass == 1));
        assert!(trace.progress.iter().any(|p| p.pass == 2));
        assert!(
            trace.progress.iter().all(|p| p.sector_end() <= 64),
            "a union across passes would have produced an impossible range"
        );
        assert_eq!(trace.coverage_gaps(), vec![], "both layers painted whole");
    }

    // -- the recorder and the wire format ---------------------------------

    #[test]
    fn every_event_round_trips_through_the_wire_format() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::ZERO));
        let chunk = pseudo(3, 512 * 64);
        for i in 0..32u64 {
            tm.wrote(1, i * 64, &chunk);
        }
        tm.finish("complete");

        for e in &sink.events {
            let line = to_json_line(e);
            let back = from_json_line(line.trim(), 1).expect("must parse");
            assert_eq!(
                to_json_line(&back),
                line,
                "re-serialising a parsed event must be byte-identical"
            );
        }
        // head bytes survive exactly
        match (&sink.events[1], from_json_line(to_json_line(&sink.events[1]).trim(), 1).unwrap()) {
            (Event::Progress(a), Event::Progress(b)) => {
                assert_eq!(a.head_bytes(), b.head_bytes());
                assert_eq!(a.head_len, b.head_len);
            }
            _ => panic!("expected progress"),
        }
    }

    #[test]
    fn the_recorder_writes_one_line_per_event() {
        let mut fan = FanoutSink::new();
        let rec = RecorderSink::new(Vec::<u8>::new());
        fan.push(Box::new(rec));
        fan.push(Box::new(NullSink));
        assert_eq!(fan.len(), 2);

        let mut collect = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut collect, Some(Duration::ZERO));
        tm.wrote(1, 0, &[0u8; 4096]);
        tm.finish("complete");

        let mut buf = Vec::new();
        {
            let mut rec = RecorderSink::new(&mut buf);
            for e in &collect.events {
                rec.emit(e);
            }
            rec.flush();
            assert_eq!(rec.lines_written(), 3);
            assert!(rec.error().is_none());
        }
        assert_eq!(buf.iter().filter(|&&b| b == b'\n').count(), 3);
        let trace = Trace::read(Cursor::new(buf)).unwrap();
        assert_eq!(trace.progress.len(), 1);
        assert!(trace.end.is_some());
    }

    #[test]
    fn a_recorder_io_error_is_captured_and_never_aborts_the_wipe() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _b: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::StorageFull, "no space"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut tm = Telemetry::start(spec(), RecorderSink::new(Broken), Some(Duration::ZERO));
        tm.wrote(1, 0, &[0u8; 4096]);
        let s = tm.finish("complete");
        assert_eq!(s.bytes_done, 4096, "the wipe still completed");
    }

    #[test]
    fn non_finite_numbers_never_reach_the_wire() {
        let mut p = Progress::blank();
        p.throughput_bps = f64::INFINITY;
        p.throughput_inst_bps = f64::NAN;
        p.entropy_sample = f64::NEG_INFINITY;
        let line = to_json_line(&Event::Progress(p));
        assert!(!line.contains("inf") && !line.contains("NaN"), "{}", line);
        let back = from_json_line(line.trim(), 1).unwrap();
        match back {
            Event::Progress(q) => {
                assert_eq!(q.throughput_bps, 0.0);
                assert_eq!(q.throughput_inst_bps, 0.0);
                assert_eq!(q.entropy_sample, 0.0);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn a_device_name_with_quotes_and_control_bytes_survives() {
        let mut s = spec();
        s.device = "image:/a \"weird\"\\path\twith\nnewline".into();
        let mut sink = CollectSink::new();
        let tm = Telemetry::start(s.clone(), &mut sink, Some(Duration::ZERO));
        drop(tm);
        let line = to_json_line(&sink.events[0]);
        match from_json_line(line.trim(), 1).unwrap() {
            Event::Header(h) => assert_eq!(h.device, s.device),
            _ => panic!(),
        }
    }

    #[test]
    fn a_malformed_line_names_the_field_it_could_not_read() {
        let e = from_json_line(r#"{"ev":"progress","seq":1}"#, 42).unwrap_err();
        match &e {
            TraceError::MissingField(l, k) => {
                assert_eq!(*l, 42);
                assert_eq!(k, "t_ms");
            }
            other => panic!("{:?}", other),
        }
        assert!(e.to_string().contains("t_ms"), "{}", e);

        assert!(matches!(
            from_json_line("not json", 1),
            Err(TraceError::Syntax(1, _))
        ));
        assert!(matches!(
            from_json_line(r#"{"ev":"sideways"}"#, 1),
            Err(TraceError::UnknownEvent(1, _))
        ));
        assert!(matches!(
            from_json_line(r#"{"ev":"header","schema":7}"#, 1),
            Err(TraceError::BadType(1, _, _))
        ));
    }

    #[test]
    fn an_unknown_field_does_not_break_an_older_replayer() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::ZERO));
        tm.wrote(1, 0, &[0u8; 512]);
        tm.finish("complete");
        let line = to_json_line(&sink.events[1]);
        let widened = line.trim().replacen('{', r#"{"future_field":123,"#, 1);
        assert!(from_json_line(&widened, 1).is_ok());
    }

    #[test]
    fn a_trace_with_no_header_is_refused_and_a_foreign_schema_is_named() {
        let body = r#"{"ev":"end","seq":0,"t_ms":0,"bytes_done":0,"bytes_total":0,"events":0,"wall_ms":0,"mean_throughput_bps":0,"achieved_hz":0,"max_gap_ms":0,"outcome":"complete"}"#;
        assert_eq!(
            Trace::read(Cursor::new(body)).unwrap_err(),
            TraceError::NoHeader
        );
        let hdr = r#"{"ev":"header","schema":"someone.else/9","device":"d","sector_size":512,"total_sectors":1,"method":"m","simulated":false,"passes":1,"pattern_seed_hex":"","started_unix_ms":0,"period_ms":40}"#;
        assert!(matches!(
            Trace::read(Cursor::new(hdr)),
            Err(TraceError::SchemaMismatch(_))
        ));
    }

    #[test]
    fn blank_lines_in_a_trace_are_skipped() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::ZERO));
        tm.wrote(1, 0, &[0u8; 512 * 2048]);
        tm.finish("complete");
        let mut text = String::new();
        for e in &sink.events {
            text.push_str(&to_json_line(e));
            text.push('\n');
        }
        let t = Trace::read(Cursor::new(text)).unwrap();
        assert_eq!(t.progress.len(), 1);
    }

    // -- coverage_gaps, the guard on the guard -----------------------------

    #[test]
    fn coverage_gaps_finds_a_real_hole() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::ZERO));
        // Deliberately skip sectors 512..1024.
        tm.wrote(1, 0, &[0u8; 512 * 512]);
        tm.wrote(1, 1024, &[0u8; 512 * 1024]);
        tm.finish("complete");
        let t = collected_trace(&sink);
        assert_eq!(t.coverage_gaps(), vec![(1, 512, 512)]);
    }

    #[test]
    fn coverage_gaps_reports_an_unfinished_run_as_a_tail_gap() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::ZERO));
        tm.wrote(1, 0, &[0u8; 512 * 100]);
        tm.finish("aborted:power");
        let t = collected_trace(&sink);
        assert_eq!(t.coverage_gaps(), vec![(1, 100, 1948)]);
    }

    // -- replay ------------------------------------------------------------

    #[test]
    fn a_recorded_trace_replays_with_no_engine_attached() {
        // Record.
        let mut buf = Vec::new();
        {
            let rec = RecorderSink::new(&mut buf);
            let mut tm = Telemetry::start(spec(), rec, Some(Duration::ZERO));
            let chunk = pseudo(11, 512 * 128);
            for i in 0..16u64 {
                tm.wrote(1, i * 128, &chunk);
            }
            tm.end_pass(1);
            tm.finish("complete");
        }
        let recorded_bytes = buf.len();
        let trace = Trace::read(Cursor::new(buf)).unwrap();
        assert_eq!(trace.progress.len(), 16);
        assert_eq!(trace.coverage_gaps(), vec![]);
        assert!(recorded_bytes > 0);

        // Replay, fast, through the same sink type the live engine drives.
        let mut out = CollectSink::new();
        let n = replay(&trace, &mut out, f64::INFINITY);
        assert_eq!(n, 18, "header + 16 frames + end");
        assert_eq!(out.events.len(), 18);
        assert_eq!(out.flushes, 1);
        match (&out.events[0], &out.events[17]) {
            (Event::Header(h), Event::End(e)) => {
                assert_eq!(h.total_sectors, 2048);
                assert_eq!(e.outcome, "complete");
            }
            _ => panic!("replay must open with a header and close with an end"),
        }
        // The replayed stream is the recorded stream, event for event.
        let mut rebuilt = Vec::new();
        for e in &out.events {
            rebuilt.extend_from_slice(to_json_line(e).as_bytes());
        }
        let round = Trace::read(Cursor::new(rebuilt)).unwrap();
        assert_eq!(round.progress, trace.progress);
    }

    #[test]
    fn a_paced_replay_honours_the_recorded_timeline() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::ZERO));
        for i in 0..4u64 {
            tm.wrote(1, i * 512, &[0u8; 512 * 512]);
            std::thread::sleep(Duration::from_millis(25));
        }
        tm.finish("complete");
        let trace = collected_trace(&sink);
        let recorded = trace.duration_ms();
        assert!(recorded >= 75.0, "recorded only {:.1} ms", recorded);

        // 10x speed: must take roughly a tenth of the recorded span, and never longer.
        let mut out = CollectSink::new();
        let t = Instant::now();
        replay(&trace, &mut out, 10.0);
        let elapsed = dur_ms(t.elapsed());
        assert!(
            elapsed < recorded,
            "10x replay took {:.1} ms for a {:.1} ms recording",
            elapsed,
            recorded
        );
        assert!(elapsed >= recorded / 10.0 - 5.0, "replay outran the timeline");
    }

    #[test]
    fn replay_drives_the_live_backpressure_path_too() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::ZERO));
        let chunk = vec![0u8; 512 * 8];
        for i in 0..256u64 {
            tm.wrote(1, i * 8, &chunk);
        }
        tm.finish("complete");
        let trace = collected_trace(&sink);

        let (mut cs, rx) = channel(2);
        let consumer = drain_slowly(rx, 1);
        replay(&trace, &mut cs, f64::INFINITY);
        drop(cs);
        let seen = trace_of(&consumer.join().unwrap());
        assert!(
            seen.progress.len() < trace.progress.len(),
            "coalescing applied on replay too"
        );
        assert_eq!(seen.coverage_gaps(), vec![], "and the canvas is still whole");
    }

    // -- event size, so the figure in the build report is measured ----------

    #[test]
    fn the_wire_size_of_a_frame_is_what_the_build_report_says() {
        let mut sink = CollectSink::new();
        let mut tm = Telemetry::start(spec(), &mut sink, Some(Duration::ZERO));
        tm.wrote(1, 1_048_576, &pseudo(1, 512 * 256));
        tm.finish("complete");
        let line = to_json_line(&sink.events[1]);
        // 512 hex characters of head plus the numeric readout.
        assert!(
            line.len() >= 700 && line.len() <= 900,
            "a frame is {} bytes on the wire",
            line.len()
        );
        assert!(line.contains("\"head_hex\":\""));
        assert_eq!(line.matches("\"head_hex\"").count(), 1);
    }

    #[test]
    fn sinks_compose_through_a_box() {
        let mut boxed: Box<dyn EventSink> = Box::new(CollectSink::new());
        let mut tm = Telemetry::start(spec(), &mut boxed, Some(Duration::ZERO));
        tm.wrote(1, 0, &[0u8; 512]);
        let s = tm.finish("complete");
        assert_eq!(s.events, 1);
    }
}
