//! Power-cut-safe, signed A/B firmware update logic with rollback protection. `no_std`, no allocation.
//!
//! This is the *decision logic* of a bootloader, written against two small traits ([`Flash`], [`Otp`])
//! so it can be driven by a simulated flash that loses power at any operation. It is not a bootloader: it
//! does not jump to an image, and it has not run on a chip. See `docs/threat-model.md` for what it does and
//! does not defend against.
//!
//! # Layout
//!
//! Two slots. Each slot is three kinds of flash sectors:
//!
//! ```text
//! [ header sector ][ payload sectors ... ][ state sector ]
//! ```
//!
//! * **header** (112 bytes): `IRONBOOT`, version, payload length, SHA-256 of the payload, and an Ed25519
//!   signature over a domain-separated message of (version, length, hash). It is programmed *last*, so a
//!   torn write leaves a header that fails its signature and the slot is simply invalid.
//! * **state sector**: single-byte flags that are only ever *cleared* (flash can clear bits without an erase):
//!   byte 0 = `TRIAL` (staged, try it), byte 1 = `CONFIRMED` (the running image declared itself healthy),
//!   bytes 2.. = one `TRY` byte per boot attempt of a trial image. A flag is "set" when its byte is not
//!   0xFF, so a half-programmed byte still reads as set; every flag is safe to read as set after a cut.
//! * The **rollback floor** lives in one-time-programmable storage ([`Otp`]) as a thermometer count that
//!   can only rise. A slot whose version is below the floor is never booted, even if correctly signed.
//!
//! # Update, in order
//!
//! 1. [`stage`]: erase the target slot's header, payload and state sectors (header first, so the slot is
//!    invalid at once), program the payload, program the header, then set `TRIAL`.
//! 2. [`boot`]: a valid `TRIAL` slot that is not `CONFIRMED` and has tries left is booted and one `TRY` is
//!    consumed. When tries run out, or the image is invalid, the highest valid `CONFIRMED` slot boots.
//! 3. [`confirm`]: set `CONFIRMED`, then raise the rollback floor to the image's version.
//!
//! The order of those steps is what makes a cut at any point survivable; `tests/sim.rs` checks that by
//! cutting at every flash operation of the whole sequence.

#![no_std]

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const MAGIC: [u8; 8] = *b"IRONBOOT";
pub const HEADER_LEN: usize = 8 + 4 + 4 + 32 + 64;
/// Boot attempts a trial image gets before the bootloader gives up on it.
pub const MAX_TRIES: usize = 3;
const DOMAIN: &[u8] = b"ironboot-image-v1";
const FLAG_TRIAL: usize = 0;
const FLAG_CONFIRMED: usize = 1;
const FIRST_TRY: usize = 2;

/// Power was lost during a flash or OTP operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerLoss;

/// NOR flash: `program` can only clear bits; `erase_sector` sets a whole sector to 0xFF. Either may be
/// interrupted by [`PowerLoss`], leaving the affected bytes in an undefined state.
pub trait Flash {
    fn read(&self, addr: usize, buf: &mut [u8]);
    fn erase_sector(&mut self, sector: usize) -> Result<(), PowerLoss>;
    fn program(&mut self, addr: usize, data: &[u8]) -> Result<(), PowerLoss>;
}

/// One-time-programmable rollback counter: the floor can rise, never fall.
pub trait Otp {
    fn floor(&self) -> u32;
    fn raise_floor(&mut self, to: u32) -> Result<(), PowerLoss>;
}

/// Sector geometry. A real RP2350 part would use 4,096-byte sectors; the tests use small ones.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub sector: usize,
    pub payload_sectors: usize,
}

impl Layout {
    pub const fn sectors_per_slot(&self) -> usize {
        1 + self.payload_sectors + 1
    }
    pub const fn header_sector(&self, slot: usize) -> usize {
        slot * self.sectors_per_slot()
    }
    pub const fn payload_sector(&self, slot: usize) -> usize {
        self.header_sector(slot) + 1
    }
    pub const fn state_sector(&self, slot: usize) -> usize {
        self.header_sector(slot) + 1 + self.payload_sectors
    }
    pub const fn addr(&self, sector: usize) -> usize {
        sector * self.sector
    }
    pub const fn max_payload(&self) -> usize {
        self.payload_sectors * self.sector
    }
    pub const fn total_bytes(&self) -> usize {
        2 * self.sectors_per_slot() * self.sector
    }
}

/// The parsed, *unverified* header of a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u32,
    pub len: u32,
    pub hash: [u8; 32],
    pub sig: [u8; 64],
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[..8].copy_from_slice(&MAGIC);
        b[8..12].copy_from_slice(&self.version.to_le_bytes());
        b[12..16].copy_from_slice(&self.len.to_le_bytes());
        b[16..48].copy_from_slice(&self.hash);
        b[48..112].copy_from_slice(&self.sig);
        b
    }

    pub fn decode(b: &[u8; HEADER_LEN]) -> Option<Header> {
        if b[..8] != MAGIC {
            return None;
        }
        Some(Header {
            version: u32::from_le_bytes(b[8..12].try_into().ok()?),
            len: u32::from_le_bytes(b[12..16].try_into().ok()?),
            hash: b[16..48].try_into().ok()?,
            sig: b[48..112].try_into().ok()?,
        })
    }
}

/// The bytes that are signed: domain tag, version, length, payload hash.
pub fn signed_message(version: u32, len: u32, hash: &[u8; 32]) -> [u8; 17 + 4 + 4 + 32] {
    let mut m = [0u8; 17 + 4 + 4 + 32];
    m[..17].copy_from_slice(DOMAIN);
    m[17..21].copy_from_slice(&version.to_le_bytes());
    m[21..25].copy_from_slice(&len.to_le_bytes());
    m[25..].copy_from_slice(hash);
    m
}

pub fn read_header<F: Flash>(f: &F, l: &Layout, slot: usize) -> Option<Header> {
    let mut b = [0u8; HEADER_LEN];
    f.read(l.addr(l.header_sector(slot)), &mut b);
    Header::decode(&b)
}

/// The version of the image in `slot` if, and only if, it is acceptable: version non-zero and at least
/// `floor`, length within the slot, payload hash matches, signature valid under `key`.
pub fn verify_slot<F: Flash>(
    f: &F,
    l: &Layout,
    key: &VerifyingKey,
    slot: usize,
    floor: u32,
) -> Option<u32> {
    let h = read_header(f, l, slot)?;
    if h.version == 0 || h.version < floor || h.len as usize > l.max_payload() {
        return None;
    }
    let mut hasher = Sha256::new();
    let base = l.addr(l.payload_sector(slot));
    let mut done = 0usize;
    let mut buf = [0u8; 64];
    while done < h.len as usize {
        let n = (h.len as usize - done).min(buf.len());
        f.read(base + done, &mut buf[..n]);
        hasher.update(&buf[..n]);
        done += n;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if digest != h.hash {
        return None;
    }
    let sig = Signature::from_bytes(&h.sig);
    key.verify_strict(&signed_message(h.version, h.len, &h.hash), &sig)
        .ok()?;
    Some(h.version)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct State {
    trial: bool,
    confirmed: bool,
    tries: usize,
}

fn read_state<F: Flash>(f: &F, l: &Layout, slot: usize) -> State {
    let base = l.addr(l.state_sector(slot));
    let mut b = [0xFFu8; FIRST_TRY + MAX_TRIES];
    f.read(base, &mut b);
    State {
        trial: b[FLAG_TRIAL] != 0xFF,
        confirmed: b[FLAG_CONFIRMED] != 0xFF,
        tries: b[FIRST_TRY..].iter().filter(|x| **x != 0xFF).count(),
    }
}

fn set_flag<F: Flash>(f: &mut F, l: &Layout, slot: usize, index: usize) -> Result<(), PowerLoss> {
    f.program(l.addr(l.state_sector(slot)) + index, &[0x00])
}

/// What [`boot`] decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootDecision {
    pub slot: usize,
    pub version: u32,
    /// The image is on trial: it must call [`confirm`] once it has checked itself, or it is dropped after
    /// [`MAX_TRIES`] boots.
    pub trial: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootError {
    /// Neither slot holds an acceptable confirmed image or a trial with tries left. A recovery path outside
    /// this logic (for example the chip's ROM USB loader) is the only way out.
    NoBootableImage,
    PowerLoss,
}

impl From<PowerLoss> for BootError {
    fn from(_: PowerLoss) -> Self {
        BootError::PowerLoss
    }
}

/// Decide which slot to run, consuming one try if it is a trial.
pub fn boot<D: Flash + Otp>(
    d: &mut D,
    l: &Layout,
    key: &VerifyingKey,
) -> Result<BootDecision, BootError> {
    let floor = d.floor();
    let valid = [
        verify_slot(d, l, key, 0, floor),
        verify_slot(d, l, key, 1, floor),
    ];
    let state = [read_state(d, l, 0), read_state(d, l, 1)];

    // a trial image with tries left, highest version first
    let mut best_trial: Option<(usize, u32)> = None;
    for s in 0..2 {
        if let Some(v) = valid[s] {
            let st = state[s];
            if st.trial
                && !st.confirmed
                && st.tries < MAX_TRIES
                && best_trial.is_none_or(|(_, bv)| v > bv)
            {
                best_trial = Some((s, v));
            }
        }
    }
    if let Some((slot, version)) = best_trial {
        set_flag(d, l, slot, FIRST_TRY + state[slot].tries)?;
        return Ok(BootDecision {
            slot,
            version,
            trial: true,
        });
    }

    let mut best: Option<(usize, u32)> = None;
    for s in 0..2 {
        if let Some(v) = valid[s] {
            if state[s].confirmed && best.is_none_or(|(_, bv)| v > bv) {
                best = Some((s, v));
            }
        }
    }
    best.map(|(slot, version)| BootDecision {
        slot,
        version,
        trial: false,
    })
    .ok_or(BootError::NoBootableImage)
}

/// The running image has checked itself: mark its slot confirmed, then raise the rollback floor.
/// Flag first, floor second: a cut between them leaves a confirmed, valid image and an old floor, which
/// boots the same image.
pub fn confirm<D: Flash + Otp>(
    d: &mut D,
    l: &Layout,
    slot: usize,
    version: u32,
) -> Result<(), PowerLoss> {
    set_flag(d, l, slot, FLAG_CONFIRMED)?;
    d.raise_floor(version)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageError {
    /// The target slot is the one currently running.
    Active,
    /// The payload does not fit in a slot.
    TooBig,
    PowerLoss,
}

impl From<PowerLoss> for StageError {
    fn from(_: PowerLoss) -> Self {
        StageError::PowerLoss
    }
}

/// Write a signed image into `target` and mark it for trial. The caller supplies the header exactly as
/// signed; nothing is verified here, because [`boot`] verifies everything before running anything.
pub fn stage<F: Flash>(
    f: &mut F,
    l: &Layout,
    active: usize,
    target: usize,
    header: &Header,
    payload: &[u8],
) -> Result<(), StageError> {
    if target == active {
        return Err(StageError::Active);
    }
    if payload.len() > l.max_payload() {
        return Err(StageError::TooBig);
    }
    f.erase_sector(l.header_sector(target))?; // header first: the slot is invalid from here on
    for i in 0..l.payload_sectors {
        f.erase_sector(l.payload_sector(target) + i)?;
    }
    f.erase_sector(l.state_sector(target))?;
    f.program(l.addr(l.payload_sector(target)), payload)?;
    f.program(l.addr(l.header_sector(target)), &header.encode())?; // header last
    set_flag(f, l, target, FLAG_TRIAL)?;
    Ok(())
}

/// Factory provisioning: an image that is already confirmed, and the floor set to its version.
pub fn provision<D: Flash + Otp>(
    d: &mut D,
    l: &Layout,
    slot: usize,
    header: &Header,
    payload: &[u8],
) -> Result<(), StageError> {
    stage(d, l, 1 - slot, slot, header, payload)?;
    set_flag(d, l, slot, FLAG_CONFIRMED)?;
    d.raise_floor(header.version)?;
    Ok(())
}
