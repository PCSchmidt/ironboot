//! Fault injection: cut the power at every flash operation of an update and check the device survives.
//!
//! The simulated device counts "units": one per sector erase, one per programmed byte, one per OTP bit
//! blown. A fault is armed at one unit and one pattern, then every later operation fails until `power_on`:
//!
//! * erase cut:   pattern 0 sector unchanged, 1 sector fully erased, 2 and 3 sector left as garbage
//! * program cut: pattern 0 byte unchanged, 1 byte fully programmed, 2 byte partly programmed (a random
//!   subset of the bits that should clear), 3 this byte and every later byte of the same 256-byte page partly
//!   programmed (a cut inside a page program)
//! * OTP cut:     pattern 0 bit not blown, 1 bit blown (a one-bit write is treated as all or nothing)
//!
//! Flash semantics are NOR: programming only clears bits (`new = old & data`), erasing sets 0xFF.
//! The signing key here is a fixed test key; no real key is in this repository.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ironboot::*;
use sha2::{Digest, Sha256};

const L: Layout = Layout {
    sector: 256,
    payload_sectors: 8,
};
const PAYLOAD: usize = 1500;

struct Sim {
    mem: Vec<u8>,
    floor: u32,
    units: u64,
    arm: Option<(u64, u8)>,
    dead: bool,
    rng: u64,
}

impl Sim {
    fn new() -> Self {
        Sim {
            mem: vec![0xFF; L.total_bytes()],
            floor: 0,
            units: 0,
            arm: None,
            dead: false,
            rng: 0x9E37_79B9_7F4A_7C15,
        }
    }
    fn rand(&mut self) -> u8 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng >> 24) as u8
    }
    /// None = the unit completes; Some(255) = power already gone; Some(p) = power is cut now, pattern p.
    fn tick(&mut self) -> Option<u8> {
        if self.dead {
            return Some(255);
        }
        let u = self.units;
        self.units += 1;
        if let Some((at, p)) = self.arm {
            if u == at {
                self.dead = true;
                self.arm = None;
                return Some(p);
            }
        }
        None
    }
    fn power_on(&mut self) {
        self.dead = false;
        self.arm = None;
    }
    fn arm_at(&mut self, unit_from_now: u64, pattern: u8) {
        self.arm = Some((self.units + unit_from_now, pattern));
    }
}

impl Flash for Sim {
    fn read(&self, addr: usize, buf: &mut [u8]) {
        buf.copy_from_slice(&self.mem[addr..addr + buf.len()]);
    }
    fn erase_sector(&mut self, sector: usize) -> Result<(), PowerLoss> {
        let r = sector * L.sector..(sector + 1) * L.sector;
        match self.tick() {
            None => {
                self.mem[r].fill(0xFF);
                Ok(())
            }
            Some(255) | Some(0) => Err(PowerLoss),
            Some(1) => {
                self.mem[r].fill(0xFF);
                Err(PowerLoss)
            }
            Some(_) => {
                for i in r {
                    self.mem[i] = self.rand();
                }
                Err(PowerLoss)
            }
        }
    }
    fn program(&mut self, addr: usize, data: &[u8]) -> Result<(), PowerLoss> {
        for (i, &b) in data.iter().enumerate() {
            match self.tick() {
                None => self.mem[addr + i] &= b,
                Some(255) | Some(0) => return Err(PowerLoss),
                Some(1) => {
                    self.mem[addr + i] &= b;
                    return Err(PowerLoss);
                }
                Some(3) => {
                    // a cut inside a flash page program: this byte AND every later byte of the same
                    // 256-byte page are left partly programmed, not just one torn byte
                    let page_end = ((addr + i) / 256 + 1) * 256;
                    let end = data.len().min(page_end - addr);
                    for (j, &want) in data.iter().enumerate().take(end).skip(i) {
                        let old = self.mem[addr + j];
                        let partial = (old & !want) & self.rand();
                        self.mem[addr + j] = old & !partial;
                    }
                    return Err(PowerLoss);
                }
                Some(_) => {
                    let old = self.mem[addr + i];
                    let to_clear = old & !b;
                    let partial = to_clear & self.rand();
                    self.mem[addr + i] = old & !partial;
                    return Err(PowerLoss);
                }
            }
        }
        Ok(())
    }
}

impl Otp for Sim {
    fn floor(&self) -> u32 {
        self.floor
    }
    fn raise_floor(&mut self, to: u32) -> Result<(), PowerLoss> {
        while self.floor < to {
            match self.tick() {
                None => self.floor += 1,
                Some(1) => {
                    self.floor += 1;
                    return Err(PowerLoss);
                }
                Some(_) => return Err(PowerLoss),
            }
        }
        Ok(())
    }
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn other_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn vk() -> VerifyingKey {
    key().verifying_key()
}

fn payload(version: u32) -> Vec<u8> {
    (0..PAYLOAD)
        .map(|i| (i as u32).wrapping_mul(31).wrapping_add(version * 17) as u8)
        .collect()
}

fn signed(k: &SigningKey, version: u32, payload: &[u8]) -> Header {
    let hash: [u8; 32] = Sha256::digest(payload).into();
    let sig = k
        .sign(&signed_message(version, payload.len() as u32, &hash))
        .to_bytes();
    Header {
        version,
        len: payload.len() as u32,
        hash,
        sig,
    }
}

/// A device out of the factory: version 1 confirmed in slot 0, floor 1.
fn factory() -> Sim {
    let mut s = Sim::new();
    let p = payload(1);
    provision(&mut s, &L, 0, &signed(&key(), 1, &p), &p).unwrap();
    s
}

fn stage_v2(s: &mut Sim, active: usize) -> Result<(), StageError> {
    let p = payload(2);
    stage(s, &L, active, 1 - active, &signed(&key(), 2, &p), &p)
}

/// The whole update as one device would run it: stage v2, reboot into the trial, the new image confirms.
fn update_sequence(s: &mut Sim) -> Result<(), ()> {
    stage_v2(s, 0).map_err(|_| ())?;
    let d = boot(s, &L, &vk()).map_err(|_| ())?;
    assert_eq!((d.slot, d.version, d.trial), (1, 2, true));
    confirm(s, &L, d.slot, d.version).map_err(|_| ())?;
    Ok(())
}

/// What the device must satisfy after any power cut, once power is back.
fn check_survives(s: &mut Sim) {
    let floor_before = s.floor;
    // the highest version that is valid AND already confirmed: the device must never boot anything older
    let mut max_confirmed = 0;
    for slot in 0..2 {
        let mut flag = [0u8];
        s.read(L.addr(L.state_sector(slot)) + 1, &mut flag);
        if let Some(v) = verify_slot(s, &L, &vk(), slot, floor_before) {
            if flag[0] != 0xFF {
                max_confirmed = max_confirmed.max(v);
            }
        }
    }
    let d =
        boot(s, &L, &vk()).expect("the device must still have a bootable image after a power cut");
    assert!(
        d.version == 1 || d.version == 2,
        "booted an unexpected version {}",
        d.version
    );
    let mut content = vec![0u8; PAYLOAD];
    s.read(L.addr(L.payload_sector(d.slot)), &mut content);
    assert_eq!(
        content,
        payload(d.version),
        "the booted slot does not hold the genuine image"
    );
    assert!(
        s.floor <= d.version,
        "rollback floor {} is above the booted version {}",
        s.floor,
        d.version
    );
    if floor_before >= 2 {
        assert_eq!(
            d.version, 2,
            "the floor reached 2 but an older image booted"
        );
    }
    assert!(
        d.version >= max_confirmed,
        "booted version {} although version {max_confirmed} is valid and confirmed",
        d.version
    );
}

/// What a sensible updater does after a reboot, until version 2 is confirmed.
fn finish_update(s: &mut Sim) {
    for _ in 0..4 {
        let d = boot(s, &L, &vk()).expect("bootable");
        if d.version == 2 {
            if d.trial || s.floor < 2 {
                confirm(s, &L, d.slot, 2).unwrap();
            }
            break;
        }
        stage_v2(s, d.slot).unwrap();
    }
    let d = boot(s, &L, &vk()).unwrap();
    assert_eq!(
        (d.version, d.trial, s.floor),
        (2, false, 2),
        "the update did not complete after recovery"
    );
}

#[test]
fn a_factory_device_boots_its_confirmed_image() {
    let mut s = factory();
    assert_eq!(
        boot(&mut s, &L, &vk()),
        Ok(BootDecision {
            slot: 0,
            version: 1,
            trial: false
        })
    );
}

#[test]
fn a_normal_update_runs_a_trial_then_becomes_the_confirmed_image() {
    let mut s = factory();
    update_sequence(&mut s).unwrap();
    assert_eq!(
        boot(&mut s, &L, &vk()),
        Ok(BootDecision {
            slot: 1,
            version: 2,
            trial: false
        })
    );
    assert_eq!(s.floor, 2);
    assert_eq!(
        verify_slot(&s, &L, &vk(), 0, s.floor),
        None,
        "the old image is below the floor and no longer boots"
    );
}

#[test]
fn staging_into_the_running_slot_is_refused() {
    let mut s = factory();
    let p = payload(2);
    assert_eq!(
        stage(&mut s, &L, 0, 0, &signed(&key(), 2, &p), &p),
        Err(StageError::Active)
    );
    assert_eq!(boot(&mut s, &L, &vk()).unwrap().version, 1);
}

#[test]
fn an_oversized_payload_is_refused() {
    let mut s = factory();
    let p = vec![0u8; L.max_payload() + 1];
    assert_eq!(
        stage(&mut s, &L, 0, 1, &signed(&key(), 2, &p), &p),
        Err(StageError::TooBig)
    );
}

fn stage_and_expect_v1_still_boots(s: &mut Sim, header: Header, payload: &[u8]) {
    stage(s, &L, 0, 1, &header, payload).unwrap();
    assert_eq!(
        boot(s, &L, &vk()),
        Ok(BootDecision {
            slot: 0,
            version: 1,
            trial: false
        }),
        "the bad image must be ignored"
    );
}

#[test]
fn a_tampered_payload_is_ignored() {
    let mut s = factory();
    let p = payload(2);
    let h = signed(&key(), 2, &p);
    let mut bad = p.clone();
    bad[700] ^= 0x01;
    stage_and_expect_v1_still_boots(&mut s, h, &bad);
}

#[test]
fn an_image_signed_by_another_key_is_ignored() {
    let mut s = factory();
    let p = payload(2);
    stage_and_expect_v1_still_boots(&mut s, signed(&other_key(), 2, &p), &p);
}

#[test]
fn a_garbage_signature_is_ignored() {
    let mut s = factory();
    let p = payload(2);
    let mut h = signed(&key(), 2, &p);
    h.sig = [0xA5; 64];
    stage_and_expect_v1_still_boots(&mut s, h, &p);
}

#[test]
fn changing_the_version_or_length_after_signing_breaks_the_signature() {
    for tweak in 0..2 {
        let mut s = factory();
        let p = payload(2);
        let mut h = signed(&key(), 2, &p);
        if tweak == 0 {
            h.version = 3; // claim a newer version with the old signature
        } else {
            h.len -= 1; // claim a shorter payload (the hash then also differs)
        }
        stage_and_expect_v1_still_boots(&mut s, h, &p);
    }
}

#[test]
fn a_length_longer_than_the_slot_is_ignored_without_reading_past_it() {
    let mut s = factory();
    let p = payload(2);
    let mut h = signed(&key(), 2, &p);
    h.len = u32::MAX;
    stage_and_expect_v1_still_boots(&mut s, h, &p);
}

#[test]
fn version_zero_is_never_accepted() {
    let mut s = Sim::new();
    let p = payload(0);
    provision(&mut s, &L, 0, &signed(&key(), 0, &p), &p).unwrap();
    assert_eq!(boot(&mut s, &L, &vk()), Err(BootError::NoBootableImage));
}

#[test]
fn a_correctly_signed_older_image_is_rejected_after_the_floor_has_risen() {
    let mut s = factory();
    update_sequence(&mut s).unwrap(); // floor is now 2
                                      // an attacker (or a mistake) puts the genuine, signed version 1 back into the idle slot and trials it
    let p = payload(1);
    stage(&mut s, &L, 1, 0, &signed(&key(), 1, &p), &p).unwrap();
    assert_eq!(
        boot(&mut s, &L, &vk()),
        Ok(BootDecision {
            slot: 1,
            version: 2,
            trial: false
        }),
        "downgrade must not boot"
    );
}

#[test]
fn a_new_image_that_never_confirms_is_dropped_after_max_tries() {
    let mut s = factory();
    stage_v2(&mut s, 0).unwrap();
    for n in 0..MAX_TRIES {
        assert_eq!(
            boot(&mut s, &L, &vk()),
            Ok(BootDecision {
                slot: 1,
                version: 2,
                trial: true
            }),
            "trial boot {n}"
        );
    }
    assert_eq!(
        boot(&mut s, &L, &vk()),
        Ok(BootDecision {
            slot: 0,
            version: 1,
            trial: false
        }),
        "fell back to the confirmed image"
    );
    assert_eq!(s.floor, 1, "the floor never rose for the failed image");
    assert_eq!(
        boot(&mut s, &L, &vk()).unwrap().version,
        1,
        "and it stays on the old image"
    );
}

#[test]
fn destroying_the_only_valid_image_is_a_denial_of_service_not_a_downgrade() {
    // The price of rollback protection: once floor = 2, version 1 is dead. If version 2 is destroyed, there is
    // nothing to boot. A recovery path outside this logic (the ROM loader) must exist; see the threat model.
    let mut s = factory();
    update_sequence(&mut s).unwrap();
    s.mem[L.addr(L.header_sector(1))..L.addr(L.header_sector(1)) + 4].fill(0);
    assert_eq!(boot(&mut s, &L, &vk()), Err(BootError::NoBootableImage));
}

/// Total units the update sequence uses, with no fault.
fn sequence_units() -> u64 {
    let mut s = factory();
    let start = s.units;
    update_sequence(&mut s).unwrap();
    s.units - start
}

#[test]
fn power_cut_at_every_operation_of_an_update_never_bricks_or_downgrades() {
    let n = sequence_units();
    let (mut runs, mut ended_v1, mut ended_v2_partial, mut cut_inside_confirm) =
        (0u64, 0u64, 0u64, 0u64);
    for unit in 0..n {
        for pattern in 0..4u8 {
            let mut s = factory();
            s.arm_at(unit, pattern);
            let r = update_sequence(&mut s);
            assert!(r.is_err(), "the cut at unit {unit} did not fire");
            s.power_on();

            let mut probe = Sim {
                mem: s.mem.clone(),
                floor: s.floor,
                units: s.units,
                arm: None,
                dead: false,
                rng: s.rng,
            };
            let before = probe.floor;
            check_survives(&mut probe);
            if before >= 2 {
                cut_inside_confirm += 1;
            }
            match boot(
                &mut Sim {
                    mem: s.mem.clone(),
                    floor: s.floor,
                    units: 0,
                    arm: None,
                    dead: false,
                    rng: 1,
                },
                &L,
                &vk(),
            )
            .unwrap()
            .version
            {
                1 => ended_v1 += 1,
                _ => ended_v2_partial += 1,
            }
            finish_update(&mut s);
            runs += 1;
        }
    }
    println!(
        "update sequence = {n} units; {runs} cut-and-recover runs (every unit x 4 patterns): all booted after the cut and all completed after recovery; \
         after the cut {ended_v1} would boot v1, {ended_v2_partial} would boot v2 ({cut_inside_confirm} with the floor already raised)"
    );
    assert_eq!(runs, n * 4);
}

#[test]
fn a_second_power_cut_during_the_recovery_boot_is_survived_too() {
    let n = sequence_units();
    let mut runs = 0u64;
    for unit in 0..n {
        for pattern in 0..4u8 {
            let mut s = factory();
            s.arm_at(unit, pattern);
            let _ = update_sequence(&mut s);
            s.power_on();
            // the reboot after the first cut loses power as well: at each of its first operations, each pattern
            for second_unit in 0..3 {
                for second in 0..4u8 {
                    let mut t = Sim {
                        mem: s.mem.clone(),
                        floor: s.floor,
                        units: s.units,
                        arm: None,
                        dead: false,
                        rng: s.rng ^ 0x55,
                    };
                    t.arm_at(second_unit, second);
                    let _ = boot(&mut t, &L, &vk());
                    t.power_on();
                    check_survives(&mut t);
                    finish_update(&mut t);
                    runs += 1;
                }
            }
        }
    }
    println!("{runs} double-cut runs survived");
}

#[test]
fn a_cut_while_staging_a_third_update_leaves_the_confirmed_image_untouched() {
    // the running image must never be written to: cut at every unit of staging v3 on top of a confirmed v2
    let mut base = factory();
    update_sequence(&mut base).unwrap(); // v2 confirmed in slot 1, floor 2, slot 0 idle
    let p3 = payload(3);
    let h3 = signed(&key(), 3, &p3);
    let mut dry = Sim {
        mem: base.mem.clone(),
        floor: base.floor,
        units: 0,
        arm: None,
        dead: false,
        rng: 3,
    };
    stage(&mut dry, &L, 1, 0, &h3, &p3).unwrap();
    let n = dry.units;
    let active = L.addr(L.header_sector(1))..L.addr(L.header_sector(1) + L.sectors_per_slot());
    for unit in 0..n {
        for pattern in 0..4u8 {
            let mut s = Sim {
                mem: base.mem.clone(),
                floor: base.floor,
                units: 0,
                arm: None,
                dead: false,
                rng: 3,
            };
            s.arm_at(unit, pattern);
            assert!(stage(&mut s, &L, 1, 0, &h3, &p3).is_err());
            s.power_on();
            assert_eq!(
                s.mem[active.clone()],
                base.mem[active.clone()],
                "staging touched the running slot at unit {unit}"
            );
            let d = boot(&mut s, &L, &vk()).unwrap();
            assert!(d.version == 2 || d.version == 3);
        }
    }
}

#[test]
fn the_harness_has_teeth_a_naive_in_place_update_is_bricked_by_a_power_cut() {
    // Control experiment: overwrite the only image in place (no second slot to fall back on). The same
    // sweep must find power-cut points that leave nothing bootable, or it proves nothing about the real scheme.
    let p2 = payload(2);
    let h2 = signed(&key(), 2, &p2);
    let mut dry = factory();
    let start = dry.units;
    stage(&mut dry, &L, 1, 0, &h2, &p2).unwrap(); // pretends slot 1 is the running one, so slot 0 is overwritten
    let n = dry.units - start;
    let mut bricked = 0u64;
    for unit in 0..n {
        let mut s = factory();
        s.arm_at(unit, 2);
        let _ = stage(&mut s, &L, 1, 0, &h2, &p2);
        s.power_on();
        if boot(&mut s, &L, &vk()) == Err(BootError::NoBootableImage) {
            bricked += 1;
        }
    }
    println!("naive in-place update: {bricked} of {n} cut points leave the device unbootable");
    assert!(
        bricked > n / 2,
        "the sweep should brick a single-slot update at most cut points, got {bricked} of {n}"
    );
}

#[test]
fn staging_over_a_used_slot_clears_its_old_flags_so_the_new_image_starts_on_trial() {
    let mut s = factory();
    update_sequence(&mut s).unwrap(); // slot 1 now carries CONFIRMED and tries; slot 0 is idle
    let p3 = payload(3);
    stage(&mut s, &L, 1, 0, &signed(&key(), 3, &p3), &p3).unwrap();
    assert_eq!(
        boot(&mut s, &L, &vk()),
        Ok(BootDecision {
            slot: 0,
            version: 3,
            trial: true
        })
    );
    // and stage a fourth over slot 1, which holds stale CONFIRMED and TRY flags from version 2
    let p4 = payload(4);
    stage(&mut s, &L, 0, 1, &signed(&key(), 4, &p4), &p4).unwrap();
    confirm(&mut s, &L, 0, 3).unwrap();
    assert_eq!(
        boot(&mut s, &L, &vk()),
        Ok(BootDecision {
            slot: 1,
            version: 4,
            trial: true
        }),
        "stale flags must not make v4 look confirmed"
    );
}
