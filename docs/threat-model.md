# Threat model

Scope: the update and boot decision logic in `src/lib.rs`, for a small microcontroller (the target is a Raspberry Pi Pico 2, RP2350) that runs signed firmware from external flash and takes updates over a link such as serial or BLE. A STRIDE pass over each interface, then what is defended, what is designed but not built, and what is not addressed. "Tested" means a test in `tests/sim.rs` fails if the control is removed (see [results](results.md) for how that was checked); nothing here has run on a chip.

## Assets and attacker

| Asset | Why it matters |
| --- | --- |
| The running firmware's integrity | Everything else (sensing, control, later an anomaly model) trusts it |
| The signing key (private half, held off-device) | Whoever has it can ship firmware the device accepts |
| The public key or its hash on the device | If an attacker can replace it, signatures mean nothing |
| The rollback floor | If it can be lowered, old vulnerable firmware can be reinstalled |
| Availability of a bootable image | A bricked device is a failed device |

Attackers considered: (a) someone who can send bytes over the update link; (b) someone with brief physical access who can read and write the external flash chip with a clip; (c) a well-meaning but faulty update server or build; (d) random power loss during an update. **Not considered:** an attacker with the signing key, a state-level attacker with chip-level tools (decapsulation, voltage glitching), and any threat to the application's own logic.

## STRIDE by interface

### 1. Update link (serial / BLE) carrying a new image

| | Threat | Control | Status |
| --- | --- | --- | --- |
| **S**poofing | Someone pretends to be the update server and sends their own firmware | Ed25519 signature over (version, length, SHA-256 of payload), verified against an on-device public key before anything runs; domain-separation tag in the signed message | **Implemented and tested** (wrong key, garbage signature) |
| **T**ampering | Bytes altered in transit or while staged | Payload hash and signature checked at every boot, not only at install; the signature covers the version and length too | **Implemented and tested** (tampered payload, changed version, changed length) |
| **R**epudiation | "That update was never approved" | No on-device log; signed images give provenance only | Not addressed |
| **I**nformation disclosure | Firmware read in transit | Images are signed, not encrypted | Not addressed (firmware is not secret here) |
| **D**enial of service | Oversized or malformed image fills or crashes the updater | Length checked against the slot before any read; staging never touches the running slot; a failed image is dropped after 3 trial boots | **Implemented and tested** |
| **E**levation | Malformed header makes the loader read or run outside the image | Length bound check; header parsed from fixed offsets with a magic check | **Implemented and tested** (length larger than the slot) |

### 2. External flash chip (physical attacker with a clip)

| | Threat | Control | Status |
| --- | --- | --- | --- |
| **T**ampering | Overwrite a slot with a malicious or older image | Same verification as above rejects any image not signed by the key; the floor rejects older signed images | **Implemented and tested** (downgrade below the floor is not booted) |
| **T**ampering | Modify the image *after* it was verified but before or while it executes from flash (time-of-check to time-of-use) | None | **Not addressed.** Booting executes from the same flash that was verified; defending needs copying to RAM and verifying the copy, or hardware that checks on execution |
| **I**nformation disclosure | Read the firmware or secrets from flash | None | **Not addressed.** No flash encryption; no secrets are stored here |
| **D**enial of service | Destroy both images so nothing boots | Detected and reported (`NoBootableImage`); recovery must come from outside this logic | **Known weakness, tested as such**: once the floor has risen, the previous image is dead on purpose, so destroying the new one leaves nothing. A ROM-level recovery path (USB loader, or a signed recovery image) is required |

### 3. Boot chain and debug access

| | Threat | Control | Status |
| --- | --- | --- | --- |
| **S**poofing / **T**ampering | Replace the bootloader itself | The RP2350's boot ROM verifies a signed image: a SHA-256 hash of the image, signed with an ECDSA secp256k1 key, whose public key's SHA-256 hash (fingerprint) must match one of up to four fingerprints held in one-time-programmable (OTP) memory (RP2350 datasheet, section 5.1 on signature verification and section 5.9.2 for the block format; read 2026-10-23 from a copy of the datasheet). That would make this logic the second link of a chain | **Designed, not built, not run on a chip.** The scheme is now read from the datasheet; whether it behaves so on a real board is untested. **A limit the datasheet itself states:** the signature check happens only at boot, so for an image kept in external flash someone with physical access can replace its contents after the check; the datasheet recommends packaged SRAM binaries for secure boot. This matches the check-to-use gap noted below and is not closed by this logic |
| **T**ampering | Attach a debugger and rewrite memory or registers | Intended: lock debug access via OTP | **Not built** |
| **E**levation | Glitch the clock or voltage during the signature check to skip it | None | **Not addressed.** Software cannot fully defend this; it needs hardware glitch detection or redundant checks |

### 4. Rollback floor (OTP)

| | Threat | Control | Status |
| --- | --- | --- | --- |
| **T**ampering | Lower the floor to allow an old image | The floor is a thermometer count in one-time-programmable storage, so it can only rise; a version below it never boots | **Logic implemented and tested** against a simulated OTP. **The chip's own mechanism matches in kind and differs in timing** (RP2350 datasheet, section 5.1.11): the boot ROM keeps a minimum rollback version as a unary thermometer code in OTP rows (so it can be incremented but not decremented), refuses to boot a signed image whose rollback version is lower, and the rollback version is covered by the image's signature. **But the boot ROM raises the thermometer when an image with a non-zero rollback version boots successfully, not when the application later confirms it.** An A/B trial scheme must therefore keep the new image's rollback version equal to the old one's until it has been confirmed, and bump it only in a release that is meant to be irreversible, or a bad new image could make rolling back impossible. IronBoot's own floor (raised only on confirm) is a separate, application-level floor; whether to rely on the chip's, this one, or both is a design decision not yet made. The datasheet also advises a minimum rollback version of 1, because version 0 does not set the ROLLBACK_REQUIRED flag |
| **D**enial of service | A buggy signed image is confirmed, raising the floor, and cannot be replaced by a fixed older one | Release discipline: bump the version for every shipped image; never ship an image that can confirm itself and be broken | Residual risk; irreversible by design |

### 5. Power (loss during update)

| | Threat | Control | Status |
| --- | --- | --- | --- |
| **D**enial of service | A power cut during an update leaves no valid image, or a mix of old and new | A/B slots; the running slot is never written; the header (which carries the signature) is written last; trial flags are single bytes that only clear bits and are safe to read as set when half-written; confirm sets its flag then raises the floor | **Implemented and tested exhaustively**: a cut at every one of 1,626 operations, 4 cut patterns, then again with a second cut during the recovery boot |

### 6. The confirm path (the new image declares itself healthy)

| | Threat | Control | Status |
| --- | --- | --- | --- |
| **S**poofing | A compromised image confirms itself to defeat rollback | A confirmed image is by definition already signed and verified; confirming raises the floor only to its own version | Accepted: a signed malicious image can confirm itself. That is a key-compromise problem, not a boot-logic one |
| **D**enial of service | A broken image never confirms | After 3 trial boots the bootloader returns to the confirmed image | **Implemented and tested** |

## What the tests do not and cannot show

- The simulated flash is byte-granular and its cut patterns are mine: real NOR flash and its controller can behave differently (multi-byte program units, erase suspend, partial-erase levels). The page-program pattern is the harshest I modelled.
- The bootloader is logic only. Nothing jumps to an image, and no chip was involved.
- Signature verification speed, flash wear and update time on the RP2350 are unmeasured.
- Key management is out of scope: no real key exists; tests use a fixed key that must never be used for anything real.
- Side channels, fault injection, supply-chain attacks on the toolchain, and key compromise or revocation are not covered.

## Next, in order of value

1. Decide how IronBoot's application-level floor and the boot ROM's rollback thermometer fit together (the timing difference above), then run this logic on a board.
2. Close the check-to-use gap (verify the copy in RAM, or use hardware verification).
3. Add a signed recovery image so destroying one slot is not a permanent denial of service.
4. The on-MCU anomaly detector from the project outline, with its own threat entry (poisoned or spoofed bus traffic).
