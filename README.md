# IronBoot

Power-cut-safe, signed A/B firmware update logic with rollback protection for a small microcontroller, written in `no_std` Rust and tested by cutting the (simulated) power at every flash operation of an update.

**Status: the update and boot decision logic exists and is heavily tested against a simulated flash; it has not run on a chip, there is no real bootloader that jumps to an image, and the secure-boot chain below it is designed but not built.** Part of [physical-ai-portfolio](https://github.com/PCSchmidt/physical-ai-portfolio) (its Project 4). The portfolio plan also includes an on-MCU anomaly detector; that is not started.

## What it does

- Two image slots; each image has a header carrying a version, length, SHA-256 and an Ed25519 signature. A slot boots only if the signature and hash verify and its version is not below a rollback floor held in one-time-programmable storage.
- An update is staged into the idle slot (the running slot is never written), tried for up to three boots, and confirmed by the new image itself; if it never confirms, the bootloader falls back to the old image.
- The header is written last and the flags are single bytes that only clear bits, so a half-written update is simply an invalid slot.

## What the tests show (details in [docs/results.md](docs/results.md))

- A power cut injected at **every one of the 1,626 flash operations** of an update, in four cut patterns (including a cut inside a page program that leaves the rest of the page partly programmed): in **6,504 runs** the device always booted a genuine image, never booted an older one after a newer was confirmed, and completed the update after recovery. With a second cut during the recovery boot: **78,048 more runs, no failures.**
- The harness is shown to be able to fail: the same sweep against a naive in-place update leaves the device unbootable at **1,622 of 1,623** cut points, and 7 of 9 deliberate bugs in the real logic are caught (the other 2 are equivalent changes that cannot affect safety).
- Rejected: unsigned or wrong-key images, tampered payloads, changed version or length fields, oversized lengths, version 0, and correctly signed older images below the floor.

## What they do not show

The flash is simulated by the same person who wrote the scheme, so a different fault model could find something this one does not. Nothing is timed, nothing ran on an RP2350, and the logic is not a bootloader. A physical attacker who can rewrite flash between verification and execution, glitch the signature check, or read the flash is **not** defended against, and destroying the new image after confirmation leaves nothing bootable (the price of rollback protection; a recovery path is needed). The [threat model](docs/threat-model.md) says what is defended, what is designed, and what is not addressed.

## Run

```sh
cargo test --release     # 18 tests, about 35 s
cargo build --release --target thumbv8m.main-none-eabihf   # the logic builds for the RP2350's Cortex-M33
```

The signing key in the tests is a fixed test key. No real key exists in this repository.

## Licence

MIT.
