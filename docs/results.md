# Results: fault injection

All of this is on a **simulated flash**; nothing has run on a chip. Tests: `cargo test --release` (about 35 seconds), 18 tests in `tests/sim.rs`.

## The update sequence and the cut sweep

One update is: stage version 2 into the idle slot, reboot into the trial, the new image confirms itself (sets its flag, raises the rollback floor). On the simulated device that is **1,626 operations** (sector erases, programmed bytes, OTP bits). A power cut is injected at every one of them, in four patterns:

| Cut during | Patterns |
| --- | --- |
| a sector erase | unchanged; fully erased; left as garbage (two variants) |
| a byte program | byte unchanged; byte fully programmed; byte partly programmed (a random subset of the bits that should clear); this byte **and every later byte of the same 256-byte page** partly programmed |
| an OTP bit | not blown; blown |

After each cut the device is powered back on and must satisfy, checked in code:

1. it boots (a valid image exists), and the booted slot's contents equal the genuine image of that version byte for byte;
2. the version is 1 or 2, never anything else;
3. the rollback floor never exceeds the booted version, and if it reached 2, version 2 boots;
4. the booted version is never older than the highest version that is both valid and already confirmed;
5. an updater that then retries completes the update (version 2 confirmed, floor 2).

| Experiment | Runs | Failures |
| --- | --- | --- |
| Single cut at every operation x 4 patterns, then recover and finish | 6,504 | 0 |
| The same, plus a second power cut at each of the first 3 operations of the recovery boot (x 4 patterns) | 78,048 | 0 |
| Cut at every one of the 1,623 operations of staging a *third* update over a confirmed image (x 4 patterns); the running slot's bytes are compared before and after | 6,492 | 0 (running slot never modified) |

After a cut, 6,489 of the 6,504 single-cut runs would boot version 1 and 15 would boot version 2, one of them with the floor already raised; the rest of the update then completes by retrying.

## Does the harness have teeth? Two checks

**Control: a naive single-slot update.** The same sweep run against an in-place overwrite of the only image (erase it, write the new one) leaves the device unbootable at **1,622 of 1,623** cut points. The A/B scheme, under the same cuts, is never unbootable. So the sweep does detect the failure it is meant to rule out.

**Mutation testing of the real logic.** Nine deliberate bugs were introduced one at a time and the suite re-run:

| Mutant | Result |
| --- | --- |
| remove the rollback floor check | caught (3 tests) |
| skip the payload hash check | caught (tampered payload) |
| skip the signature check | caught (3 tests) |
| stage does not erase the target's state sector (stale flags) | caught (2 tests) |
| boot picks the lowest version instead of the highest | **first survived**; the invariant only required version 1 or 2. I added invariant 4 above and it is now caught by the cut sweep |
| remove the length bound check | caught (5 tests) |
| confirm raises the floor before setting its flag | caught (double-cut test) |
| program the header before the payload | survived: an *equivalent* mutant |
| set the trial flag before the header is programmed | survived: an *equivalent* mutant |

The two survivors are equivalent because safety comes from verifying the hash and signature before booting, not from write order: a half-written image fails verification whichever order produced it. Order still matters for tidiness and for when a torn image becomes invalid, so the code keeps the safer order, but no test can distinguish them. In total 7 of 9 mutants are caught and the other 2 are equivalent.

## Not shown

The cut patterns are a model: real flash may tear in other ways. The scheme is verified against a simulator written by the same person as the scheme, and a different author's fault model would be a stronger test. Cycle counts, signature-check time and flash wear on a real chip are unmeasured. See the [threat model](threat-model.md) for what the logic does not defend.
