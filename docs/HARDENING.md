# Hardening record

What was weak, what changed, and the test that keeps it fixed. Every row has a
regression test in `tests/test_hardening.py` (186 tests pass in total).

## Legacy packet (v0)

| Weakness | Fix | Where | Test |
|---|---|---|---|
| Message travelled in plain text | Use the v2 channel for confidentiality; v0 stays as the signed baseline | `src/qsc/channel.py` | `test_v2_wire_never_carries_plaintext` |
| A missing ML-DSA tag counted as valid | Tag is required whenever Bob holds Alice's ML-DSA key | `src/bob.py` | `test_missing_ml_dsa_tag_is_rejected` |
| ML-DSA signed only the first 16 bytes of one revealed key | Signs a canonical transcript: session, sequence, message hash, a digest of every revealed key, the message bits and parameters | `src/crypto.py::canonical_transcript`, `src/alice.py`, `src/bob.py` | `test_ml_dsa_covers_every_revealed_key` |
| Hash fields were concatenated without separators | Domain tag plus length-prefixed fields; constant-time compare | `src/crypto.py` | `test_hash_fields_cannot_shift` |
| Signed bits depended on the message only | Bits now mix in the session and sequence number; Bob also checks the signature's session and slot match the packet | `src/qds_signer.py`, `src/qds_verifier.py`, `src/bob.py` | `test_signature_bits_bound_to_session_and_slot` |
| One GC key pair could sign twice, exposing both keys at some positions | Key pairs are one-time; a second `sign` raises. The console fetches fresh keys automatically | `src/qds_signer.py`, `src/gc_keys.py`, `src/ui_helpers.py` | `test_gc_key_pair_is_one_time` |
| An invalid packet used up its sequence number, blocking the genuine one | Sequence numbers are checked first and consumed only after acceptance | `src/session.py`, `src/bob.py` | `test_rejected_packet_does_not_use_up_its_sequence_number` |
| Basis choices used Python's `random` | `secrets.SystemRandom` | `src/qpkd.py`, `src/e91_monitor.py` | covered by existing E91 and QPKD tests |

## Encrypted channel (v1 to v2)

| Weakness in v1 | v2 behaviour | Test |
|---|---|---|
| Classical QKD messages unauthenticated | Every handshake message carries an ML-DSA-65 signature from a pinned identity key, with a counter | `test_v2_handshake_messages_are_authenticated` |
| Fell back to X25519 alone if QKD aborted | No classical-only path: ML-KEM-768 and X25519 always run; QKD adds a third secret; all are combined by HKDF-SHA3 over the transcript | `test_v2_never_falls_back_to_classical_only`, `test_v2_delivers_honestly_with_all_three_keys` |
| Poisson pulses with no decoys, no privacy amplification | Signal, weak and vacuum decoy intensities; single-photon yield and error bounds; finite-size correction; Toeplitz privacy amplification sized to the bound | `src/qsc/bb84.py`, exercised by every v2 test |
| Python `random` for QKD | `secrets.SystemRandom` | v2 config |
| No replay protection | Per-message ratchet and strictly increasing sequence numbers | `test_v2_accepts_each_packet_once` |
| Data packets authenticated only by GCM | GCM plus an ML-DSA signature over header and ciphertext | `test_v2_rejects_modified_ciphertext`, `test_v2_rejects_packet_without_signature` |
| Ciphertext length equalled message length | Plaintext padded to 64-byte blocks | `test_v2_padding_hides_short_length_differences` |
| No key confirmation | Both sides prove the derived key before any data | `test_v2_aborts_if_kem_ciphertext_changes` |

## Limits that remain

- Everything is simulation: photons, detectors and quantum memory are modelled in Python and Qiskit Aer.
- The Gottesman-Chuang layer signs 32 bits of the bound hash. The ML-DSA transcript now covers the full hash, but the quantum layer alone should use 128 or more positions for real security.
- The GC acceptance threshold tolerates one noisy position out of 32 by design, so a single substituted public-key copy is absorbed as noise (the console's Pauli-noise scenarios show this).
- If QKD aborts (for example, because someone is measuring photons), v2 still delivers using ML-KEM-768 plus X25519. That keeps the session post-quantum secure but without the photon key; the report lists which key sources were used.
- Identity keys are assumed to be exchanged once, out of band, as in any QKD deployment.
- Simulated measurement sampling in `src/teleportation.py` uses NumPy's generator; it produces no key material.

## Architecture review, round 2

Found by reading the design after v2 shipped. Fixed items have tests in
`tests/test_hardening.py` (190 tests pass in total).

| Finding | Status | Where | Test |
|---|---|---|---|
| Bob ran destructive SWAP tests on packets that had already failed a classical check, so an invalid packet could use up the copies the genuine signature needed | Fixed: SWAP tests run only after session, replay, hash and ML-DSA all pass | `src/bob.py` | `test_rejected_packet_does_not_burn_quantum_copies` |
| The v2 ratchet required strict order, so one lost message made every later one undeliverable | Fixed: receiver steps ahead up to 64 messages, keeps one-use keys for the gaps, and commits state only after a packet verifies | `src/qsc/channel.py` | `test_v2_survives_a_lost_message` |
| Bob added no randomness to the session, and the version and identities were not in the key schedule | Fixed: Bob sends a signed nonce; nonce, version, identity fingerprints and the list of key sources feed HKDF | `src/qsc/channel.py` | covered by every v2 test |
| Bob never checked the version in the hello | Fixed: Bob accepts exactly one version and echoes what he heard in a signed reply | `src/qsc/channel.py` | `test_v2_aborts_if_hello_is_changed` |
| Rejections were silent | Fixed: each rejection is counted by reason (bad signature, replay, decryption failed, bad padding, too far ahead) | `SessionReport.rejections` | `test_v2_records_why_packets_were_rejected` |
| Padding length was not validated | Fixed: length and block size are checked before the plaintext is returned | `src/qsc/channel.py` | covered by v2 tests |
| The website could load anything | Fixed: Content Security Policy allows only the page's own scripts and Google Fonts, no outgoing requests, no referrer | `website/site/index.html` | checked in a browser |
| Judge plugins run with full user permissions | Documented: the lint is not a sandbox; run untrusted plugins in a container or VM | `redteam/judge.py`, `redteam/README.md` | |

### Design limits that code alone cannot fix

- **The E91 monitor and threat score are not wired to the traffic.** Each verification runs a fresh, independent Bell-pair simulation; the caller decides whether it is "attacked". It illustrates the idea but is not evidence about the channel the packet used. A real system would feed the monitor from the same quantum link.
- **The default Bell monitor is small.** Bob's monitor compares about 32 of 64 pairs, so a full intercept-resend stays under the 15% threshold several percent of the time by chance. Size the sample from the miss rate you can accept (two flaky tests were traced to this and now use larger samples).
- **Quantum public keys are classical arrays.** The copy budget is bookkeeping; any code holding the register can read every amplitude, so the Holevo argument holds only for the modelled physics, not for the Python process.
- **The handshake runs both parties in one function.** Alice and Bob share variables (for example the session id), so some checks compare a value with itself. Splitting them into separate state machines, or processes, is needed before claiming protocol-level guarantees.
- **QKD can be switched off by anyone touching the fibre.** v2 then continues on ML-KEM-768 plus X25519. That is still post-quantum, but a deployment that requires the photon key should set a policy to abort instead.
- **Pinned identity keys are created per session in the simulation.** Real use needs a one-time, out-of-band key exchange and a revocation story.
- **Google Fonts sees each visitor's IP address.** Self-host the three font files to remove that.

## Rounds 3 and 4, and a new architecture (v3)

### Round 3 findings

| Finding | Status | Test |
|---|---|---|
| BB84's error-correction check sent a full 256-bit hash but counted 64 bits as leaked, so privacy amplification could leave the key longer than is safe | Fixed: the tag is now exactly 64 bits | `test_qkd_verification_tag_matches_counted_leak` |
| Key confirmation used the session key directly as a MAC key | Fixed in v2: separate confirmation and traffic keys derived by HKDF | covered by v2 tests |
| One traffic key for the whole session: if Bob replied, both directions would share keys and nonces (catastrophic for AES-GCM) | Architectural, fixed in v3 | `test_v3_directions_use_separate_keys`, `test_v3_rejects_a_record_sent_back_to_its_sender` |
| Alice and Bob shared one function and its variables | Architectural, fixed in v3 | every v3 test |
| Bespoke handshake: a signature on every message, ad-hoc key schedule, QKD silently optional | Architectural, fixed in v3 | `test_v3_any_handshake_change_aborts`, QKD policy tests |

### v3 design

- **Two independent parties.** `Party` objects hold only their own secrets; only JSON payloads cross the wire.
- **Three-message hybrid handshake**, after TLS 1.3 and hybrid post-quantum key exchange: X25519 plus ML-KEM-768 shares, a running SHA3 transcript hash, one ML-DSA-65 signature and one Finished MAC per side, with both identities inside the transcript. The session id is derived from the transcript, so neither side chooses it.
- **QKD as a policy.** BB84 runs after the handshake. Its classical messages are authenticated with per-direction MAC keys from the handshake, and its key is mixed into the master secret. `required` aborts without it; `preferred` (the default) continues post-quantum only and reports that; `off` skips it.
- **Record layer.** Separate keys, IVs and ratchets for each direction; nonce = IV xor sequence number; a skip window of 64; padding to 64 bytes; replay rejection; state committed only after a record verifies. The master secret is wiped once traffic keys exist.
- **No `assert` for security checks** (round 4): Python's `-O` flag strips them.

### Comparison (5 honest sessions each, 3 messages)

| | v1 | v2 | v3 | v3, QKD off |
|---|---|---|---|---|
| Seconds per session | 0.06 | 1.05 | 1.26 | 0.01 |
| Data on the wire | 70 kB | 1,220 kB | 387 kB | 19 kB |
| Delivered | 5/5 | 5/5 | 5/5 | 5/5 |
| Safe replies from Bob | no | no | yes | yes |
| Passive tap reads | 0.00 | 0.00 | 0.00 | 0.00 |

**Recommendation: v3.** It is the only version with independent parties and separate keys per direction. It uses a third of v2's traffic, and its handshake follows an established pattern instead of a bespoke one. Use `Policy(qkd="required")` wherever a photon link is expected, so that interference with the fibre stops the session instead of quietly downgrading it.

### Still open after v3

- BB84 post-processing still runs as one simulated function for both parties (now authenticated with per-party MAC keys); splitting it into two state machines is the next structural step.
- v3 authenticates parties and messages but does not give per-message non-repudiation. If that is needed, sign each message with the GC quantum signature or ML-DSA inside the encrypted record (sign, then encrypt).
- Identity keys are still created per session in the simulation.

## Round 5: reliability under repetition

Running the whole suite repeatedly exposed four problems that only show up
some of the time. All are fixed; the suite passed five consecutive runs (206 tests).

| Finding | Fix | Test |
|---|---|---|
| Error correction occasionally leaked more than twice the usual parity (2,083 bits against about 850) and left no secret key on a clean fibre (about 1 session in 30). A correction could flip a bit inside another block's half-finished binary search, which then acted on stale answers and flipped a correct bit | Any block touched by a flip restarts its search from the whole block. 60 of 60 sessions now produce a photon key; worst leak 1,030 bits, smallest key 769 bits | `test_error_correction_leak_stays_bounded` |
| The Bell monitor compared about 50 pairs, so a full intercept-resend stayed under the 15% alarm about 4% of the time | Circuits run in one batched simulator call; default raised from 100 to 400 pairs (Bob's from 64). Missed 0 of 40 eavesdroppers, 0 false alarms in 40 clean runs, 0.075 s per check | `test_scenario_6_e91_disturbance`, `test_intercept_resend_detected_by_e91` |
| The tampered-key test replaced 10 of 16 keys and claimed a chance below 0.1%; the real chance was about 5% | Replaces all 32 keys (about 1 in 100,000) | `test_qds_verify_tampered_key` |
| A QKD abort discarded the statistics needed to diagnose it | Aborts now carry their statistics into the session report | used by the leak test |
