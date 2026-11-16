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
