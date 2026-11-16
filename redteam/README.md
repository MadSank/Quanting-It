# Red-Team Arena

A sender (blue team) and an attacker (red team) compete over the Quantum-Safe
Channel in `src/qsc/`. Each round the attacker hunts for ways to read or forge
messages, the protocol is hardened, and every old attack is re-run against the
new version as a regression test.

| Path | What it is | Who may read it |
|---|---|---|
| `src/qsc/` | Protocol under test (BB84 QKD, PQ KEMs, AEAD data plane) | everyone (Kerckhoffs) |
| `redteam/sender.py` | Sends real messages, saves wire captures | everyone |
| `redteam/judge.py` | Scores attack plugins with hidden plaintexts | everyone |
| `redteam/captures/` | What an eavesdropper recorded | everyone |
| `redteam/secrets/` | Hidden plaintext corpus and ground truth | **sender & judge only** |
| `redteam/attacks/` | Attack plugins (`class Attack(Adversary)`) | everyone |
| `redteam/results/` | Judge output per attack | everyone |

## Threat model

Eve controls the network:

* **Classical channel**: sees every envelope; may modify, drop or inject
  (`on_classical`, `forge`).
* **Quantum channel**: receives Alice's pulses at her output port
  (`on_quantum`). She may count photons (QND), split photons from multi-photon
  pulses, measure in any basis, block pulses, forward over a lossless line,
  or prepare her own pulses. She may **not** read private photon fields
  (`_bit`, `_basis`).
* **Harvest now, decrypt later**: in `recover()` she has a simulated
  cryptographically relevant quantum computer: `self.ctx.shor.break_x25519(pub_hex)`
  returns the X25519 private key. Lattice schemes (ML-KEM, ML-DSA) and AES-256
  are not broken by it.

Eve does not get Alice's or Bob's long-term private keys or RNG state, and
cannot read process memory. The judge rejects plugins that use `gc`, `inspect`,
frame introspection, `ctypes`, the oracle registry or the secrets folder.

## Scoring

`python -m redteam.judge redteam/attacks/<file>.py --versions v0 v1 --trials 3 --save`

* `conf_break`: fraction of hidden plaintexts Eve reproduced exactly
* `forged`: messages Bob accepted that Alice never sent (including replays)
* `detected`: session aborted, or Bob rejected a packet
* `delivered`: fraction of Alice's messages Bob received intact (an attack
  with low delivery and high detection is a denial of service, not a break)
