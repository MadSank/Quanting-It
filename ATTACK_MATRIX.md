# Threat Matrix & Defense Classification: Quatinit QDS Prototype

**Framework:** SIH 2026 Problem Statement 26141 — *Quantum-Inspired Cyber Threat Detection for Digital Signature Security*  
**Environment:** Software simulation prototype (Qiskit Aer), prototype-scale parameters ($L=128, n=8, M=32$).  
**Classification System:**
- **`PREVENTED`**: Structurally prevented by protocol design constraints (e.g., Holevo accessible-information bounds, single-use copy budget accounting).
- **`DETECTED`**: Attack is executed by the adversary and identified by the verification pipeline (e.g., SWAP test mismatch, hash verification, sequence tracking).
- **`MITIGATED`**: Attack effect is bounded by design tolerance (e.g., channel noise tolerated below $c_1$).
- **`NOT_DETECTABLE`**: Attack cannot be observed at this specific layer (e.g., passive classical wiretapping without tampering).
- **`OUT_OF_SCOPE`**: Threat vector outside the defined communication/cryptographic scope (e.g., side-channel power analysis).

---

## Complete Threat Vector Matrix

| # | Threat Vector | Target Component | Defense Classification | Detection Mechanism | Test Validation Reference | Status |
| :-: | :--- | :--- | :-: | :--- | :--- | :-: |
| **1** | **Direct Signature Forgery** | Private key revelation | `DETECTED` | SWAP test against Bob's registered public keys. Adversary's candidate key has overlap $\approx 0$, yielding $\approx 50\%$ mismatch rate $\gg c_1$. | `tests/test_forgery.py`, `tests/test_gc_protocol.py::TestForgery` | **VALIDATED** |
| **2** | **Key Inversion / Extraction** | Quantum public keys | `PREVENTED` | Holevo accessible-information budget: $T=4$ copies of $n=8$ qubits yield $\le 32$ bits of mutual information. Entropy gap $\Delta H = 128 - 32 = 96$ bits ensures key secrecy; forgery probability is bounded by SWAP test binomial distribution. | `tests/test_gc_keys.py::TestKeyGeneration::test_holevo_margin`, `tests/test_forgery.py` | **VALIDATED** |
| **3** | **Unauthorized Signature Replay** | Verification state | `DETECTED` | Dual-layer: (1) Single-use public key copy consumed upon first SWAP test; (2) Session sequence number increments and rejects stale indices. | `tests/test_replay.py`, `tests/test_gc_protocol.py::TestReplay` | **VALIDATED** |
| **4** | **Copy Budget Depletion** | Quantum memory model | `PREVENTED` | Finite quantum public-key copy budget modeled through explicit logical resource accounting (`CopyBudget`). Distribution beyond $T < L/n$ or reuse triggers `RuntimeError`. | `tests/test_gc_keys.py::TestCopyBudget`, `tests/test_gc_protocol.py::TestCopyManagement` | **VALIDATED** |
| **5** | **Message Content Tampering** | Classical payload | `DETECTED` | SHA-256 session-salted hash check detects bit changes; re-encoded message bits diverge from revealed keys, causing immediate verification abort. | `tests/test_hash_integrity.py`, `tests/test_gc_protocol.py::TestWrongMessage` | **VALIDATED** |
| **6** | **Hash Binding Tampering** | Classical digest | `DETECTED` | Bob computes expected hash $H(m \parallel \text{sess} \parallel \text{chal} \parallel \text{seq})$. Any mismatch immediately aborts at Layer 3. | `tests/test_hash_integrity.py`, `tests/test_end_to_end_security.py` | **VALIDATED** |
| **7** | **Single-Position Key Tampering** | Revealed key string | `DETECTED` | Changing a single revealed key $k_i$ causes SWAP test at position $i$ to fail. Exceeding $c_1$ threshold triggers rejection. | `tests/test_gc_protocol.py::TestForgery::test_single_position_forgery` | **VALIDATED** |
| **8** | **Impersonation Attack** | Signer identity | `DETECTED` | Eve creates a signed packet without Alice's private keys. SWAP test fails against Bob's registered public keys from Alice. | `tests/test_end_to_end_security.py::test_scenario_4_impersonation` | **VALIDATED** |
| **9** | **Public Key Substitution** | Verifier register | `DETECTED` | Substituting a public key state $|f_k\rangle$ causes honest signature revealed keys to mismatch with the substituted state during SWAP testing. | `tests/test_gc_protocol.py::TestPublicKeySubstitution` | **VALIDATED** |
| **10** | **Quantum Channel Noise** | Teleported state | `MITIGATED` | Depolarizing noise below error tolerance is absorbed by calibrated acceptance threshold $c_1$. Severe noise triggers rejection. | `tests/test_gc_protocol.py::TestChannelNoise`, `tests/test_threshold_calibration.py` | **VALIDATED** |
| **11** | **Pauli-X Channel Attack** | Teleported state | `DETECTED` | Bit-flip error on fingerprint qubits alters amplitude signs, degrading state overlap; SWAP test flags mismatch. | `tests/test_teleportation.py`, `tests/test_gc_protocol.py::TestCorrectionAttacks` | **VALIDATED** |
| **12** | **Pauli-Z Channel Attack** | Teleported state | `DETECTED` | Phase-flip error directly alters phase-encoded codeword coefficients, reducing overlap; SWAP test flags mismatch. | `tests/test_teleportation.py`, `tests/test_gc_protocol.py::TestCorrectionAttacks` | **VALIDATED** |
| **13** | **Pauli-Y Channel Attack** | Teleported state | `DETECTED` | Simultaneous bit- and phase-flip maximally disturbs fingerprint statevector; SWAP test flags mismatch. | `tests/test_teleportation.py`, `tests/test_gc_protocol.py::TestCorrectionAttacks` | **VALIDATED** |
| **14** | **Intercept-Resend Attack** | Quantum channel | `DETECTED` | Intercept-resend measurement collapses entanglement, causing $25\%$ error rate on E91-inspired monitor and collapsing public key fidelity. | `tests/test_e91_monitor.py`, `tests/test_teleportation.py` | **VALIDATED** |
| **15** | **Bell-Correlation Disturbance**| Entanglement bus | `DETECTED` | E91-inspired correlation monitor evaluates matched-basis Bell measurements; disturbance $> 15\%$ error rate aborts session. | `tests/test_e91_monitor.py`, `tests/test_gc_protocol.py::TestBellMonitoring` | **VALIDATED** |
| **16** | **Repudiation Attempt** | Transferability | `PREVENTED` | Threshold gap $c_2 - c_1$ creates a statistical transferability region; repudiation probability is bounded under measured binomial mismatch distributions. | `tests/test_gc_protocol.py::TestRepudiation`, `tests/test_gc_protocol.py::TestTransferability` | **VALIDATED** |
| **17** | **Cross-Session Proof Reuse** | Session boundary | `DETECTED` | Signature tied to unique `session_id` and sequence number; verification in a different session fails session check or transcript verification. | `tests/test_end_to_end_security.py::test_scenario_8_cross_session` | **VALIDATED** |
| **18** | **Compromised Session Context** | Stolen Session ID | `DETECTED` | Invalid sequence number or unsynchronized challenge triggers Layer 1/Layer 2 session rejection. | `tests/test_end_to_end_security.py::test_scenario_9_compromised_context` | **VALIDATED** |
| **19** | **Transcript Tampering** | Classical ML-DSA | `DETECTED` | Modifying the canonical transcript or signature invalidates NIST ML-DSA-65 classical cryptographic verification. | `tests/test_classical_channel.py`, `tests/test_gc_protocol.py::TestTranscriptTampering` | **VALIDATED** |
| **20** | **Passive Wiretapping** | Public classical wire | `NOT_DETECTABLE` | Passive eavesdropping on public classical channel reveals only already-public transcripts and revealed keys for verified messages. | Information-theoretic analysis: Forward secrecy of one-way function | **BY DESIGN** |

---

## Multi-Architecture Security Comparison

As empirically demonstrated in `tests/test_security_experiments.py`:

| Threat Vector | Architecture A<br>(Classical Hash + Seq) | Architecture B<br>(Pure PQC / ML-DSA) | Architecture C<br>(QDS Only) | Architecture D<br>(Quatinit: GC QDS + E91 Monitoring) |
| :--- | :---: | :---: | :---: | :---: |
| **Message Tampering** | DETECTED | DETECTED | DETECTED | **DETECTED** |
| **Direct Forgery** | NOT DETECTED | DETECTED | DETECTED | **DETECTED (SWAP Test Overlap)** |
| **Quantum Channel Interception** | NOT DETECTED | NOT DETECTED | DETECTED (SWAP) | **DETECTED (SWAP + Bell Monitor)** |
| **Entanglement Disturbance** | NOT DETECTED | NOT DETECTED | NOT DETECTED | **DETECTED (E91-Inspired Monitor)** |
| **Key Extraction / Inversion** | VULNERABLE | COMPUTATIONAL (Lattice) | PREVENTED (Holevo) | **PREVENTED (Holevo Info Budget)** |
| **Repudiation** | VULNERABLE | VULNERABLE | PREVENTED (c1 < c2) | **PREVENTED (Statistical Transferability)** |
| **Copy Reuse (No-Cloning)** | N/A | N/A | PREVENTED | **PREVENTED (Copy Accounting)** |
