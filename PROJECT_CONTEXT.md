# PROJECT CONTEXT: QUATINIT
## SIH 2026 Problem Statement 26141

**CANONICAL REPOSITORY GROUND TRUTH**  
All architectural statements herein are backed by automated tests in `tests/` executed against Qiskit Aer simulation.

---

## 1. PROJECT IDENTITY
**Project Name:** Quatinit  
**Problem Statement:** 26141 — *Quantum-Inspired Cyber Threat Detection for Digital Signature Security*  
**Category:** Software (Blockchain & Cybersecurity)  
**Implementation Stage:** Working Prototype (Software Simulation)

**What is Quatinit trying to address?**
As quantum computing algorithms advance, traditional asymmetric schemes (RSA, ECC) are vulnerable to Shor's algorithm. Post-quantum cryptographic algorithms (such as NIST ML-DSA-65) address computational hardness against classical and quantum cryptanalysis, but classical communication remains exposed to transmission-level manipulation, replay, and eavesdropping.

Quatinit models a **Gottesman–Chuang (GC) style Quantum Digital Signature (QDS)** architecture integrated with a multi-layer statistical cyber-threat detection engine. The system explores information-theoretic bounds (Holevo theorem accessible information), single-use public key copy budgeting, quantum teleportation transport adaptation, and auxiliary post-quantum transcript authentication.

**What Quatinit IS:**
*   A functional **Three-Party Gottesman–Chuang QDS Prototype** (Alice, Bob, Charlie) running on Qiskit Aer.
*   **Asymmetric Signing Material:** Alice alone possesses classical private keys $k_b^i$; Bob and Charlie possess non-orthogonal quantum public keys $|f_{k_b^i}\rangle$.
*   **Deterministic Pseudorandom Codeword Encoding (QOWF):** HMAC-SHA256 phase-encoded quantum fingerprints with exponential compression ($L \gg n$).
*   **Destructive SWAP Test Verification:** Real Qiskit controlled-SWAP test circuits with single-shot execution.
*   **Explicit Copy Budget Accounting:** Programmatic modeling of finite quantum public key copy budgets (`CopyBudget`, $T < L/n$).
*   **Teleportation Transport Adaptation Layer:** Bell pairs with conditional Pauli corrections ($Z^{crz} X^{crx}$) for quantum public key distribution.
*   **Three-Outcome Decision Logic:** ($c_1, c_2$) thresholds establishing a statistical transferability region.
*   **Statistical Threat Engine:** Continuous binomial confidence evaluation and empirical attack benchmarking.

**Explicit Scope & Limitations (What Quatinit is NOT):**
*   **Simulation Only:** It runs on Qiskit Aer numerical simulators, **not** on physical quantum hardware.
*   **Prototype Scale:** Parameters ($M=32, n=8, L=128$) are calibrated for simulation; they do **not** claim production cryptographic security.
*   **Transport Only:** Teleportation is an adaptation transport layer, **not** part of the original Gottesman–Chuang security proof.
*   **Inspired Monitoring:** The E91 component provides **E91-inspired Bell-correlation channel monitoring**, not a complete E91 QKD protocol.
*   **Classical Transcript Auth:** NIST ML-DSA-65 provides classical control-plane authentication, **not** the QDS itself.

---

## 2. SUMMARY DESCRIPTION
Quatinit demonstrates digital signature security rooted in quantum state discrimination. Alice signs messages by releasing classical private keys that verifiers test against distributed quantum public keys using destructive controlled-SWAP tests. Under Holevo's theorem, an adversary with $T$ copies of an $n$-qubit public state has an accessible-information budget bounded by $T \cdot n$ bits, leaving an entropy gap $\Delta H = L - T \cdot n > 0$ that prevents unique private key reconstruction. Forgery is detected through SWAP test mismatch statistics ($p \approx 0.5$ per position for incorrect keys). Public key states are transported via quantum teleportation channels, classical transcripts are authenticated via NIST ML-DSA-65, and channel integrity is monitored via E91-inspired Bell correlation checks.

---

## 3. CORE PROTOCOL WORKFLOW
1.  **Key Generation (`gc_keys.py`):**
    *   Alice generates $M$ pairs of $L$-bit classical private keys: $\{(k_0^i, k_1^i)\}_{i=0}^{M-1}$.
    *   Alice prepares $n$-qubit phase-encoded quantum public keys $|f_{k_b^i}\rangle$ via the QOWF ($N=2^n$ dimensions).
2.  **Quantum Public Key Distribution (`alice.py`, `teleportation.py`):**
    *   Alice distributes a finite copy budget of $T$ public key copies to Bob and Charlie.
    *   Distribution is adapted over quantum channels via Bell pairs and conditional Pauli corrections.
    *   Verifiers store copies in a `VerifierKeyRegister`.
3.  **Message Signing (`qds_signer.py`):**
    *   Alice hashes the message and binds it to session state (`session.py`, `crypto.py`).
    *   The message is encoded into $M$ bits $b = (b_0, \dots, b_{M-1})$.
    *   Alice reveals the classical keys corresponding to the message bits: $\{k_{b_i}^i\}_{i=0}^{M-1}$.
    *   An auxiliary ML-DSA-65 post-quantum signature binds the canonical transcript.
4.  **Verification via SWAP Test (`qds_verifier.py`, `swap_test.py`):**
    *   Bob verifies classical session state, sequence number, and hash binding.
    *   For each position $i$, Bob uses the revealed key $k_{b_i}^i$ to compute $|f_{k_{b_i}^i}\rangle$.
    *   Bob consumes his stored quantum public key copy and runs a controlled-SWAP test against the computed state.
    *   Bob counts failed SWAP tests $s_B$.
5.  **Threshold Evaluation & Transferability (`threat_engine.py`, `threshold_calibration.py`):**
    *   If $s_B \le c_1 \cdot M$: Signature is accepted as `1-ACC` (valid and transferable).
    *   Bob can transfer the signature to Charlie. Charlie verifies against his own register using threshold $c_2$.
    *   If $s_C \le c_2 \cdot M$: Charlie accepts (`0-ACC` or `1-ACC`).
    *   Threshold gap $c_2 - c_1$ establishes a statistical transferability region.
6.  **Threat Assessment (`threat_engine.py`):**
    *   Continuous statistical evaluation generates a `ThreatScore` and classifies detected attacks.

---

## 4. CODEBASE STRUCTURE & CORE MODULES

| Module | Responsibility | Key Classes / Functions |
| :--- | :--- | :--- |
| `src/qowf.py` | Quantum One-Way Function | `encode()`, `prepare_statevector()`, `quantum_fingerprint_overlap()` |
| `src/swap_test.py` | Controlled-SWAP circuits | `build_swap_test_circuit()`, `run_swap_test()`, `run_single_shot_swap_test()` |
| `src/gc_keys.py` | Key material & Copy Budget | `GCKeyGenerator`, `GCKeyPair`, `PublicKeyCopy`, `CopyBudget`, `VerifierKeyRegister` |
| `src/qds_signer.py` | GC Signature Generation | `GCSigner`, `GCSignature`, `sign_message()` |
| `src/qds_verifier.py` | GC Signature Verification | `GCVerifier`, `GCVerificationResult`, `VerificationOutcome` |
| `src/alice.py` | Signer Orchestration | `Alice.distribute_public_keys()`, `Alice.create_packet()` |
| `src/bob.py` | Verifier Orchestration | `Bob.verify_packet()`, `Bob.receive_public_keys()` |
| `src/eve.py` | Attack Simulation | `Eve.forge_gc_signature()`, `Eve.tamper_revealed_key()`, `Eve.substitute_public_key()` |
| `src/threat_engine.py` | Statistical Threat Scoring | `GCForgeryModel`, `GCThreatScorer`, `ThreatScore`, `ThreatScorer` |
| `src/threshold_calibration.py`| Threshold Calibration | `ThresholdCalibrator`, `CalibrationReport` |
| `src/teleportation.py` | Teleportation Transport Layer | `create_teleportation_circuit()`, `teleport_fingerprint_state()` |
| `src/e91_monitor.py` | Bell Correlation Monitoring | `E91Monitor.measure_disturbance()` |
| `src/attack_simulator.py` | Attack Suite Execution | `AttackSimulator.run_attack()` |
| `src/metrics.py` | Results & Classifications | `AttackResult`, `AttackType`, `DefenseStatus`, `SecurityMetrics` |
| `src/session.py` | Session Management | `SessionManager`, `Session` |
| `src/packet.py` | Wire Format | `SecurePacket` |

---

## 5. VALIDATION SUITE SUMMARY
The entire codebase is validated via `pytest tests/ -v`:
*   **Total Tests:** 136 tests across 21 test modules
*   **Failures:** 0
*   **Pass Rate:** 100%
*   **Hadamard Inversion Disproof:** Preserved in `tests/test_qowf.py::TestHadamardNegative::test_original_hadamard_qowf_is_trivially_invertible`
