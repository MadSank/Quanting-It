# Hybrid Post-Quantum + Quantum Authentication Framework

An educational experimental framework exploring the intersection of **Post-Quantum Cryptography (ML-DSA)**, classical session management, and **Quantum State-Based Authentication (Quantum Fingerprinting, E91 Monitoring)**.

## Problem
In a post-quantum world where classical public-key cryptography (like RSA or ECC) may be broken by Shor's algorithm, maintaining the integrity and authenticity of messages is a critical challenge. This project proposes a hybrid, layered approach that combines the deterministic security of Post-Quantum Signatures (like ML-DSA) with the tamper-evident properties of Quantum Mechanics.

## What the System Does
1. **Alice** prepares a classical message.
2. The message is hashed and bound to a session challenge/sequence number.
3. Alice signs the hash using a **Post-Quantum Digital Signature** (ML-DSA). *(Note: A structural mock `DEMO_PQ_SIGNER` is currently implemented).*
4. Shared, quantum-correlated material generates a session authentication context.
5. The classical binding is combined with the authentication context to deterministically generate a **Quantum Fingerprint** (e.g., `|0>`, `|1>`, `|+>`, `|->`).
6. These quantum proof states are transferred to Bob using quantum teleportation.
7. An **E91-inspired Monitor** tracks the general disturbance in the entanglement channel.
8. **Bob** receives the message and executes a **6-Layer Verification Pipeline**:
   - Session & State Check
   - Replay Protection Check
   - SHA-256 Integrity Check
   - PQ Signature Validation
   - Quantum Fingerprint Measurement & Validation
   - E91 Channel Integrity Check

## Attack Model
This framework tests against several classical and quantum adversarial behaviors, simulated via the Eve Attack Lab:
- **MESSAGE_TAMPERING**: Detected at Classical Hash layer.
- **SIGNATURE_TAMPERING**: Detected at PQ Signature layer.
- **REPLAY**: Detected at Sequence/Replay layer.
- **PROOF_SUBSTITUTION**: Detected due to Quantum Fingerprint mismatch.
- **CROSS_SESSION_REUSE**: Detected due to Context binding.
- **INTERCEPT_RESEND**: Highly detectable due to quantum disturbance. Caught by Quantum Fingerprint or E91 Monitor.
- **QUANTUM_X / QUANTUM_Z**: Pauli-level interference on the quantum states.

## How to Run
Activate your environment and run the following:

**Run the CLI Demo:**
```bash
.venv\Scripts\python demo.py
```

**Run the Streamlit Dashboard (5 Tabs!):**
```bash
.venv\Scripts\streamlit run app.py
```

**Run the Test Suite (40+ Passing Tests!):**
```bash
.venv\Scripts\python -m pytest tests/
```

## Scientific Limitations
1. **Simulation Only:** This project relies on `qiskit_aer` simulators.
2. **Mock PQ Signature:** We use a structural placeholder (`DEMO_PQ_SIGNER`) that uses ECDSA underneath. It is structurally identical to ML-DSA but does NOT provide mathematical post-quantum security.
3. **Orbital Encoding:** The experimental 2^N classical -> 3^M orbital state mapping demonstrates intentional collisions.
4. **Not Production Ready:** This is an experimental proof-of-concept.
