# Hybrid Protocol Flow Documentation

The following is the detailed step-by-step documentation for the Hybrid Session-Based Quantum Authentication framework.

### 1. Classical Setup [CLASSICAL CRYPTOGRAPHY]
Alice formulates a classical message:
`MESSAGE`
↓
Alice computes a cryptographically secure hash of the message over the session variables:
`SHA-256 MESSAGE HASH` = `Hash(Message || Session ID || Challenge || Sequence Number)`
↓

### 2. Post-Quantum Signature [PQ CRYPTOGRAPHY]
Alice signs the Message Hash using her Post-Quantum Private Key.
`PQ SIGNATURE` = `ML-DSA-Sign(Message Hash, Private Key)`
↓

### 3. Quantum Context Setup [EXPERIMENTAL DESIGN]
Alice and Bob share a secret, entanglement-derived authentication context.
`SESSION AUTHENTICATION CONTEXT`
↓
The message hash and the session context are combined to generate a unique, non-reversible binding.
`AUTHENTICATION BINDING` = `HKDF(Message Hash, Session Context)`
↓

### 4. Quantum Fingerprint Generation [QUANTUM MECHANICS]
The authentication binding is mapped deterministically to a specific quantum proof specification consisting of a set of bases (X or Z) and states (0 or 1).
`DETERMINISTIC QUANTUM PROOF SPECIFICATION`
↓
Alice prepares a set of qubits corresponding exactly to this proof specification.
`QUANTUM STATE PREPARATION`
↓

### 5. Transmission & Monitoring [QUANTUM MECHANICS]
Alice teleports the quantum states to Bob.
Simultaneously, the underlying entanglement generation channel is monitored for disturbances (e.g., Eve attempting to measure passing qubits) using an E91-inspired protocol.
`TELEPORTATION` & `E91 CHANNEL MONITORING`
↓

### 6. Verification Pipeline [EXPERIMENTAL DESIGN]
Bob independently receives the `MESSAGE`, `PQ SIGNATURE`, and `QUANTUM FINGERPRINT`.
Bob evaluates a strict 6-step verification pipeline:
1. **Session Match**: Ensures Alice and Bob are in the same active session.
2. **Replay Check**: Ensures the sequence number hasn't been consumed.
3. **Classical Hash**: Matches the received message to the expected hash.
4. **PQ Signature**: Validates `ML-DSA-Verify(Message Hash, Signature, Public Key)`.
5. **Quantum Fingerprint**: Bob measures the quantum states in the derived bases and ensures the results match perfectly.
6. **E91 Channel Check**: Ensures the channel disturbance error rate is < 15%.

### 7. Decision
`ACCEPT / REJECT`
If all 6 layers pass, Bob accepts the packet. If any layer fails, Bob rejects the packet and logs the specific layer where the tamper was detected.
