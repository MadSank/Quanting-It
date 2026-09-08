# Gottesman–Chuang Quantum Digital Signature (QDS) Protocol Flow

This document details the complete end-to-end execution flow of the Quatinit Gottesman–Chuang QDS prototype architecture.

---

### Phase 1: Key Generation & Distribution (Alice)
1. **Classical Private Keys:**
   Alice generates $M$ pairs of $L$-bit random classical keys:
   $$\mathcal{K} = \left\{ \left(k_0^i, k_1^i\right) \right\}_{i=0}^{M-1}, \quad k_b^i \in \{0, 1\}^L$$

2. **Quantum Fingerprint Preparation (QOWF):**
   Alice expands each key $k$ using a deterministic pseudorandom codeword/fingerprint encoding for the prototype into an $N$-bit codeword $E(k)$ ($N = 2^n$) and prepares $n$-qubit phase-encoded states:
   $$\left|f_{k_b^i}\right\rangle = \frac{1}{\sqrt{N}} \sum_{j=0}^{N-1} (-1)^{E(k_b^i)_j} |j\rangle$$

3. **Quantum Public Key Distribution (Teleportation Transport Layer):**
   - Alice creates $T$ copies of each state: $T \le 4$ ensures an accessible-information budget bounded by $T \cdot n$ bits and a positive entropy gap ($\Delta H = L - T \cdot n = 96 \text{ bits} > 0$).
   - Alice distributes copies to Bob and Charlie using quantum teleportation as a quantum transport adaptation layer:
     - Alice and verifier share Bell pairs $\left|\Phi^+\right\rangle = \frac{1}{\sqrt{2}}(|00\rangle + |11\rangle)$.
     - Alice performs Bell-basis measurement on the fingerprint qubit and her Bell qubit, yielding classical correction bits $(crz, crx)$.
     - Verifier applies Pauli correction $Z^{crz} X^{crx}$ to reconstruct $\left|f_{k_b^i}\right\rangle$ in their quantum register.
   - Bob and Charlie store the copies in their local `VerifierKeyRegister`.

---

### Phase 2: Signing (Alice)
1. **Message Hashing & Domain Binding:**
   Alice computes the session-salted digest:
   $$h = \text{SHA-256}(m \parallel \text{session\_id} \parallel \text{challenge} \parallel \text{seq})$$

2. **Bit Mapping:**
   The digest is mapped to $M$ message bits: $b = (b_0, b_1, \dots, b_{M-1}) \in \{0, 1\}^M$.

3. **Private Key Revelation:**
   Alice reveals the classical key corresponding to each message bit:
   $$\sigma_{\text{QDS}} = \left( m, \left\{ k_{b_i}^i \right\}_{i=0}^{M-1} \right)$$
   *(Note: Alice does NOT reveal the complement keys $k_{1 - b_i}^i$; their information remains protected under the Holevo accessible information budget).*

4. **Auxiliary Classical Transcript Authentication:**
   Alice signs the canonical transcript using NIST ML-DSA-65 to provide classical control-plane authentication during transit (note: ML-DSA provides classical computational authentication only and is not the QDS itself):
   $$\sigma_{\text{PQC}} = \text{ML-DSA-Sign}(\text{transcript}, sk_{\text{Alice}})$$

5. **Packet Assembly:**
   Alice transmits the `SecurePacket` to Bob containing $(m, h, \sigma_{\text{QDS}}, \sigma_{\text{PQC}}, \text{metadata})$.

---

### Phase 3: Verification (Bob — Primary Verifier)
1. **Classical Layer Checks:**
   - Layer 1: Active session validation.
   - Layer 2: Sequence number freshness check (replay protection).
   - Layer 3: Classical hash check $h \stackrel{?}{=} \text{SHA-256}(\dots)$.
   - Layer 3.5: ML-DSA classical signature verification over canonical transcript.

2. **Quantum SWAP Test Verification:**
   - For each position $i \in \{0, \dots, M-1\}$:
     1. Bob takes candidate key $k_{\text{candidate}} = k_{b_i}^i$ from the signature.
     2. Bob prepares fresh quantum state $\left|f_{k_{\text{candidate}}}\right\rangle$ via the deterministic forward QOWF.
     3. Bob consumes his stored public key copy $\left|f_{k_{b_i}^i}\right\rangle$ from his `VerifierKeyRegister` (modeled through explicit logical resource accounting).
     4. Bob executes a controlled-SWAP circuit on an ancilla qubit between the fresh state and the stored copy.
     5. Bob measures the ancilla: outcome $|0\rangle$ indicates match; outcome $|1\rangle$ indicates mismatch.
   - Bob calculates total mismatches $s_B$.

3. **Three-Outcome Decision Logic:**
   - If $s_B \le c_1 \cdot M$: **`1-ACC`** (Signature accepted and transferable).
   - If $c_1 \cdot M < s_B < c_2 \cdot M$: **`0-ACC`** (Signature accepted locally, but transferability not guaranteed).
   - If $s_B \ge c_2 \cdot M$: **`REJ`** (Signature rejected).

---

### Phase 4: Transferability (Bob to Charlie)
1. Bob forwards the classical message and revealed keys $\sigma_{\text{QDS}}$ to Charlie.
2. Charlie independently verifies the revealed keys against Charlie's own stored quantum public key copies via SWAP tests.
3. Charlie accepts if mismatches $s_C \le c_2 \cdot M$.
4. **Transferability & Repudiation:** The threshold gap $c_2 - c_1$ is the mechanism used to create a statistical transferability region. The actual repudiation probability depends on protocol assumptions and measured mismatch distributions (measured at $\approx 0.35\%$ for prototype parameters $M=32, c_1=1, c_2=8$).

---

### Phase 5: Continuous Threat Scoring
The Threat Engine evaluates:
- $\text{Mismatch Rate} \le c_1$
- $\text{E91-Inspired Bell Correlation Error Rate} \le 15\%$
- $\text{Classical Checks} = \text{All True}$
- $\text{Copy Available} = \text{True}$

Produces continuous `ThreatScore` with classification into `PREVENTED`, `DETECTED`, `MITIGATED`, `NOT_DETECTABLE`, or `OUT_OF_SCOPE`.
