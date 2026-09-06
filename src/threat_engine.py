"""
[STATISTICAL THREAT ENGINE — CENTERPIECE DELIVERABLE]

Implements the forgery-probability model and statistical threat scoring.
This is what makes the framework a "threat detection" system, not just
a signature scheme.

Contains:
- ForgeryModel: Derived mathematical bound on forgery probability
- ThreatScorer: Continuous statistical evaluation of verification results
- ThreatScore: Comprehensive per-layer confidence output

NON-REPUDIATION LIMITATION (QMAC ACKNOWLEDGMENT):
Because the session auth context is symmetrically shared between Alice
and Bob, Bob can independently derive the signing specification and
prepare identical quantum states. This means Bob could forge a signature
and claim it came from Alice — the protocol provides authentication
(outsider cannot forge) but NOT non-repudiation (insider can forge).
Formally, this is a Quantum Message Authentication Code (QMAC), not a
full Quantum Digital Signature with non-repudiation.

A full QDS with non-repudiation requires a 3-party protocol where Alice
distributes states to both Bob (verifier) and Charlie (arbiter), who
perform a Swap Test to detect discrepancies.
"""

import math
from dataclasses import dataclass, field
from typing import Optional
from scipy.stats import binom


@dataclass
class ThreatScore:
    """
    Comprehensive threat assessment from the statistical evaluation pipeline.
    Every field provides continuous statistical information, not binary pass/fail.
    """
    # QDS signature verification
    qds_mismatch_rate: float
    qds_threshold: float
    qds_forgery_bound: float
    qds_security_bits: int
    qds_n_qubits: int
    qds_n_mismatches: int

    # E91 channel integrity
    e91_error_rate: float
    e91_threshold: float

    # Classical checks
    classical_hash_valid: bool
    correction_bits_valid: bool
    session_valid: bool
    replay_valid: bool
    ml_dsa_valid: bool

    # Aggregate assessment
    overall_confidence: float  # 0.0 to 1.0
    threat_assessment: str  # Human-readable summary

    # Protocol model transparency
    protocol_model: str = "TWO_PARTY_QMAC"
    non_repudiation_warning: str = (
        "Symmetric key sharing means verifier could forge. "
        "Non-repudiation requires 3-party QDS with arbiter (Alice→Bob+Charlie, Swap Test)."
    )

    is_accepted: bool = True


class ForgeryModel:
    """
    Derived mathematical model for forgery probability.

    For an adversary without the correct quantum key material:
    - Each qubit is a Pauli eigenstate in Z or X basis.
    - Adversary must guess the basis and the state.
    - Per-qubit forgery success probability:
      If Eve guesses the basis correctly (50%), she guesses the state correctly 50% of the time (0.5 * 0.5 = 0.25).
      If Eve guesses the wrong basis (50%), she produces a random outcome upon Bob's measurement (0.5 * 0.5 = 0.25).
      Total success probability = 0.25 + 0.25 = 0.50.

    For n signature qubits with acceptance threshold t:
    P_forge(n, t) = P(X <= t) where X ~ Binomial(n, 1 - p_forge)
    i.e., the probability that a forger produces <= t mismatches,
    where each qubit independently mismatches with probability 0.50.
    """

    # Default adversary per-qubit success probability
    DEFAULT_ADVERSARY_SUCCESS = 0.50  # Probability of matching per qubit

    @staticmethod
    def compute_forgery_bound(n_qubits: int, threshold: float,
                              adversary_success: float = 0.50) -> float:
        """
        Compute the probability that a forger produces ≤ threshold fraction
        of mismatches.

        Args:
            n_qubits: Number of signature qubits
            threshold: Maximum acceptable mismatch fraction (e.g., 0.05)
            adversary_success: Per-qubit success probability for the adversary

        Returns:
            Forgery probability bound (float)
        """
        max_mismatches = int(math.floor(n_qubits * threshold))
        # Adversary mismatch probability per qubit
        adversary_mismatch_prob = 1.0 - adversary_success

        # P(forger has <= max_mismatches mismatches)
        # Each qubit mismatches with prob = adversary_mismatch_prob = 0.50
        # Forger wants few mismatches. P(X <= t) where X ~ Binom(n, 0.50)
        p_forge = binom.cdf(max_mismatches, n_qubits, adversary_mismatch_prob)

        return float(p_forge)

    @staticmethod
    def compute_security_level(n_qubits: int, threshold: float,
                               adversary_success: float = 0.50) -> int:
        """
        Compute security level in bits: -log₂(P_forge).

        Returns:
            Number of security bits (higher is better). 0 if P_forge ≥ 1.
        """
        p_forge = ForgeryModel.compute_forgery_bound(
            n_qubits, threshold, adversary_success
        )
        if p_forge <= 0:
            return 256  # cap
        if p_forge >= 1.0:
            return 0
        return int(math.floor(-math.log2(p_forge)))

    @staticmethod
    def optimal_threshold(n_qubits: int, target_security_bits: int,
                          adversary_success: float = 0.50) -> float:
        """
        Find the maximum threshold that achieves at least target_security_bits.

        Uses binary search over threshold range [0.0, 0.25].

        Returns:
            Optimal threshold fraction
        """
        low, high = 0.0, 0.49
        best = 0.0

        for _ in range(50):  # binary search iterations
            mid = (low + high) / 2
            sec_bits = ForgeryModel.compute_security_level(
                n_qubits, mid, adversary_success
            )
            if sec_bits >= target_security_bits:
                best = mid
                low = mid
            else:
                high = mid

        # Truncate to 4 decimal places instead of rounding to avoid crossing floor boundaries
        return math.floor(best * 10000) / 10000

    @staticmethod
    def legitimate_error_rate() -> float:
        """
        Error rate for a legitimate signer in ideal noiseless simulation.
        Always 0.0 — teleportation is perfect in the simulator.
        """
        return 0.0


class ThreatScorer:
    """
    Evaluates verification results into a comprehensive ThreatScore.
    Produces per-layer confidence with human-readable threat assessment.
    """

    def __init__(self, qds_threshold: float = 0.05,
                 e91_threshold: float = 0.15):
        self.qds_threshold = qds_threshold
        self.e91_threshold = e91_threshold

    def evaluate(self, qds_mismatch_rate: float, qds_n_qubits: int,
                 qds_n_mismatches: int, correction_bits_valid: bool,
                 e91_error_rate: float,
                 classical_hash_valid: bool, session_valid: bool,
                 replay_valid: bool, ml_dsa_valid: bool) -> ThreatScore:
        """
        Produce a comprehensive ThreatScore from all verification layers.

        Args:
            qds_mismatch_rate: Aggregate QDS mismatch rate
            qds_n_qubits: Number of signature qubits
            qds_n_mismatches: Number of mismatched qubits
            correction_bits_valid: ML-DSA auth tag on correction bits
            e91_error_rate: E91 channel error rate
            classical_hash_valid: SHA-256 hash check result
            session_valid: Session state check result
            replay_valid: Replay protection check result
            ml_dsa_valid: ML-DSA signature check result

        Returns:
            ThreatScore with full statistical assessment
        """
        # Compute forgery bounds
        forgery_bound = ForgeryModel.compute_forgery_bound(
            qds_n_qubits, self.qds_threshold
        )
        security_bits = ForgeryModel.compute_security_level(
            qds_n_qubits, self.qds_threshold
        )

        # Determine acceptance
        qds_ok = qds_mismatch_rate <= self.qds_threshold
        e91_ok = e91_error_rate <= self.e91_threshold
        all_classical_ok = (
            classical_hash_valid and session_valid
            and replay_valid and correction_bits_valid
            and ml_dsa_valid
        )

        is_accepted = qds_ok and e91_ok and all_classical_ok

        # Compute overall confidence
        # Weight: QDS (40%), E91 (20%), Classical (40%)
        qds_conf = max(0.0, 1.0 - (qds_mismatch_rate / self.qds_threshold)) if self.qds_threshold > 0 else 1.0
        e91_conf = max(0.0, 1.0 - (e91_error_rate / self.e91_threshold)) if self.e91_threshold > 0 else 1.0
        classical_conf = 1.0 if all_classical_ok else 0.0

        overall_confidence = min(1.0, 0.4 * qds_conf + 0.2 * e91_conf + 0.4 * classical_conf)
        if not is_accepted:
            overall_confidence = min(overall_confidence, 0.3)

        # Build human-readable threat assessment
        parts = []
        parts.append(
            f"QDS mismatch rate {qds_mismatch_rate*100:.1f}% "
            f"({qds_n_mismatches}/{qds_n_qubits} qubits), "
        )
        if qds_ok:
            parts.append(
                f"within legitimate-signer tolerance of {self.qds_threshold*100:.1f}%, "
                f"forgery probability bound < 2^-{security_bits}. "
            )
        else:
            parts.append(
                f"EXCEEDS tolerance of {self.qds_threshold*100:.1f}% — "
                f"potential forgery or channel attack. "
            )

        parts.append(
            f"E91 channel error {e91_error_rate*100:.1f}%, "
        )
        if e91_ok:
            parts.append(f"within threshold {self.e91_threshold*100:.1f}%. ")
        else:
            parts.append(
                f"EXCEEDS threshold {self.e91_threshold*100:.1f}% — "
                f"channel manipulation detected. "
            )

        if not correction_bits_valid:
            parts.append("CORRECTION BITS TAMPERED (classical DoS). ")

        if all_classical_ok:
            parts.append("All classical checks passed. ")
        else:
            failures = []
            if not classical_hash_valid:
                failures.append("hash")
            if not session_valid:
                failures.append("session")
            if not replay_valid:
                failures.append("replay")
            if not correction_bits_valid:
                failures.append("correction-bits")
            if not ml_dsa_valid:
                failures.append("ml-dsa-signature")
            parts.append(f"Classical check failures: {', '.join(failures)}. ")

        verdict = "ACCEPT" if is_accepted else "REJECT"
        parts.append(
            f"VERDICT: {verdict} (confidence {overall_confidence*100:.1f}%). "
        )
        parts.append(
            "Note: Two-Party QMAC — non-repudiation requires 3-party extension."
        )

        threat_assessment = "".join(parts)

        return ThreatScore(
            qds_mismatch_rate=qds_mismatch_rate,
            qds_threshold=self.qds_threshold,
            qds_forgery_bound=forgery_bound,
            qds_security_bits=security_bits,
            qds_n_qubits=qds_n_qubits,
            qds_n_mismatches=qds_n_mismatches,
            e91_error_rate=e91_error_rate,
            e91_threshold=self.e91_threshold,
            classical_hash_valid=classical_hash_valid,
            correction_bits_valid=correction_bits_valid,
            session_valid=session_valid,
            replay_valid=replay_valid,
            ml_dsa_valid=ml_dsa_valid,
            overall_confidence=overall_confidence,
            threat_assessment=threat_assessment,
            is_accepted=is_accepted,
        )
