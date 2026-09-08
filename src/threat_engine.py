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

    @property
    def overall_threat_score(self) -> float:
        """Derived continuous threat severity score (0.0 to 1.0)."""
        if self.is_accepted:
            return round(max(0.0, min(1.0, self.qds_mismatch_rate * 2.0 + (1.0 - self.overall_confidence) * 0.1)), 2)
        return round(max(0.6, min(1.0, 1.0 - self.overall_confidence + 0.4)), 2)

    @property
    def threat_level(self) -> str:
        """Categorical threat rating based on overall assessment."""
        score = self.overall_threat_score
        if score >= 0.8:
            return "CRITICAL"
        elif score >= 0.5:
            return "HIGH"
        elif score >= 0.2:
            return "MEDIUM"
        else:
            return "LOW"


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


# ===========================================================================
#  Gottesman-Chuang QDS Threat Engine Extensions
# ===========================================================================

class GCForgeryModel:
    """
    Mathematical model for Gottesman-Chuang QDS forgery and transferability bounds.

    Security is based on two core principles:
    1. Holevo's Theorem (Information-Theoretic Key Secrecy):
       L-bit private key k. Adversary with T copies of n-qubit states |f_k⟩
       has an accessible-information budget bounded by approximately χ ≤ T·n
       classical bits under standard assumptions.
       The quantity ΔH = L - T·n represents the remaining entropy/information gap indicator.
       When ΔH > 0 (e.g., 128 - 4*8 = 96 bits), the public states do not provide
       sufficient classical mutual information to uniquely determine the L-bit key k.
       NOTE: ΔH is an entropy gap indicator, NOT an inversion/forgery probability.
       Do NOT derive 2^-96 from this alone.
    2. SWAP Test Statistics (Overlap Discrimination):
       For an unrevealed key where adversary guesses a candidate k', the empirical
       overlap |⟨f_k|f_k'⟩| = |1 - 2 d_H/N| ≈ 0.
       SWAP test single-position mismatch prob: p_mismatch = (1 - |overlap|²)/2 ≈ 0.50.
       For M positions and threshold c₁: P_swap_forge = Binomial_CDF(c₁·M, M, p_mismatch).
    """

    DEFAULT_KEY_BITS = 128
    DEFAULT_FINGERPRINT_QUBITS = 8
    DEFAULT_MAX_COPIES = 4
    DEFAULT_EMPIRICAL_OVERLAP = 0.15

    @staticmethod
    def holevo_accessible_information(max_copies: int = DEFAULT_MAX_COPIES,
                                      fingerprint_qubits: int = DEFAULT_FINGERPRINT_QUBITS) -> int:
        """Accessible-information budget bounded by approximately T·n classical bits."""
        return max_copies * fingerprint_qubits

    @staticmethod
    def holevo_margin(key_bits: int = DEFAULT_KEY_BITS,
                      max_copies: int = DEFAULT_MAX_COPIES,
                      fingerprint_qubits: int = DEFAULT_FINGERPRINT_QUBITS) -> int:
        """
        Compute the Holevo information/entropy gap indicator ΔH = L - T·n.
        A positive gap indicates that public keys reveal fewer bits than the key length L.
        """
        return key_bits - max_copies * fingerprint_qubits

    @staticmethod
    def holevo_inversion_bound(key_bits: int = DEFAULT_KEY_BITS,
                              max_copies: int = DEFAULT_MAX_COPIES,
                              fingerprint_qubits: int = DEFAULT_FINGERPRINT_QUBITS) -> float:
        """
        Entropy gap indicator:
        Mathematically, ΔH = L - T·n is an entropy gap indicator, not a direct inversion probability.
        If ΔH <= 0, the adversary can potentially learn all key bits (returns 1.0).
        If ΔH > 0, returns 2^(-ΔH) as an entropy-gap indicator.
        """
        margin = GCForgeryModel.holevo_margin(key_bits, max_copies, fingerprint_qubits)
        if margin <= 0:
            return 1.0
        return float(2.0 ** (-margin))

    @staticmethod
    def swap_test_mismatch_prob(overlap: float = DEFAULT_EMPIRICAL_OVERLAP) -> float:
        """Mismatch probability per position for states with given overlap."""
        p_acc = (1.0 + (overlap ** 2)) / 2.0
        return 1.0 - p_acc

    @staticmethod
    def compute_forgery_bound(
        m_positions: int,
        threshold_fraction: float,
        overlap: float = DEFAULT_EMPIRICAL_OVERLAP,
        key_bits: int = DEFAULT_KEY_BITS,
        max_copies: int = DEFAULT_MAX_COPIES,
        fingerprint_qubits: int = DEFAULT_FINGERPRINT_QUBITS
    ) -> float:
        """
        Compute total forgery probability upper bound based on SWAP test binomial distribution.
        
        Conditioned on the Holevo entropy gap ΔH = L - T·n > 0 (meaning public keys do not
        contain enough mutual information to reconstruct private key k), the adversary's
        candidate key k' yields near-zero state overlap with |f_k⟩. The probability of
        passing verification across M positions with threshold fraction c1 is given by
        the binomial tail CDF: P(mismatches <= c1 * M).
        
        If the entropy gap is zero or negative (ΔH <= 0), public key states reveal >= L bits,
        so information-theoretic security does not hold (P_forge = 1.0).
        """
        margin = GCForgeryModel.holevo_margin(key_bits, max_copies, fingerprint_qubits)
        if margin <= 0:
            return 1.0

        c1 = int(math.floor(m_positions * threshold_fraction))
        p_mismatch = GCForgeryModel.swap_test_mismatch_prob(overlap)
        p_swap = float(binom.cdf(c1, m_positions, p_mismatch))
        return min(1.0, p_swap)

    @staticmethod
    def compute_security_level(
        m_positions: int,
        threshold_fraction: float,
        overlap: float = DEFAULT_EMPIRICAL_OVERLAP,
        key_bits: int = DEFAULT_KEY_BITS,
        max_copies: int = DEFAULT_MAX_COPIES,
        fingerprint_qubits: int = DEFAULT_FINGERPRINT_QUBITS
    ) -> int:
        """Compute security level in bits: -log₂(P_forge)."""
        p_forge = GCForgeryModel.compute_forgery_bound(
            m_positions, threshold_fraction, overlap, key_bits, max_copies, fingerprint_qubits
        )
        if p_forge <= 0:
            return 256
        if p_forge >= 1.0:
            return 0
        return int(math.floor(-math.log2(p_forge)))

    @staticmethod
    def calibrate_thresholds(
        m_positions: int,
        honest_error_rate: float = 0.0,
        adversary_overlap: float = DEFAULT_EMPIRICAL_OVERLAP,
        target_false_reject_prob: float = 1e-4,
        target_forgery_prob: float = 1e-4,
    ) -> dict:
        """
        Calibrate Bob's threshold c1 and Charlie's threshold c2.

        Gottesman-Chuang requires:
        0 ≤ c1 < c2 ≤ M
        - Bob accepts if mismatches ≤ c1
        - Charlie (transfer recipient) accepts if mismatches ≤ c2
        - Alice cannot repudiate because if Bob accepts (≤ c1 errors),
          with high probability Charlie also observes ≤ c2 errors.
        """
        p_adv_mismatch = GCForgeryModel.swap_test_mismatch_prob(adversary_overlap)
        p_honest_mismatch = max(1e-6, honest_error_rate)

        # Find maximum c1 such that P(adversary <= c1) <= target_forgery_prob
        best_c1 = 0
        for c in range(m_positions):
            p_forg = float(binom.cdf(c, m_positions, p_adv_mismatch))
            if p_forg <= target_forgery_prob:
                best_c1 = c
            else:
                break

        # Find minimum c2 > c1 such that margin c2 - c1 provides repudiation protection
        best_c2 = min(m_positions - 1, max(best_c1 + 1, int(m_positions * 0.25)))

        return {
            "m_positions": m_positions,
            "c1": best_c1,
            "c2": best_c2,
            "threshold_bob_fraction": best_c1 / m_positions,
            "threshold_charlie_fraction": best_c2 / m_positions,
            "adv_mismatch_prob": p_adv_mismatch,
            "forgery_prob_at_c1": float(binom.cdf(best_c1, m_positions, p_adv_mismatch)),
            "margin": best_c2 - best_c1,
        }


class GCThreatScorer:
    """
    Threat scorer for the Gottesman-Chuang QDS architecture.
    Evaluates SWAP test results, Holevo bounds, copy budgets, and classical checks.
    """

    def __init__(self, c1_threshold_fraction: float = 0.10,
                 c2_threshold_fraction: float = 0.25,
                 e91_threshold: float = 0.15):
        self.c1_threshold_fraction = c1_threshold_fraction
        self.c2_threshold_fraction = c2_threshold_fraction
        self.e91_threshold = e91_threshold

    def evaluate_gc(
        self,
        m_positions: int,
        n_mismatches: int,
        is_transfer: bool = False,
        e91_error_rate: float = 0.0,
        classical_hash_valid: bool = True,
        session_valid: bool = True,
        replay_valid: bool = True,
        copy_available: bool = True,
        ml_dsa_valid: bool = True,
    ) -> ThreatScore:
        """
        Evaluate GC QDS verification.
        """
        threshold_fraction = self.c2_threshold_fraction if is_transfer else self.c1_threshold_fraction
        mismatch_rate = n_mismatches / m_positions if m_positions > 0 else 1.0

        forgery_bound = GCForgeryModel.compute_forgery_bound(
            m_positions, threshold_fraction
        )
        sec_bits = GCForgeryModel.compute_security_level(
            m_positions, threshold_fraction
        )

        qds_ok = (mismatch_rate <= threshold_fraction) and copy_available
        e91_ok = e91_error_rate <= self.e91_threshold
        all_classical_ok = (
            classical_hash_valid and session_valid
            and replay_valid and ml_dsa_valid
        )

        is_accepted = qds_ok and e91_ok and all_classical_ok

        # Confidence calculation
        qds_conf = max(0.0, 1.0 - (mismatch_rate / threshold_fraction)) if threshold_fraction > 0 else 1.0
        e91_conf = max(0.0, 1.0 - (e91_error_rate / self.e91_threshold)) if self.e91_threshold > 0 else 1.0
        classical_conf = 1.0 if all_classical_ok else 0.0
        overall_confidence = min(1.0, 0.45 * qds_conf + 0.15 * e91_conf + 0.40 * classical_conf)
        if not is_accepted:
            overall_confidence = min(overall_confidence, 0.25)

        role = "Charlie (transfer)" if is_transfer else "Bob (primary verifier)"
        parts = [
            f"GC QDS verification by {role}: ",
            f"SWAP test mismatches {n_mismatches}/{m_positions} ({mismatch_rate*100:.1f}%), ",
            f"threshold {threshold_fraction*100:.1f}%. ",
        ]
        if qds_ok:
            parts.append(f"QDS verified within tolerance. Forgery bound < 2^-{sec_bits}. ")
        else:
            if not copy_available:
                parts.append("REJECTED: Public key copy exhausted or unavailable (no-cloning violation). ")
            else:
                parts.append("REJECTED: SWAP test mismatch count exceeds threshold. ")

        if not all_classical_ok:
            parts.append("Classical checks failed. ")

        verdict = "ACCEPT" if is_accepted else "REJECT"
        parts.append(f"VERDICT: {verdict} (confidence {overall_confidence*100:.1f}%).")

        return ThreatScore(
            qds_mismatch_rate=mismatch_rate,
            qds_threshold=threshold_fraction,
            qds_forgery_bound=forgery_bound,
            qds_security_bits=sec_bits,
            qds_n_qubits=m_positions,
            qds_n_mismatches=n_mismatches,
            e91_error_rate=e91_error_rate,
            e91_threshold=self.e91_threshold,
            classical_hash_valid=classical_hash_valid,
            correction_bits_valid=copy_available,
            session_valid=session_valid,
            replay_valid=replay_valid,
            ml_dsa_valid=ml_dsa_valid,
            overall_confidence=overall_confidence,
            threat_assessment="".join(parts),
            protocol_model="THREE_PARTY_GC_QDS",
            non_repudiation_warning=(
                "Full Gottesman-Chuang QDS: Alice signs via classical key release; "
                "Bob and Charlie independently verify against quantum public key copies via SWAP test. "
                "Non-repudiation holds under no-cloning and Holevo bounds."
            ),
            is_accepted=is_accepted,
        )
