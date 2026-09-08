"""
Threshold Calibration Module for Gottesman-Chuang QDS
=====================================================

Performs empirical and analytical calibration of verification thresholds:
  c₁: Primary verifier (Bob) acceptance threshold (mismatches ≤ c₁·M → 1-ACC)
  c₂: Transfer verifier (Charlie) acceptance threshold (mismatches ≤ c₂·M → 0-ACC)
  Rejection: mismatches ≥ c₂·M → REJ

Gottesman-Chuang Requirement:
  0 ≤ c₁ < c₂ ≤ M
  The threshold gap c₂ - c₁ is the mechanism used to create a statistical
  transferability region between primary (Bob) and transferred (Charlie) verifiers.
  The actual repudiation probability depends on protocol assumptions and the
  empirically measured mismatch distributions between verifiers.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Any, Tuple, List
import numpy as np
from scipy.stats import binom

from src.gc_keys import GCKeyGenerator, GCKeyPair, VerifierKeyRegister
from src.qds_signer import GCSigner, GCSignature
from src.qds_verifier import GCVerifier, VerificationOutcome
from src.eve import Eve
from src.threat_engine import GCForgeryModel


@dataclass
class CalibrationReport:
    """Statistical summary of threshold calibration experiment."""
    m_positions: int
    n_rounds: int
    honest_mean_mismatches: float
    honest_std_mismatches: float
    honest_max_mismatches: int
    forgery_mean_mismatches: float
    forgery_std_mismatches: float
    forgery_min_mismatches: int
    c1_threshold: int
    c2_threshold: int
    c1_fraction: float
    c2_fraction: float
    separation_margin: int
    empirical_far: float  # False Acceptance Rate (forgery accepted)
    empirical_frr: float  # False Rejection Rate (honest rejected)
    theoretical_forgery_bound: float
    security_bits: int


class ThresholdCalibrator:
    """
    Calibrates c₁ and c₂ through empirical Monte Carlo trials
    and theoretical binomial tail bounds.
    """

    def __init__(
        self,
        m_positions: int = 16,
        fingerprint_qubits: int = 8,
        key_bits: int = 128,
    ):
        self.m_positions = m_positions
        self.fingerprint_qubits = fingerprint_qubits
        self.key_bits = key_bits

    def run_empirical_calibration(
        self,
        n_rounds: int = 20,
        target_far: float = 1e-4,
    ) -> CalibrationReport:
        """
        Execute n_rounds of honest and adversarial verification rounds,
        measure mismatch distributions, and calibrate (c₁, c₂).
        """
        honest_mismatches: List[int] = []
        forgery_mismatches: List[int] = []

        for _ in range(n_rounds):
            # Setup fresh key pair and register
            kp = GCKeyGenerator.generate(
                n_positions=self.m_positions,
                fingerprint_qubits=self.fingerprint_qubits,
                private_key_bits=self.key_bits
            )
            reg_bob = VerifierKeyRegister(owner="Bob")
            for i in range(self.m_positions):
                for b in (0, 1):
                    reg_bob.store(kp.distribute_copy(i, b, "Bob"))

            # 1. Honest verification round
            msg = b"VALID_CALIBRATION_PAYLOAD"
            sig = GCSigner.sign(message=msg, key_pair=kp)
            verifier = GCVerifier(acceptance_threshold=0.5, rejection_threshold=0.9)
            res_honest = verifier.verify(signature=sig, key_register=reg_bob, message=msg)
            honest_mismatches.append(res_honest.n_failures)

            # 2. Forgery round (fresh register)
            reg_forgery = VerifierKeyRegister(owner="Bob_Forge")
            for i in range(self.m_positions):
                for b in (0, 1):
                    reg_forgery.store(kp.distribute_copy(i, b, "Bob_Forge"))

            forged_sig = Eve.forge_gc_signature(
                message=msg,
                n_positions=self.m_positions,
                key_bytes=self.key_bits // 8
            )
            res_forgery = verifier.verify(
                signature=forged_sig,
                key_register=reg_forgery,
                message=msg
            )
            forgery_mismatches.append(res_forgery.n_failures)

        h_mean = float(np.mean(honest_mismatches))
        h_std = float(np.std(honest_mismatches))
        h_max = int(np.max(honest_mismatches))

        f_mean = float(np.mean(forgery_mismatches))
        f_std = float(np.std(forgery_mismatches))
        f_min = int(np.min(forgery_mismatches))

        # Calibrate c1:
        # In noiseless sim, h_mean = 0. Set c1 to accommodate noise margin while <= f_min - 2
        p_adv = GCForgeryModel.swap_test_mismatch_prob()
        c1 = 0
        for c in range(self.m_positions):
            if binom.cdf(c, self.m_positions, p_adv) <= target_far:
                c1 = c
            else:
                break

        # If c1 computed theoretically is 0, allow at least 0 (or 1 if M >= 32)
        c1 = max(0, min(c1, max(0, f_min - 2)))

        # Calibrate c2:
        # Minimum c2 providing transferability gap (c2 - c1 >= 2 or at least 25% of M)
        gap = max(2, int(math.ceil(self.m_positions * 0.15)))
        c2 = min(self.m_positions - 1, c1 + gap)

        # Compute empirical FAR and FRR
        empirical_far = sum(1 for m in forgery_mismatches if m <= c1) / len(forgery_mismatches)
        empirical_frr = sum(1 for m in honest_mismatches if m > c1) / len(honest_mismatches)

        theoretical_bound = GCForgeryModel.compute_forgery_bound(
            self.m_positions, c1 / self.m_positions if self.m_positions > 0 else 0.0
        )
        sec_bits = GCForgeryModel.compute_security_level(
            self.m_positions, c1 / self.m_positions if self.m_positions > 0 else 0.0
        )

        return CalibrationReport(
            m_positions=self.m_positions,
            n_rounds=n_rounds,
            honest_mean_mismatches=h_mean,
            honest_std_mismatches=h_std,
            honest_max_mismatches=h_max,
            forgery_mean_mismatches=f_mean,
            forgery_std_mismatches=f_std,
            forgery_min_mismatches=f_min,
            c1_threshold=c1,
            c2_threshold=c2,
            c1_fraction=c1 / self.m_positions,
            c2_fraction=c2 / self.m_positions,
            separation_margin=c2 - c1,
            empirical_far=empirical_far,
            empirical_frr=empirical_frr,
            theoretical_forgery_bound=theoretical_bound,
            security_bits=sec_bits,
        )
