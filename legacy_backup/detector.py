"""
Statistical Threat Detector for Quantum Teleportation Channel Tampering.

This module implements hypothesis testing (Binomial Exact Test & Z-score Test)
to distinguish normal operation from adversarial channel manipulation based on
Quantum Bit Error Rate (QBER) statistics.
"""

import numpy as np
from scipy import stats
from typing import Dict, Any


class QuantumThreatDetector:
    """
    Statistical Hypothesis Testing Detector for QDS Teleportation Channels.
    """

    def __init__(self, baseline_noise: float = 0.0, alpha: float = 0.01):
        """
        Args:
            baseline_noise: Expected baseline channel error rate under normal conditions p0 (default 0.0).
            alpha: Significance level for hypothesis testing (default 0.01 = 99% confidence).
        """
        self.baseline_noise = max(0.0, min(float(baseline_noise), 0.5))
        self.alpha = float(alpha)

    def analyze(self, total_shots: int, error_count: int) -> Dict[str, Any]:
        """
        Performs hypothesis testing on measurement outcome statistics.

        Null Hypothesis (H0): Channel is operating normally (QBER <= baseline_noise).
        Alternative Hypothesis (H1): Channel is under attack (QBER > baseline_noise).

        Args:
            total_shots: Total measurement shots N.
            error_count: Observed error count k (outcome '1' in verification measurement).

        Returns:
            Dict containing:
                - observed_qber
                - baseline_qber
                - z_score
                - p_value
                - threshold_qber
                - threat_detected (bool)
                - status_label ('LEGITIMATE' or 'ATTACK DETECTED')
                - confidence_level (%)
                - far_estimate (False Acceptance Rate)
                - frr_estimate (False Rejection Rate)
        """
        N = max(1, int(total_shots))
        k = max(0, int(error_count))
        observed_qber = k / N

        # Effective baseline for statistical computations
        p0 = self.baseline_noise

        # 1. Exact Binomial Test
        # Test H0: p <= p0 against H1: p > p0
        if p0 == 0.0:
            # Under ideal zero noise, any error probability p > 0 is an anomaly.
            # We use an empirical baseline p_eff = 0.5 / N for smooth p-value calculation
            p_eff = 0.5 / N
            res = stats.binomtest(k, N, p_eff, alternative='greater')
            p_value = float(res.pvalue) if k > 0 else 1.0
        else:
            res = stats.binomtest(k, N, p0, alternative='greater')
            p_value = float(res.pvalue)

        # 2. Z-Score Calculation (Normal Approximation with continuity correction)
        p_std_base = max(p0, 1.0 / N)
        sigma = np.sqrt(N * p_std_base * (1.0 - p_std_base))
        if sigma > 0:
            # Continuity correction: (k - 0.5 - N*p0) / sigma
            z_score = (k - 0.5 - N * p0) / sigma
        else:
            z_score = 0.0 if k == 0 else 10.0

        # 3. Critical Threshold QBER Calculation
        z_crit = stats.norm.ppf(1.0 - self.alpha)
        if p0 == 0.0:
            threshold_qber = 0.5 / N
        else:
            threshold_qber = p0 + z_crit * np.sqrt((p0 * (1.0 - p0)) / N)

        # 4. Threat Decision
        threat_detected = (p_value < self.alpha) or (observed_qber > threshold_qber)

        status_label = "ATTACK DETECTED" if threat_detected else "LEGITIMATE STATE VERIFIED"

        # 5. Theoretical False Rejection Rate (FRR) = Type I error = alpha
        frr_estimate = self.alpha

        # 6. Theoretical False Acceptance Rate (FAR) = Type II error beta for current observed_qber
        # FAR = P(X <= k_threshold | true error rate = observed_qber)
        k_thresh = int(np.floor(threshold_qber * N))
        if threat_detected and observed_qber > 0:
            far_estimate = float(stats.binom.cdf(k_thresh, N, observed_qber))
        else:
            far_estimate = 0.0 if not threat_detected else 0.05

        return {
            "total_shots": N,
            "error_count": k,
            "observed_qber": observed_qber,
            "baseline_qber": p0,
            "z_score": float(z_score),
            "p_value": float(p_value),
            "alpha": self.alpha,
            "z_critical": float(z_crit),
            "threshold_qber": float(threshold_qber),
            "threat_detected": bool(threat_detected),
            "status_label": status_label,
            "confidence_level": (1.0 - self.alpha) * 100.0,
            "far_estimate": float(far_estimate),
            "frr_estimate": float(frr_estimate)
        }


def detect_threat(total_shots: int, error_count: int, baseline_noise: float = 0.0, alpha: float = 0.01) -> Dict[str, Any]:
    """Helper function to run threat detection analysis."""
    detector = QuantumThreatDetector(baseline_noise=baseline_noise, alpha=alpha)
    return detector.analyze(total_shots, error_count)
