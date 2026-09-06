"""
Unit tests for statistical threat detector (Binomial test, Z-score, threat classification).
"""

import pytest
from src.detector import detect_threat, QuantumThreatDetector


def test_detector_legitimate_scenario():
    """
    Verifies that a noiseless run (0 errors out of 1000 shots) is flagged as LEGITIMATE.
    """
    result = detect_threat(total_shots=1000, error_count=0, baseline_noise=0.0, alpha=0.01)
    assert not result["threat_detected"]
    assert result["status_label"] == "LEGITIMATE STATE VERIFIED"
    assert result["p_value"] == 1.0


def test_detector_attack_scenario():
    """
    Verifies that an error count exceeding threshold (e.g. 250 errors out of 1000 shots)
    is correctly flagged as ATTACK DETECTED.
    """
    result = detect_threat(total_shots=1000, error_count=250, baseline_noise=0.0, alpha=0.01)
    assert result["threat_detected"]
    assert result["status_label"] == "ATTACK DETECTED"
    assert result["p_value"] < 0.01
    assert result["z_score"] > 2.0


def test_baseline_noise_handling():
    """
    Verifies detector performance when baseline channel noise is non-zero (e.g. 5%).
    """
    detector = QuantumThreatDetector(baseline_noise=0.05, alpha=0.01)
    
    # 40 errors in 1000 shots (4.0% QBER <= 5.0% baseline) -> Legitimate
    legit_res = detector.analyze(1000, 40)
    assert not legit_res["threat_detected"]

    # 150 errors in 1000 shots (15.0% QBER > 5.0% baseline) -> Attack Detected
    attack_res = detector.analyze(1000, 150)
    assert attack_res["threat_detected"]
