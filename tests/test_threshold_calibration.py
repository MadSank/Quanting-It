import pytest
from src.threshold_calibration import ThresholdCalibrator, CalibrationReport


def test_threshold_calibration_execution():
    """Run threshold calibration for M=16 positions."""
    calibrator = ThresholdCalibrator(m_positions=16, fingerprint_qubits=8)
    report = calibrator.run_empirical_calibration(n_rounds=10)

    assert isinstance(report, CalibrationReport)
    assert report.m_positions == 16
    assert report.honest_mean_mismatches == 0.0  # Perfect noiseless execution
    assert report.forgery_mean_mismatches > 4.0   # M=16, p~0.5 => mean ~ 8
    assert report.c1_threshold < report.c2_threshold
    assert report.separation_margin >= 2
    assert report.empirical_frr == 0.0  # Zero false rejections on honest signatures
    assert report.empirical_far == 0.0  # Zero false acceptances on forgeries


def test_threshold_ordering_and_margin():
    """Verify 0 <= c1 < c2 <= M and gap c2 - c1 is positive."""
    calibrator = ThresholdCalibrator(m_positions=32, fingerprint_qubits=8)
    report = calibrator.run_empirical_calibration(n_rounds=5)

    assert 0 <= report.c1_threshold < report.c2_threshold <= 32
    assert report.c2_threshold - report.c1_threshold >= 2
    assert report.security_bits >= 10
