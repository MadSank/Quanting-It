"""
Tests for CHSH Bell-Test Experiment Module (src/chsh.py).
"""

import math
import pytest
import numpy as np
from src.chsh import (
    ALICE_ANGLES,
    BOB_ANGLES,
    CLASSICAL_BOUND,
    TSIRELSON_BOUND,
    theoretical_correlations,
    theoretical_s,
    build_chsh_circuit,
    compute_correlation,
    run_chsh_experiment,
    run_chsh_comparison,
    CHSHResult,
)


def test_chsh_theory_correlations():
    """Verify all four theoretical correlations match cos(θA - θB) analytically."""
    th = theoretical_correlations()
    # E(a, b) = cos(0 - pi/4) = cos(-pi/4) = 1/sqrt(2)
    assert pytest.approx(th["E(a,b)"], abs=1e-7) == 1.0 / math.sqrt(2.0)
    # E(a, b') = cos(0 - 3pi/4) = cos(-3pi/4) = -1/sqrt(2)
    assert pytest.approx(th["E(a,b')"], abs=1e-7) == -1.0 / math.sqrt(2.0)
    # E(a', b) = cos(pi/2 - pi/4) = cos(pi/4) = 1/sqrt(2)
    assert pytest.approx(th["E(a',b)"], abs=1e-7) == 1.0 / math.sqrt(2.0)
    # E(a', b') = cos(pi/2 - 3pi/4) = cos(-pi/4) = 1/sqrt(2)
    assert pytest.approx(th["E(a',b')"], abs=1e-7) == 1.0 / math.sqrt(2.0)


def test_chsh_theory_s_value():
    """Verify ideal S = 2*sqrt(2) ≈ 2.8284 under the approved sign convention."""
    s_theory = theoretical_s()
    assert pytest.approx(s_theory, abs=1e-7) == 2.0 * math.sqrt(2.0)
    assert s_theory > CLASSICAL_BOUND
    assert pytest.approx(s_theory, abs=1e-7) == TSIRELSON_BOUND


def test_build_chsh_circuit():
    """Verify circuit generation has correct dimensions, registers, and operations."""
    qc = build_chsh_circuit(0.0, math.pi / 4.0, attack_type="NONE")
    assert qc.num_qubits == 2
    assert qc.num_clbits == 2
    gate_names = [inst.operation.name for inst in qc.data]
    assert "h" in gate_names
    assert "cx" in gate_names
    assert "ry" in gate_names
    assert "measure" in gate_names


def test_compute_correlation():
    """Verify correlation calculation and standard error under controlled counts."""
    # Perfect correlation: only 00 and 11
    E, err, n_same, n_diff, n_tot = compute_correlation({"00": 500, "11": 500})
    assert E == 1.0
    assert err == 0.0
    assert n_same == 1000
    assert n_diff == 0

    # Perfect anti-correlation: only 01 and 10
    E, err, n_same, n_diff, n_tot = compute_correlation({"01": 500, "10": 500})
    assert E == -1.0
    assert err == 0.0
    assert n_same == 0
    assert n_diff == 1000

    # Uncorrelated equal mixture
    E, err, n_same, n_diff, n_tot = compute_correlation({"00": 250, "01": 250, "10": 250, "11": 250})
    assert pytest.approx(E, abs=1e-6) == 0.0
    assert pytest.approx(err, abs=1e-4) == 1.0 / math.sqrt(1000)

    # Empty counts
    E, err, n_same, n_diff, n_tot = compute_correlation({})
    assert E == 0.0
    assert err == 0.0


def test_chsh_ideal_simulation_violation():
    """Verify finite-shot simulation produces a statistically significant Bell violation."""
    res = run_chsh_experiment(shots=8192, attack_type="NONE", seed_simulator=42)
    # S should be close to 2*sqrt(2) ≈ 2.8284 within statistical fluctuation (3*sigma)
    assert 2.70 < res.s_value < 2.95
    assert res.s_value > CLASSICAL_BOUND
    assert res.violates_classical is True
    assert res.sigma_violation > 3.0  # More than 3-sigma violation
    assert res.p_value_classical < 0.001
    assert res.uncertainty > 0.0
    # Lower bound of 95% confidence interval must exceed classical bound
    assert res.confidence_interval_95[0] > CLASSICAL_BOUND


def test_chsh_depolarizing_noise_degradation():
    """Verify controlled depolarizing noise lowers CHSH S below the classical bound."""
    # Under strong depolarizing noise (lambda=0.45), S = (1 - 0.45)*2.828 ≈ 1.55 <= 2.0
    res = run_chsh_experiment(
        shots=4096,
        attack_type="DEPOLARIZING_NOISE",
        attack_params={"noise_strength": 0.45},
        seed_simulator=42,
    )
    assert res.s_value < CLASSICAL_BOUND
    assert res.violates_classical is False
    assert res.attack_type == "DEPOLARIZING_NOISE"
    assert res.attack_params.get("noise_strength") == 0.45


def test_chsh_intercept_resend_attack():
    """Verify intercept-resend attack breaks entanglement and satisfies classical bound."""
    res = run_chsh_experiment(
        shots=4096,
        attack_type="INTERCEPT_RESEND",
        attack_params={"eve_angle": 0.0},
        seed_simulator=42,
    )
    # Entanglement is completely broken; S cannot violate the classical bound
    assert res.s_value <= CLASSICAL_BOUND + 2.0 * res.uncertainty
    assert res.violates_classical is False
    # Theoretical value under Z-basis intercept-resend is ≈ sqrt(2) ≈ 1.414
    assert 1.25 < res.s_value < 1.65


def test_chsh_comparison():
    """Verify run_chsh_comparison provides all three conditions for comparative analysis."""
    comp = run_chsh_comparison(shots=2048, noise_strength=0.35, seed_simulator=101)
    assert "CLEAN" in comp
    assert "DEPOLARIZING" in comp
    assert "INTERCEPT_RESEND" in comp

    clean = comp["CLEAN"]
    noisy = comp["DEPOLARIZING"]
    attacked = comp["INTERCEPT_RESEND"]

    assert clean.s_value > noisy.s_value
    assert clean.s_value > attacked.s_value
    assert clean.violates_classical is True


def test_chsh_result_serialization():
    """Verify CHSHResult converts cleanly to a JSON-compatible dictionary."""
    res = run_chsh_experiment(shots=512, seed_simulator=123)
    d = res.to_dict()
    assert isinstance(d, dict)
    assert "s_value" in d
    assert "uncertainty" in d
    assert "confidence_interval_95" in d
    assert "correlations" in d
    assert "E(a,b)" in d["correlations"]
    assert "E(a,b')" in d["correlations"]
    assert "E(a',b)" in d["correlations"]
    assert "E(a',b')" in d["correlations"]
