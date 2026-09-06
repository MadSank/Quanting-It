"""
Unit tests for attack simulation and quantum channel tampering.
"""

import pytest
from src.qds_verifier import run_qds_teleportation_experiment


@pytest.mark.parametrize("attack_type, state_name", [
    ("bit_flip", "0"),
    ("phase_flip", "+"),
    ("depolarizing", "1"),
    ("intercept_resend", "-"),
])
def test_attack_error_injection(attack_type, state_name):
    """
    Verifies that adversarial channel attacks with non-zero probability (p=0.4)
    induce state errors resulting in non-zero QBER.
    """
    res = run_qds_teleportation_experiment(
        state_name=state_name,
        attack_type=attack_type,
        attack_strength=0.4,
        shots=1000,
        seed_simulator=42
    )
    metrics = res["metrics"]
    assert metrics["qber"] > 0.0, f"Expected QBER > 0 for attack {attack_type} on state {state_name}"
    assert metrics["fidelity"] < 1.0


def test_zero_attack_strength():
    """
    Verifies that attack_strength = 0 produces zero noise regardless of attack_type.
    """
    res = run_qds_teleportation_experiment(
        state_name="0",
        attack_type="bit_flip",
        attack_strength=0.0,
        shots=500,
        seed_simulator=42
    )
    assert res["metrics"]["qber"] == 0.0
