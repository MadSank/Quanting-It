"""
Unit tests for quantum teleportation state reconstruction and verification.
"""

import pytest
import numpy as np
from src.qds_verifier import run_qds_teleportation_experiment


@pytest.mark.parametrize("state_name", ["0", "1", "+", "-"])
def test_noiseless_teleportation_reconstruction(state_name):
    """
    Verifies that under ideal noiseless quantum teleportation (attack_strength=0),
    Bob's reconstructed verification state achieves QBER = 0.0 (100% fidelity).
    """
    res = run_qds_teleportation_experiment(
        state_name=state_name,
        attack_type="none",
        attack_strength=0.0,
        shots=1000,
        seed_simulator=42
    )
    metrics = res["metrics"]
    assert metrics["error_count"] == 0, f"Expected 0 errors for state {state_name}, got {metrics['error_count']}"
    assert metrics["qber"] == 0.0
    assert metrics["fidelity"] == 1.0


def test_custom_state_teleportation():
    """
    Verifies teleportation of custom parameterized state |psi(theta, phi)>.
    """
    theta = np.pi / 3  # 60 degrees
    phi = np.pi / 4    # 45 degrees
    res = run_qds_teleportation_experiment(
        state_name="custom",
        theta=theta,
        phi=phi,
        attack_type="none",
        attack_strength=0.0,
        shots=1000,
        seed_simulator=42
    )
    metrics = res["metrics"]
    assert metrics["qber"] == 0.0
    assert metrics["fidelity"] == 1.0
