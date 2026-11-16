"""
Tests for Backend Execution Manager (src/backend_manager.py).
"""

import pytest
import os
from qiskit import QuantumCircuit
from src.backend_manager import BackendManager, ExecutionMode


def test_backend_manager_modes():
    """Verify execution mode enum values."""
    assert ExecutionMode.IDEAL_SIMULATOR == "IDEAL_SIMULATOR"
    assert ExecutionMode.NOISY_SIMULATOR == "NOISY_SIMULATOR"
    assert ExecutionMode.IBM_HARDWARE == "IBM_HARDWARE"


def test_backend_manager_ideal_execution():
    """Verify standard circuit execution on ideal AerSimulator."""
    bm = BackendManager(mode=ExecutionMode.IDEAL_SIMULATOR)
    qc = QuantumCircuit(2, 2)
    qc.h(0)
    qc.cx(0, 1)
    qc.measure([0, 1], [0, 1])

    res = bm.execute([qc], shots=1000, seed_simulator=42)
    assert res["execution_mode"] == "IDEAL_SIMULATOR"
    assert res["backend_name"] == "aer_simulator_ideal"
    assert res["job_id"] is None
    assert len(res["counts"]) == 1
    counts = res["counts"][0]
    # For Bell state |Phi+>, 00 and 11 should dominate
    assert counts.get("00", 0) > 400
    assert counts.get("11", 0) > 400


def test_backend_manager_noisy_execution():
    """Verify execution on noisy AerSimulator."""
    bm = BackendManager(mode=ExecutionMode.NOISY_SIMULATOR, noise_strength=0.2)
    qc = QuantumCircuit(2, 2)
    qc.h(0)
    qc.cx(0, 1)
    qc.id(1)
    qc.measure([0, 1], [0, 1])

    res = bm.execute([qc], shots=1000, attack_params={"noise_strength": 0.2}, seed_simulator=42)
    assert res["execution_mode"] == "NOISY_SIMULATOR"
    assert res["backend_name"] == "aer_simulator_noisy"
    assert "noise_strength" in res["metadata"]


def test_backend_manager_hardware_requires_explicit_confirmation():
    """Verify that hardware execution strictly fails if confirmed=False."""
    bm = BackendManager(mode=ExecutionMode.IBM_HARDWARE)
    qc = QuantumCircuit(2, 2)
    with pytest.raises(ValueError, match="Explicit user confirmation is required"):
        bm.execute([qc], confirmed=False)


def test_backend_manager_hardware_missing_credentials_or_package():
    """Verify informative error handling when hardware execution is confirmed but unconfigured."""
    bm = BackendManager(mode=ExecutionMode.IBM_HARDWARE)
    qc = QuantumCircuit(2, 2)
    # When confirmed=True, it attempts to validate qiskit-ibm-runtime and credentials.
    # Must raise RuntimeError rather than falling back to simulator.
    with pytest.raises(RuntimeError, match="Cannot execute on IBM Quantum Hardware"):
        bm.execute([qc], confirmed=True)


def test_backend_manager_token_retrieval(monkeypatch):
    """Verify token resolution from explicit param or environment."""
    bm1 = BackendManager(ibm_token="custom_token_123")
    assert bm1.get_token() == "custom_token_123"

    monkeypatch.setenv("QISKIT_IBM_TOKEN", "env_token_456")
    bm2 = BackendManager()
    assert bm2.get_token() == "env_token_456"
