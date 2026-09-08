"""
Test Suite: SWAP Test
======================

Tests:
  - Identical states → P(pass) = 1.0
  - Orthogonal states → P(pass) ≈ 0.5
  - General overlap → P(pass) = (1 + |⟨ψ|φ⟩|²) / 2
  - Numerical cross-check against analytical formula
  - Destructive nature (conceptual, tested via copy budget integration)
"""

import pytest
import numpy as np
from qiskit.quantum_info import Statevector

from src.swap_test import (
    analytical_acceptance_probability,
    build_swap_test_circuit,
    run_swap_test,
    run_single_shot_swap_test,
)
from src.qowf import encode, prepare_statevector


class TestAnalyticalFormula:
    """Test the theoretical acceptance probability formula."""

    def test_identical_states(self):
        """P(pass) = (1 + 1²)/2 = 1.0 for identical states."""
        assert analytical_acceptance_probability(1.0) == pytest.approx(1.0)

    def test_orthogonal_states(self):
        """P(pass) = (1 + 0²)/2 = 0.5 for orthogonal states."""
        assert analytical_acceptance_probability(0.0) == pytest.approx(0.5)

    def test_half_overlap(self):
        """P(pass) = (1 + 0.5²)/2 = 0.625 for overlap = 0.5."""
        assert analytical_acceptance_probability(0.5) == pytest.approx(0.625)


class TestSwapTestCircuit:
    """Test the SWAP test circuit with real Qiskit simulation."""

    def test_identical_single_qubit_states(self):
        """SWAP test on identical |0⟩ states → always passes."""
        sv = Statevector.from_label("0")
        result = run_swap_test(sv, sv, n_qubits=1, shots=100)
        # Should pass with very high rate (= 1.0 theoretically)
        assert result.acceptance_rate == pytest.approx(1.0, abs=0.05)

    def test_orthogonal_single_qubit_states(self):
        """SWAP test on |0⟩ vs |1⟩ → passes ~50% of the time."""
        sv0 = Statevector.from_label("0")
        sv1 = Statevector.from_label("1")
        result = run_swap_test(sv0, sv1, n_qubits=1, shots=1000)
        assert result.acceptance_rate == pytest.approx(0.5, abs=0.05)

    def test_identical_plus_states(self):
        """SWAP test on identical |+⟩ states → always passes."""
        sv = Statevector.from_label("+")
        result = run_swap_test(sv, sv, n_qubits=1, shots=100)
        assert result.acceptance_rate == pytest.approx(1.0, abs=0.05)

    def test_plus_vs_minus(self):
        """SWAP test on |+⟩ vs |−⟩ → passes ~50%."""
        sv_plus = Statevector.from_label("+")
        sv_minus = Statevector.from_label("-")
        result = run_swap_test(sv_plus, sv_minus, n_qubits=1, shots=1000)
        assert result.acceptance_rate == pytest.approx(0.5, abs=0.05)


class TestSwapTestFingerprints:
    """Test SWAP test with actual quantum fingerprint states."""

    def test_identical_fingerprints_pass(self):
        """Same key → same fingerprint → SWAP test always passes."""
        import os
        k = os.urandom(16)
        cw = encode(k, 8)
        sv1 = prepare_statevector(cw, 8)
        sv2 = prepare_statevector(cw, 8)
        result = run_swap_test(sv1, sv2, n_qubits=8, shots=50)
        assert result.acceptance_rate == pytest.approx(1.0, abs=0.05)

    def test_different_fingerprints_detect(self):
        """Different keys → different fingerprints → SWAP test detects."""
        import os
        k1 = os.urandom(16)
        k2 = os.urandom(16)
        cw1 = encode(k1, 8)
        cw2 = encode(k2, 8)
        sv1 = prepare_statevector(cw1, 8)
        sv2 = prepare_statevector(cw2, 8)
        result = run_swap_test(sv1, sv2, n_qubits=8, shots=400)
        # For random keys, overlap ≈ 0, so P(pass) ≈ 0.5
        assert result.acceptance_rate == pytest.approx(0.5, abs=0.12)

    def test_theoretical_vs_simulated(self):
        """Simulated acceptance rate matches theoretical formula."""
        import os
        k1 = os.urandom(16)
        k2 = os.urandom(16)
        cw1 = encode(k1, 8)
        cw2 = encode(k2, 8)
        sv1 = prepare_statevector(cw1, 8)
        sv2 = prepare_statevector(cw2, 8)
        result = run_swap_test(sv1, sv2, n_qubits=8, shots=500)
        assert result.theoretical_rate is not None
        assert result.acceptance_rate == pytest.approx(
            result.theoretical_rate, abs=0.08
        )

    def test_single_shot_identical(self):
        """Single-shot SWAP test on identical states always passes."""
        import os
        k = os.urandom(16)
        cw = encode(k, 8)
        sv = prepare_statevector(cw, 8)
        # Run 20 single-shot tests — all should pass
        results = [run_single_shot_swap_test(sv, sv, 8) for _ in range(20)]
        assert all(results), "Identical states should always pass single-shot SWAP test"
