"""
Test Suite: Quantum One-Way Function (QOWF)
=============================================

Tests:
  - Encoding determinism
  - Fingerprint state preparation
  - Overlap formula: |⟨f_k|f_k'⟩| = |1 - 2·d_H(E(k),E(k'))/N|
  - Identical keys → overlap = 1
  - Distinct keys → overlap < 1
  - Empirical Hamming distance statistics
  - Theoretical vs simulated overlap cross-check
  - NEGATIVE TEST: Hadamard construction is trivially invertible
"""

import os
import pytest
import numpy as np
from qiskit.quantum_info import Statevector

from src.qowf import (
    encode,
    hamming_distance,
    overlap_from_hamming,
    prepare_statevector,
    prepare_circuit,
    compute_overlap,
    compute_overlap_statevector,
    prepare_hadamard_state,
    measure_encoding_stats,
    DEFAULT_FINGERPRINT_QUBITS,
)


class TestEncoding:
    """Tests for the deterministic binary expansion encoding."""

    def test_encoding_deterministic(self):
        """Same key always produces the same codeword."""
        k = os.urandom(16)
        cw1 = encode(k, 8)
        cw2 = encode(k, 8)
        assert cw1 == cw2

    def test_encoding_length(self):
        """Codeword length equals N = 2^n."""
        k = os.urandom(16)
        for n in [4, 6, 8]:
            cw = encode(k, n)
            assert len(cw) == 2**n

    def test_encoding_binary(self):
        """All codeword values are 0 or 1."""
        k = os.urandom(16)
        cw = encode(k, 8)
        assert all(b in (0, 1) for b in cw)

    def test_encoding_different_keys_differ(self):
        """Different keys produce different codewords (with overwhelming probability)."""
        k1 = os.urandom(16)
        k2 = os.urandom(16)
        cw1 = encode(k1, 8)
        cw2 = encode(k2, 8)
        assert cw1 != cw2


class TestHammingDistance:
    """Tests for Hamming distance computation."""

    def test_identical_codewords(self):
        """Hamming distance between identical codewords is 0."""
        cw = [0, 1, 0, 1, 1, 0, 1, 0]
        assert hamming_distance(cw, cw) == 0

    def test_completely_different(self):
        """Hamming distance between complementary codewords equals length."""
        cw1 = [0] * 8
        cw2 = [1] * 8
        assert hamming_distance(cw1, cw2) == 8

    def test_known_distance(self):
        """Hamming distance for a known pair."""
        cw1 = [0, 0, 0, 0]
        cw2 = [1, 0, 1, 0]
        assert hamming_distance(cw1, cw2) == 2


class TestOverlapFormula:
    """Tests for the overlap identity: |⟨f_k|f_k'⟩| = |1 - 2·d_H/N|."""

    def test_identical_keys_overlap_one(self):
        """Identical keys → overlap = 1.0."""
        k = os.urandom(16)
        overlap = compute_overlap(k, k, 8)
        assert overlap == pytest.approx(1.0, abs=1e-10)

    def test_identical_keys_statevector_overlap_one(self):
        """Cross-check: statevector inner product also gives 1.0."""
        k = os.urandom(16)
        overlap_sv = compute_overlap_statevector(k, k, 8)
        assert overlap_sv == pytest.approx(1.0, abs=1e-10)

    def test_distinct_keys_overlap_less_than_one(self):
        """Different keys → overlap < 1."""
        k1 = os.urandom(16)
        k2 = os.urandom(16)
        overlap = compute_overlap(k1, k2, 8)
        assert overlap < 1.0

    def test_analytical_vs_statevector_overlap(self):
        """Analytical (Hamming) overlap matches statevector inner product."""
        for _ in range(10):
            k1 = os.urandom(16)
            k2 = os.urandom(16)
            overlap_analytical = compute_overlap(k1, k2, 8)
            overlap_sv = compute_overlap_statevector(k1, k2, 8)
            assert overlap_analytical == pytest.approx(overlap_sv, abs=1e-10)

    def test_overlap_from_hamming_formula(self):
        """Direct test of |1 - 2·d_H/N| formula."""
        N = 256
        # d_H = 0 → overlap = 1
        assert overlap_from_hamming(0, N) == pytest.approx(1.0)
        # d_H = N/2 → overlap = 0
        assert overlap_from_hamming(N // 2, N) == pytest.approx(0.0)
        # d_H = N/4 → overlap = 0.5
        assert overlap_from_hamming(N // 4, N) == pytest.approx(0.5)
        # d_H = N → overlap = 1 (all bits flipped)
        assert overlap_from_hamming(N, N) == pytest.approx(1.0)

    def test_empirical_max_overlap(self):
        """For random keys, maximum empirical overlap should be small."""
        overlaps = []
        for _ in range(200):
            k1 = os.urandom(16)
            k2 = os.urandom(16)
            overlaps.append(compute_overlap(k1, k2, 8))
        max_overlap = max(overlaps)
        # For random 256-bit strings, d_H is concentrated around 128
        # so overlap ≈ 0. Max should be well below 0.5 with high probability.
        assert max_overlap < 0.5, f"Max overlap {max_overlap} unexpectedly high"

    def test_empirical_min_hamming_distance(self):
        """Minimum Hamming distance should be well above 0 for random keys."""
        distances = []
        for _ in range(200):
            k1 = os.urandom(16)
            k2 = os.urandom(16)
            cw1 = encode(k1, 8)
            cw2 = encode(k2, 8)
            distances.append(hamming_distance(cw1, cw2))
        min_dist = min(distances)
        # Expected: concentrated around 128. Min should be > 50.
        assert min_dist > 50, f"Min Hamming distance {min_dist} is too small"


class TestFingerprintState:
    """Tests for quantum fingerprint state preparation."""

    def test_statevector_normalization(self):
        """Prepared statevector should be normalized (|ψ| = 1)."""
        k = os.urandom(16)
        cw = encode(k, 8)
        sv = prepare_statevector(cw, 8)
        # Check normalization
        norm = float(np.sqrt(np.sum(np.abs(sv.data) ** 2)))
        assert norm == pytest.approx(1.0, abs=1e-10)

    def test_statevector_amplitudes(self):
        """All amplitudes should be ±1/√N."""
        k = os.urandom(16)
        N = 256
        cw = encode(k, 8)
        sv = prepare_statevector(cw, 8)
        expected_magnitude = 1.0 / np.sqrt(N)
        for amp in sv.data:
            assert abs(abs(amp) - expected_magnitude) < 1e-10

    def test_circuit_matches_statevector(self):
        """Circuit preparation matches analytical statevector."""
        k = os.urandom(16)
        cw = encode(k, 8)
        sv_analytical = prepare_statevector(cw, 8)
        qc = prepare_circuit(cw, 8)
        sv_circuit = Statevector.from_instruction(qc)
        fidelity = float(abs(sv_analytical.inner(sv_circuit)))
        assert fidelity == pytest.approx(1.0, abs=1e-6)


class TestHadamardNegative:
    """NEGATIVE TEST: The old Hadamard construction is trivially invertible."""

    def test_original_hadamard_qowf_is_trivially_invertible(self):
        """
        H^⊗n |ψ_k⟩ = H^⊗n (H^⊗n |k⟩) = |k⟩.
        This proves the old construction provides ZERO security.
        
        Kept as a regression test per user requirement.
        """
        n = 4
        for k_int in range(2**n):
            k_bits = [(k_int >> i) & 1 for i in range(n)]
            
            # Prepare H^⊗n|k⟩
            sv = prepare_hadamard_state(k_bits, n)
            
            # Apply H^⊗n (inversion)
            from qiskit import QuantumCircuit
            qc = QuantumCircuit(n)
            qc.initialize(sv.data, range(n))
            for i in range(n):
                qc.h(i)
            recovered = Statevector.from_instruction(qc)
            
            # Measure — should recover |k⟩ with probability 1.0
            probs = recovered.probabilities_dict()
            k_bitstring = ''.join(str(b) for b in reversed(k_bits))
            assert probs.get(k_bitstring, 0) == pytest.approx(1.0, abs=1e-10), \
                f"Key {k_bits} not recovered: probs={probs}"


class TestEncodingStats:
    """Test encoding statistics measurement."""

    def test_measure_stats(self):
        """Encoding stats should return sensible values."""
        stats = measure_encoding_stats(n_samples=100, key_length_bytes=16, n_qubits=8)
        assert stats.n_samples == 100
        assert stats.codeword_length == 256
        # Mean Hamming distance should be near N/2 = 128
        assert 100 < stats.mean_hamming_distance < 156
        # Mean overlap should be near 0
        assert stats.mean_overlap < 0.3
        # Min Hamming distance should be > 0
        assert stats.min_hamming_distance > 0
