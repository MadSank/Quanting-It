"""
Test Suite: Quantum Teleportation Transport Layer
=================================================

Comprehensive test suite validating quantum teleportation as a transport/distribution
adaptation layer for quantum states and GC quantum public keys.

Validates:
  1. Canonical basis states: |0⟩, |1⟩, |+⟩, |-⟩
  2. Pauli corrections: X, Z, and X+Z (Y-equivalent)
  3. Arbitrary phase-encoded fingerprint states
  4. Fault injections:
     - Corrupted classical correction bits
     - Altered / disturbed Bell pairs
     - Depolarizing noise
     - Intercept/resend attacks
"""

import os
import pytest
import numpy as np
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

from src.teleportation import (
    create_teleportation_circuit,
    simulate_teleportation,
    teleport_fidelity_single_qubit,
    teleport_fingerprint_state,
)
from src.qowf import encode, prepare_statevector


class TestCanonicalStateTeleportation:
    """Validate teleportation circuit reconstruction for standard single-qubit states."""

    def test_teleport_zero_state(self):
        """Teleport |0⟩: Bob's reconstructed state must have fidelity 1.0."""
        qc = QuantumCircuit(1)  # already |0⟩
        c = create_teleportation_circuit(qc)
        fid = teleport_fidelity_single_qubit(c, Statevector.from_label("0"))
        assert fid == pytest.approx(1.0, abs=1e-5)

    def test_teleport_one_state(self):
        """Teleport |1⟩: Bob's reconstructed state must have fidelity 1.0."""
        qc = QuantumCircuit(1)
        qc.x(0)
        c = create_teleportation_circuit(qc)
        fid = teleport_fidelity_single_qubit(c, Statevector.from_label("1"))
        assert fid == pytest.approx(1.0, abs=1e-5)

    def test_teleport_plus_state(self):
        """Teleport |+⟩ = (|0⟩+|1⟩)/√2: Bob's reconstructed state must have fidelity 1.0."""
        qc = QuantumCircuit(1)
        qc.h(0)
        c = create_teleportation_circuit(qc)
        fid = teleport_fidelity_single_qubit(c, Statevector.from_label("+"))
        assert fid == pytest.approx(1.0, abs=1e-5)

    def test_teleport_minus_state(self):
        """Teleport |-⟩ = (|0⟩-|1⟩)/√2: Bob's reconstructed state must have fidelity 1.0."""
        qc = QuantumCircuit(1)
        qc.x(0)
        qc.h(0)
        c = create_teleportation_circuit(qc)
        fid = teleport_fidelity_single_qubit(c, Statevector.from_label("-"))
        assert fid == pytest.approx(1.0, abs=1e-5)


class TestPauliCorrectionsAndFaults:
    """Validate Bob's Pauli corrections and degradation under channel/classical faults."""

    def test_channel_pauli_x_disturbance(self):
        """Pauli-X error on input state flips |0⟩ to |1⟩."""
        qc = QuantumCircuit(1)  # |0⟩
        c = create_teleportation_circuit(qc, channel_error="X")
        # Receiving |1⟩ instead of |0⟩
        fid_to_zero = teleport_fidelity_single_qubit(c, Statevector.from_label("0"))
        fid_to_one = teleport_fidelity_single_qubit(c, Statevector.from_label("1"))
        assert fid_to_zero == pytest.approx(0.0, abs=1e-5)
        assert fid_to_one == pytest.approx(1.0, abs=1e-5)

    def test_channel_pauli_z_disturbance(self):
        """Pauli-Z error on input state flips |+⟩ to |-⟩."""
        qc = QuantumCircuit(1)
        qc.h(0)  # |+⟩
        c = create_teleportation_circuit(qc, channel_error="Z")
        fid_to_plus = teleport_fidelity_single_qubit(c, Statevector.from_label("+"))
        fid_to_minus = teleport_fidelity_single_qubit(c, Statevector.from_label("-"))
        assert fid_to_plus == pytest.approx(0.0, abs=1e-5)
        assert fid_to_minus == pytest.approx(1.0, abs=1e-5)

    def test_channel_pauli_y_disturbance(self):
        """Pauli-Y (simultaneous X+Z) error disturbs both basis and phase."""
        qc = QuantumCircuit(1)
        qc.h(0)  # |+⟩
        c = create_teleportation_circuit(qc, channel_error="Y")
        fid = teleport_fidelity_single_qubit(c, Statevector.from_label("+"))
        assert fid < 0.1

    def test_corrupted_classical_crx_bit(self):
        """Inverting classical X correction bit corrupts reconstructed state."""
        qc = QuantumCircuit(1)
        qc.x(0)  # |1⟩
        c = create_teleportation_circuit(qc, corrupt_crx=True)
        fid = teleport_fidelity_single_qubit(c, Statevector.from_label("1"))
        # Due to wrong X correction when crx=1, average fidelity drops
        assert fid < 0.9

    def test_corrupted_classical_crz_bit(self):
        """Inverting classical Z correction bit corrupts phase-sensitive state."""
        qc = QuantumCircuit(1)
        qc.h(0)  # |+⟩
        c = create_teleportation_circuit(qc, corrupt_crz=True)
        fid = teleport_fidelity_single_qubit(c, Statevector.from_label("+"))
        assert fid < 0.9

    def test_altered_bell_pair(self):
        """An altered Bell pair (|Ψ+⟩ instead of |Φ+⟩) degrades teleportation fidelity."""
        qc = QuantumCircuit(1)  # |0⟩
        c = create_teleportation_circuit(qc, bell_error="X")
        fid = teleport_fidelity_single_qubit(c, Statevector.from_label("0"))
        assert fid < 0.1


class TestFingerprintTeleportation:
    """Validate n-qubit quantum fingerprint teleportation and threat models."""

    def test_arbitrary_fingerprint_noiseless(self):
        """Noiseless teleportation preserves arbitrary 8-qubit fingerprint state."""
        key = os.urandom(16)
        cw = encode(key, 8)
        sv = prepare_statevector(cw, 8)

        reconstructed_sv, meta = teleport_fingerprint_state(sv, n_qubits=8, noise_rate=0.0)
        assert meta["fidelity"] == pytest.approx(1.0, abs=1e-5)
        assert meta["bell_pairs_consumed"] == 8
        assert len(meta["crz_bits"]) == 8
        assert len(meta["crx_bits"]) == 8

    def test_depolarizing_noise_reduces_fidelity(self):
        """Depolarizing noise degrades fingerprint state fidelity proportionally."""
        key = os.urandom(16)
        cw = encode(key, 8)
        sv = prepare_statevector(cw, 8)

        _, meta_clean = teleport_fingerprint_state(sv, n_qubits=8, noise_rate=0.0)
        _, meta_noisy = teleport_fingerprint_state(sv, n_qubits=8, noise_rate=0.20)

        assert meta_clean["fidelity"] == pytest.approx(1.0, abs=1e-5)
        assert meta_noisy["fidelity"] < 0.95

    def test_intercept_resend_destroys_fidelity(self):
        """Intercept-resend attack collapses superposition and drops fidelity."""
        key = os.urandom(16)
        cw = encode(key, 8)
        sv = prepare_statevector(cw, 8)

        _, meta = teleport_fingerprint_state(sv, n_qubits=8, intercept_resend=True)
        # Fingerprint in N=256 dim: collapsing to a computational basis state gives overlap^2 = 1/256 ≈ 0.0039
        assert meta["fidelity"] < 0.05

    def test_altered_bell_pair_fingerprint(self):
        """Altered Bell pairs alter the phase of the teleported fingerprint."""
        key = os.urandom(16)
        cw = encode(key, 8)
        sv = prepare_statevector(cw, 8)

        out_sv, meta = teleport_fingerprint_state(sv, n_qubits=8, altered_bell_pair=True)
        assert meta["fidelity"] < 0.1

    def test_corrupted_classical_bits_fingerprint(self):
        """Corrupted classical correction bits invert spatial basis of fingerprint."""
        key = os.urandom(16)
        cw = encode(key, 8)
        sv = prepare_statevector(cw, 8)

        out_sv, meta = teleport_fingerprint_state(sv, n_qubits=8, corrupt_classical_bits=True)
        # Flipped axes alter state, reducing overlap significantly
        assert meta["fidelity"] < 0.8
