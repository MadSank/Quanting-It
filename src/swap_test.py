"""
SWAP Test — Quantum State Comparison Circuit
=============================================

Implements the SWAP test from Buhrman, Cleve, Watrous, de Wolf (2001),
as used in the Gottesman–Chuang QDS protocol for quantum state verification.

Circuit:
    |0⟩ ——H—— ●——— H —— M
               |
    |ψ⟩ ——————×———
               |
    |φ⟩ ——————×———

Theory:
    P(ancilla = 0) = (1 + |⟨ψ|φ⟩|²) / 2
    P(ancilla = 1) = (1 - |⟨ψ|φ⟩|²) / 2

    - Identical states: P(pass) = 1.0
    - Orthogonal states: P(pass) = 0.5
    - General: P(pass) = (1 + |⟨ψ|φ⟩|²) / 2

The SWAP test is a DESTRUCTIVE operation — both input states are
consumed by the measurement process.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector
from qiskit_aer import AerSimulator


@dataclass
class SwapTestResult:
    """Result of a single SWAP test execution."""
    passed: bool              # True if ancilla measured 0 (states match)
    n_shots: int              # Total shots executed
    n_pass: int               # Number of times ancilla = 0
    n_fail: int               # Number of times ancilla = 1
    acceptance_rate: float    # n_pass / n_shots
    theoretical_rate: float | None = None  # (1 + |overlap|^2) / 2 if known


def analytical_acceptance_probability(overlap: float) -> float:
    """
    Compute theoretical SWAP test acceptance probability from state overlap.

    P(pass) = (1 + |⟨ψ|φ⟩|²) / 2

    Args:
        overlap: |⟨ψ|φ⟩| (absolute value of inner product).

    Returns:
        Probability that the SWAP test ancilla measures 0.
    """
    return (1.0 + overlap ** 2) / 2.0


def build_swap_test_circuit(
    state1: Statevector,
    state2: Statevector,
    n_qubits: int,
) -> QuantumCircuit:
    """
    Build a SWAP test circuit for two n-qubit states.

    Qubit layout:
        qubit 0: ancilla
        qubits 1..n: state 1
        qubits n+1..2n: state 2

    Total qubits: 2n + 1.

    Args:
        state1: First n-qubit statevector.
        state2: Second n-qubit statevector.
        n_qubits: Number of qubits per state.

    Returns:
        QuantumCircuit implementing the SWAP test with measurement on ancilla.
    """
    total_qubits = 2 * n_qubits + 1
    qc = QuantumCircuit(total_qubits, 1)

    # Initialize states
    # State 1 on qubits [1, ..., n]
    qc.initialize(state1.data, list(range(1, n_qubits + 1)))
    # State 2 on qubits [n+1, ..., 2n]
    qc.initialize(state2.data, list(range(n_qubits + 1, 2 * n_qubits + 1)))

    # Hadamard on ancilla
    qc.h(0)

    # Controlled-SWAP for each pair of qubits
    for i in range(n_qubits):
        qc.cswap(0, 1 + i, n_qubits + 1 + i)

    # Hadamard on ancilla
    qc.h(0)

    # Measure ancilla
    qc.measure(0, 0)

    return qc


def run_swap_test(
    state1: Statevector,
    state2: Statevector,
    n_qubits: int,
    shots: int = 1,
    sim: AerSimulator | None = None,
) -> SwapTestResult:
    """
    Execute a SWAP test between two n-qubit quantum states.

    This is a DESTRUCTIVE operation. In a real protocol, the stored
    quantum public key copy used for comparison is consumed.

    Args:
        state1: First n-qubit statevector (e.g., freshly prepared |f_k⟩).
        state2: Second n-qubit statevector (e.g., stored quantum public key copy).
        n_qubits: Number of qubits per state.
        shots: Number of measurement shots.
        sim: AerSimulator instance (created if None).

    Returns:
        SwapTestResult with pass/fail outcome and statistics.
    """
    if sim is None:
        sim = AerSimulator()

    qc = build_swap_test_circuit(state1, state2, n_qubits)
    result = sim.run(qc, shots=shots).result()
    counts = result.get_counts()

    n_pass = counts.get("0", 0)
    n_fail = counts.get("1", 0)
    acceptance_rate = n_pass / shots

    # Compute theoretical rate from analytical overlap
    overlap = float(abs(state1.inner(state2)))
    theoretical = analytical_acceptance_probability(overlap)

    return SwapTestResult(
        passed=(n_pass > n_fail) if shots > 1 else (n_pass == 1),
        n_shots=shots,
        n_pass=n_pass,
        n_fail=n_fail,
        acceptance_rate=acceptance_rate,
        theoretical_rate=theoretical,
    )


def run_single_shot_swap_test(
    state1: Statevector,
    state2: Statevector,
    n_qubits: int,
    sim: AerSimulator | None = None,
) -> bool:
    """
    Run a single-shot SWAP test. Returns True if passed (states match).

    This is the operational mode used in the GC verification protocol:
    one shot per position, consuming the stored public key copy.
    """
    result = run_swap_test(state1, state2, n_qubits, shots=1, sim=sim)
    return result.passed
