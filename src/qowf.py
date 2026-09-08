"""
Quantum One-Way Function (QOWF) — GC-style Quantum Fingerprints
================================================================

Implements the quantum fingerprint state construction from the
Gottesman–Chuang quantum digital signature protocol (quant-ph/0105032).

Construction:
    For a classical key k of length L bits:
        1. Encode k into an N-bit codeword E(k) via deterministic binary expansion
        2. Prepare quantum fingerprint state:
           |f_k⟩ = 1/√N  Σ_{j=0}^{N-1} (-1)^{E(k)_j} |j⟩
           where N = 2^n and n = number of qubits.

Overlap identity:
    ⟨f_k | f_k'⟩ = 1 - 2·d_H(E(k), E(k')) / N

    Therefore: |⟨f_k | f_k'⟩| = |1 - 2·d_H(E(k), E(k')) / N|

    This is controlled directly by the Hamming distance of the encoding.

One-wayness (Holevo bound):
    Given T copies of |f_k⟩ (an n-qubit state), an adversary learns at most
    Tn classical bits about k. Security requires L - Tn >> 1.

ENCODING NOTE:
    The current encoding uses a deterministic pseudorandom codeword/fingerprint
    encoding for the prototype (HMAC-SHA256 expansion). This is NOT a formal
    error-correcting code and does NOT have a mathematically proven minimum distance.
    Hamming distance statistics are measured empirically. A mathematically defined
    binary linear error-correcting code with proven distance is a future hardening step.
"""

from __future__ import annotations

import hmac
import hashlib
from dataclasses import dataclass

import numpy as np
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector


# ---------------------------------------------------------------------------
#  Default parameters (all configurable)
# ---------------------------------------------------------------------------
DEFAULT_PRIVATE_KEY_BITS = 128   # L
DEFAULT_FINGERPRINT_QUBITS = 8  # n  →  N = 2^n = 256
# NOTE: These parameters are simulation/demo scale.
# They do NOT provide production cryptographic security.


# ---------------------------------------------------------------------------
#  Encoding: classical key → binary codeword
# ---------------------------------------------------------------------------

def encode(k: bytes, n_qubits: int = DEFAULT_FINGERPRINT_QUBITS) -> list[int]:
    """
    Deterministic binary expansion of L-byte key k to N = 2^n_qubits bit codeword.

    Uses HMAC-SHA256 with sequential block counters to produce N bits
    deterministically from the key material.

    This is a deterministic pseudorandom codeword/fingerprint encoding for
    the prototype, NOT a formal error-correcting code with proven minimum distance.
    Hamming distance properties are pseudorandom and measured empirically.

    Args:
        k: Classical key bytes (length L/8).
        n_qubits: Number of fingerprint qubits. Codeword length N = 2^n_qubits.

    Returns:
        List of N bits (0 or 1).
    """
    N = 2 ** n_qubits
    bits: list[int] = []
    block = 0
    while len(bits) < N:
        h = hmac.new(k, f"qowf-expand-{block}".encode(), hashlib.sha256).digest()
        for byte_val in h:
            for bit_pos in range(8):
                if len(bits) < N:
                    bits.append((byte_val >> bit_pos) & 1)
        block += 1
    return bits[:N]


# ---------------------------------------------------------------------------
#  Hamming distance utilities
# ---------------------------------------------------------------------------

def hamming_distance(cw1: list[int], cw2: list[int]) -> int:
    """Compute Hamming distance between two equal-length binary codewords."""
    if len(cw1) != len(cw2):
        raise ValueError(f"Codeword lengths differ: {len(cw1)} vs {len(cw2)}")
    return sum(a != b for a, b in zip(cw1, cw2))


def overlap_from_hamming(d_h: int, N: int) -> float:
    """
    Compute quantum fingerprint overlap from Hamming distance.

    |⟨f_k | f_k'⟩| = |1 - 2·d_H / N|
    """
    return abs(1.0 - 2.0 * d_h / N)


# ---------------------------------------------------------------------------
#  Quantum fingerprint state preparation
# ---------------------------------------------------------------------------

def prepare_statevector(codeword: list[int], n_qubits: int) -> Statevector:
    """
    Prepare quantum fingerprint state as a Statevector (analytical).

    |f_k⟩ = 1/√N  Σ_{j=0}^{N-1} (-1)^{codeword_j}  |j⟩

    Args:
        codeword: N-bit binary codeword (list of 0s and 1s).
        n_qubits: Number of qubits (N = 2^n_qubits).

    Returns:
        Statevector representing |f_k⟩.
    """
    N = 2 ** n_qubits
    if len(codeword) != N:
        raise ValueError(f"Codeword length {len(codeword)} != N={N}")

    amplitudes = np.array(
        [(-1) ** codeword[j] / np.sqrt(N) for j in range(N)],
        dtype=complex,
    )
    return Statevector(amplitudes)


def prepare_circuit(codeword: list[int], n_qubits: int) -> QuantumCircuit:
    """
    Prepare quantum fingerprint state as a QuantumCircuit using initialize().

    This uses Qiskit's initialize() instruction which decomposes into
    elementary gates internally. For simulation, this is equivalent to
    direct statevector preparation.

    Args:
        codeword: N-bit binary codeword.
        n_qubits: Number of qubits.

    Returns:
        QuantumCircuit that prepares |f_k⟩.
    """
    sv = prepare_statevector(codeword, n_qubits)
    qc = QuantumCircuit(n_qubits)
    qc.initialize(sv.data, range(n_qubits))
    return qc


# ---------------------------------------------------------------------------
#  Overlap computation
# ---------------------------------------------------------------------------

def compute_overlap(k1: bytes, k2: bytes,
                    n_qubits: int = DEFAULT_FINGERPRINT_QUBITS) -> float:
    """
    Compute |⟨f_{k1} | f_{k2}⟩| analytically via Hamming distance.

    Uses the identity:
        ⟨f_k | f_k'⟩ = 1 - 2·d_H(E(k), E(k')) / N

    Args:
        k1, k2: Classical keys (bytes).
        n_qubits: Fingerprint qubit count.

    Returns:
        Absolute overlap |⟨f_{k1} | f_{k2}⟩|.
    """
    cw1 = encode(k1, n_qubits)
    cw2 = encode(k2, n_qubits)
    d_h = hamming_distance(cw1, cw2)
    return overlap_from_hamming(d_h, 2 ** n_qubits)


def compute_overlap_statevector(k1: bytes, k2: bytes,
                                n_qubits: int = DEFAULT_FINGERPRINT_QUBITS) -> float:
    """
    Compute |⟨f_{k1} | f_{k2}⟩| by constructing statevectors and taking inner product.

    This serves as a cross-check against the analytical Hamming-distance formula.
    """
    cw1 = encode(k1, n_qubits)
    cw2 = encode(k2, n_qubits)
    sv1 = prepare_statevector(cw1, n_qubits)
    sv2 = prepare_statevector(cw2, n_qubits)
    return float(abs(sv1.inner(sv2)))


# ---------------------------------------------------------------------------
#  Negative test: Hadamard construction (KNOWN BROKEN)
# ---------------------------------------------------------------------------

def prepare_hadamard_state(k_bits: list[int], n_qubits: int) -> Statevector:
    """
    Prepare the REJECTED Hadamard construction: |ψ_k⟩ = H^⊗n |k⟩.

    THIS IS TRIVIALLY INVERTIBLE: H^⊗n |ψ_k⟩ = |k⟩.
    Kept ONLY as a negative/regression test to demonstrate why
    this construction was rejected as a QOWF.

    Args:
        k_bits: n-bit key as list of 0s and 1s.
        n_qubits: Number of qubits (must equal len(k_bits)).

    Returns:
        Statevector of H^⊗n |k⟩.
    """
    if len(k_bits) != n_qubits:
        raise ValueError(f"k_bits length {len(k_bits)} != n_qubits {n_qubits}")

    qc = QuantumCircuit(n_qubits)
    for i, b in enumerate(k_bits):
        if b == 1:
            qc.x(i)
    for i in range(n_qubits):
        qc.h(i)
    return Statevector.from_instruction(qc)


# ---------------------------------------------------------------------------
#  Encoding statistics
# ---------------------------------------------------------------------------

@dataclass
class EncodingStats:
    """Statistics of the binary expansion encoding for a sample of key pairs."""
    n_samples: int
    n_qubits: int
    codeword_length: int
    mean_hamming_distance: float
    min_hamming_distance: int
    max_hamming_distance: int
    std_hamming_distance: float
    mean_overlap: float
    max_overlap: float
    min_overlap: float


def measure_encoding_stats(n_samples: int = 1000,
                           key_length_bytes: int = 16,
                           n_qubits: int = DEFAULT_FINGERPRINT_QUBITS) -> EncodingStats:
    """
    Empirically measure Hamming distance and overlap statistics
    for the prototype encoding by sampling random key pairs.

    Args:
        n_samples: Number of random key pairs to sample.
        key_length_bytes: Length of each key in bytes (L = 8 * key_length_bytes).
        n_qubits: Fingerprint qubit count.

    Returns:
        EncodingStats with measured statistics.
    """
    import os
    N = 2 ** n_qubits
    distances = []
    for _ in range(n_samples):
        k1 = os.urandom(key_length_bytes)
        k2 = os.urandom(key_length_bytes)
        cw1 = encode(k1, n_qubits)
        cw2 = encode(k2, n_qubits)
        distances.append(hamming_distance(cw1, cw2))

    d_arr = np.array(distances)
    overlaps = np.array([overlap_from_hamming(d, N) for d in distances])

    return EncodingStats(
        n_samples=n_samples,
        n_qubits=n_qubits,
        codeword_length=N,
        mean_hamming_distance=float(d_arr.mean()),
        min_hamming_distance=int(d_arr.min()),
        max_hamming_distance=int(d_arr.max()),
        std_hamming_distance=float(d_arr.std()),
        mean_overlap=float(overlaps.mean()),
        max_overlap=float(overlaps.max()),
        min_overlap=float(overlaps.min()),
    )
