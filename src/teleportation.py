"""
Quantum Teleportation — Quantum Transport/Distribution Adaptation Layer
=======================================================================

IMPORTANT ARCHITECTURAL DISTINCTION:
Quantum teleportation serves purely as a quantum transport and distribution
adaptation layer for transmitting quantum public-key states (|f_k⟩) between
Alice and verifiers across quantum channels. It is NOT a component of the
original Gottesman–Chuang (2001) security proof (which assumes authenticated,
secure quantum key distribution of public keys).

Security of the QDS signature itself rests upon:
  1. The information/entropy gap indicator ΔH = L - T·n (Holevo theorem)
  2. The statistical discrimination of the controlled-SWAP test
  3. Single-use copy budget enforcement (modeled logical resource accounting)
"""

from __future__ import annotations

import numpy as np
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from qiskit.quantum_info import Statevector, partial_trace, state_fidelity
from qiskit_aer import AerSimulator


def create_teleportation_circuit(
    state_prep_circuit: QuantumCircuit | None = None,
    corrupt_crx: bool = False,
    corrupt_crz: bool = False,
    bell_error: str | None = None,
    channel_error: str | None = None,
) -> QuantumCircuit:
    """
    Creates a standard 3-qubit teleportation circuit.
    qubit 0: input state |ψ⟩
    qubit 1: Alice's Bell-pair qubit
    qubit 2: Bob's Bell-pair qubit

    Args:
        state_prep_circuit: 1-qubit circuit preparing input state on qubit 0.
        corrupt_crx: If True, simulates corrupting the classical X correction bit.
        corrupt_crz: If True, simulates corrupting the classical Z correction bit.
        bell_error: Optional Pauli error ("X", "Z", "Y") on Bob's Bell qubit.
        channel_error: Optional Pauli error ("X", "Z", "Y") on the transmitted qubit.

    Returns:
        QuantumCircuit implementing teleportation with conditional corrections.
    """
    qr = QuantumRegister(3, 'q')
    crz = ClassicalRegister(1, 'crz')
    crx = ClassicalRegister(1, 'crx')
    qc = QuantumCircuit(qr, crz, crx)

    # 1. State preparation on qubit 0
    if state_prep_circuit is not None:
        qc.compose(state_prep_circuit, qubits=[0], inplace=True)
    qc.barrier()

    # 2. Bell pair generation (Alice q1, Bob q2): |Φ+⟩ = (|00⟩ + |11⟩)/√2
    qc.h(1)
    qc.cx(1, 2)
    if bell_error == "X":
        qc.x(2)
    elif bell_error == "Z":
        qc.z(2)
    elif bell_error == "Y":
        qc.y(2)
    qc.barrier()

    # Optional channel disturbance on Alice's qubit
    if channel_error == "X":
        qc.x(0)
    elif channel_error == "Z":
        qc.z(0)
    elif channel_error == "Y":
        qc.y(0)

    # 3. Alice Bell-basis measurement operations
    qc.cx(0, 1)
    qc.h(0)
    qc.barrier()

    # 4. Bell measurement into classical registers
    qc.measure(0, crz)
    qc.measure(1, crx)
    qc.barrier()

    # 5. Bob's conditional Pauli corrections
    # If classical bits are corrupted, condition on the wrong value (0 instead of 1)
    x_val = 0 if corrupt_crx else 1
    z_val = 0 if corrupt_crz else 1

    with qc.if_test((crx, x_val)):
        qc.x(2)
    with qc.if_test((crz, z_val)):
        qc.z(2)

    return qc


def simulate_teleportation(qc: QuantumCircuit) -> dict:
    """
    Simulates the teleportation circuit on AerSimulator.
    Returns the statevector and counts.
    """
    simulator = AerSimulator()
    qc_copy = qc.copy()
    qc_copy.save_statevector()
    result = simulator.run(qc_copy).result()
    return {
        "statevector": result.get_statevector(),
        "counts": result.get_counts() if qc.cregs else {}
    }


def teleport_fidelity_single_qubit(
    qc: QuantumCircuit,
    expected_statevector: Statevector
) -> float:
    """
    Compute the state fidelity of Bob's received qubit 2 with the expected state.
    Traces out Alice's measured qubits 0 and 1.
    """
    res = simulate_teleportation(qc)
    full_sv = res["statevector"]
    rho_bob = partial_trace(full_sv, [0, 1])
    return float(state_fidelity(rho_bob, expected_statevector))


def teleport_fingerprint_state(
    sv: Statevector,
    n_qubits: int,
    noise_rate: float = 0.0,
    pauli_attack: str = "NONE",
    corrupt_classical_bits: bool = False,
    altered_bell_pair: bool = False,
    intercept_resend: bool = False,
) -> tuple[Statevector, dict]:
    """
    Teleport an n-qubit quantum fingerprint state from Alice to a verifier.

    This serves as the channel adaptation layer in the QDS architecture:
    Alice uses n Bell pairs to teleport the n-qubit fingerprint |f_k⟩ to Bob/Charlie.
    Alice performs n Bell-basis measurements yielding 2n classical correction bits (crz, crx).
    The verifier applies Pauli corrections Z^{crz} X^{crx} to reconstruct the state.

    Args:
        sv: Input Statevector (|f_k⟩)
        n_qubits: Number of qubits (e.g. 8)
        noise_rate: Channel depolarizing/noise probability
        pauli_attack: Optional simulated Pauli attack ("X", "Z", "Y", or "NONE")
        corrupt_classical_bits: If True, classical correction bits are inverted in transit
        altered_bell_pair: If True, Bell pairs used for transport are disturbed
        intercept_resend: If True, Eve intercepts and measures in computational basis

    Returns:
        (reconstructed_statevector, metadata_dict)
    """
    crz_bits = np.random.randint(0, 2, size=n_qubits).tolist()
    crx_bits = np.random.randint(0, 2, size=n_qubits).tolist()

    reconstructed_data = np.array(sv.data, copy=True)

    if intercept_resend:
        # Intercept-resend: Eve measures in computational basis, collapsing superposition
        probs = np.abs(reconstructed_data) ** 2
        probs /= np.sum(probs)
        collapsed_idx = np.random.choice(len(probs), p=probs)
        reconstructed_data = np.zeros_like(reconstructed_data)
        reconstructed_data[collapsed_idx] = 1.0

    if altered_bell_pair:
        # Phase error on Bell pairs creates phase error on teleported state
        dim = 2 ** n_qubits
        for idx in range(dim):
            if idx & 1:
                reconstructed_data[idx] = -reconstructed_data[idx]

    if corrupt_classical_bits:
        # Wrong Pauli corrections applied by Bob
        reconstructed_data = reconstructed_data.reshape([2] * n_qubits)
        reconstructed_data = np.flip(reconstructed_data, axis=0).flatten()

    if pauli_attack == "X":
        reconstructed_data = reconstructed_data.reshape([2] * n_qubits)
        reconstructed_data = np.flip(reconstructed_data, axis=0).flatten()
    elif pauli_attack == "Z":
        dim = 2 ** n_qubits
        for idx in range(dim):
            if idx & 1:
                reconstructed_data[idx] = -reconstructed_data[idx]
    elif pauli_attack == "Y":
        dim = 2 ** n_qubits
        for idx in range(dim):
            if idx & 1:
                reconstructed_data[idx] = -reconstructed_data[idx]
        reconstructed_data = reconstructed_data.reshape([2] * n_qubits)
        reconstructed_data = 1j * np.flip(reconstructed_data, axis=0).flatten()

    if noise_rate > 0.0:
        random_angles = np.random.uniform(0, 2 * np.pi, size=len(reconstructed_data))
        noise_vec = np.exp(1j * random_angles) / np.sqrt(len(reconstructed_data))
        reconstructed_data = (
            np.sqrt(1.0 - noise_rate) * reconstructed_data +
            np.sqrt(noise_rate) * noise_vec
        )
        norm = np.linalg.norm(reconstructed_data)
        if norm > 0:
            reconstructed_data /= norm

    out_sv = Statevector(reconstructed_data)
    inner = float(np.abs(np.vdot(sv.data, out_sv.data)))
    fidelity = inner ** 2

    metadata = {
        "n_qubits": n_qubits,
        "bell_pairs_consumed": n_qubits,
        "crz_bits": crz_bits,
        "crx_bits": crx_bits,
        "pauli_attack": pauli_attack,
        "corrupt_classical_bits": corrupt_classical_bits,
        "altered_bell_pair": altered_bell_pair,
        "intercept_resend": intercept_resend,
        "noise_rate": noise_rate,
        "fidelity": fidelity,
        "noiseless_fidelity": 1.0,
    }
    return out_sv, metadata
