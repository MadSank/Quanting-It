"""
Quantum Teleportation Circuit Builder and Simulator using Qiskit 1.x / 2.x.

This module constructs the 3-qubit quantum teleportation protocol:
  Qubit 0: Alice's input state |psi> (Signature payload)
  Qubit 1: Alice's half of the EPR Bell pair
  Qubit 2: Bob's half of the EPR Bell pair

It supports state preparation in standard bases (|0>, |1>, |+>, |->, or custom angle theta, phi),
Bell-state entanglement, Bell measurement, classical communication with Pauli corrections,
and verification basis rotations.
"""

import numpy as np
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from qiskit_aer import AerSimulator
from qiskit_aer.noise import NoiseModel


def prepare_input_state(circuit: QuantumCircuit, qubit_idx: int, state_name: str = "0", theta: float = 0.0, phi: float = 0.0):
    """Applies gate sequence to prepare Alice's input state on the specified qubit."""
    state_name = str(state_name).lower()
    if state_name == "0":
        pass  # Qubit starts in |0>
    elif state_name == "1":
        circuit.x(qubit_idx)
    elif state_name in ["+", "plus"]:
        circuit.h(qubit_idx)
    elif state_name in ["-", "minus"]:
        circuit.x(qubit_idx)
        circuit.h(qubit_idx)
    elif state_name == "custom":
        circuit.ry(theta, qubit_idx)
        circuit.rz(phi, qubit_idx)
    else:
        raise ValueError(f"Unknown state_name '{state_name}'. Choose from '0', '1', '+', '-', 'custom'.")


def apply_inverse_state_prep(circuit: QuantumCircuit, qubit_idx: int, state_name: str = "0", theta: float = 0.0, phi: float = 0.0):
    """Applies inverse rotation U_prep^dagger to map the reconstructed state back to |0> for QBER measurement."""
    state_name = str(state_name).lower()
    if state_name == "0":
        pass
    elif state_name == "1":
        circuit.x(qubit_idx)
    elif state_name in ["+", "plus"]:
        circuit.h(qubit_idx)
    elif state_name in ["-", "minus"]:
        circuit.h(qubit_idx)
        circuit.x(qubit_idx)
    elif state_name == "custom":
        circuit.rz(-phi, qubit_idx)
        circuit.ry(-theta, qubit_idx)
    else:
        raise ValueError(f"Unknown state_name '{state_name}'.")


def build_teleportation_circuit(
    state_name: str = "0",
    theta: float = 0.0,
    phi: float = 0.0,
    verification_mode: bool = True
) -> QuantumCircuit:
    """
    Builds the standard 3-qubit quantum teleportation circuit.
    
    Args:
        state_name: '0', '1', '+', '-', or 'custom'
        theta: Angle theta for custom state (0 to pi)
        phi: Angle phi for custom state (0 to 2*pi)
        verification_mode: If True, Bob applies inverse state prep to measure QBER (outcome '0' = correct).
                          If False, Bob measures in Z-basis directly.
    """
    qr = QuantumRegister(3, 'q')
    cr_alice = ClassicalRegister(2, 'c_alice')
    cr_bob = ClassicalRegister(1, 'c_bob')
    qc = QuantumCircuit(qr, cr_alice, cr_bob, name="Quantum_Teleportation")

    # Step 1: Alice state preparation on qubit 0
    prepare_input_state(qc, 0, state_name, theta, phi)

    # Step 2: Entanglement generation (Bell state |Phi+> between qubit 1 and qubit 2)
    qc.h(1)
    qc.cx(1, 2)

    # Step 3: Target channel operation location on Bob's qubit (identity placeholder)
    qc.id(2)

    # Step 4: Alice Bell Measurement on qubits 0 and 1
    qc.cx(0, 1)
    qc.h(0)
    qc.measure(0, cr_alice[0])
    qc.measure(1, cr_alice[1])

    # Step 5: Classical communication & Pauli corrections on Bob's qubit (qubit 2)
    with qc.if_test((cr_alice[1], 1)):
        qc.x(2)
    with qc.if_test((cr_alice[0], 1)):
        qc.z(2)

    # Step 6: Bob's Measurement
    if verification_mode:
        # Inverse state prep turns expected state |psi> into |0>
        apply_inverse_state_prep(qc, 2, state_name, theta, phi)
    
    qc.measure(2, cr_bob[0])

    return qc


def run_teleportation_simulation(
    circuit: QuantumCircuit,
    noise_model: NoiseModel = None,
    shots: int = 1000,
    seed_simulator: int = None
) -> dict:
    """
    Executes the teleportation circuit on AerSimulator and returns the raw outcome counts.
    """
    sim = AerSimulator(noise_model=noise_model, seed_simulator=seed_simulator)
    result = sim.run(circuit, shots=shots).result()
    counts = result.get_counts(circuit)
    return counts
