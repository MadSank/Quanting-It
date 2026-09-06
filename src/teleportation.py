from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from qiskit_aer import AerSimulator
import numpy as np

def create_teleportation_circuit(state_prep_circuit: QuantumCircuit = None) -> QuantumCircuit:
    """
    Creates a standard 3-qubit teleportation circuit.
    qubit 0: input state
    qubit 1: Alice's Bell-pair qubit
    qubit 2: Bob's Bell-pair qubit
    """
    qr = QuantumRegister(3, 'q')
    crz = ClassicalRegister(1, 'crz')
    crx = ClassicalRegister(1, 'crx')
    qc = QuantumCircuit(qr, crz, crx)

    # 1. State preparation
    if state_prep_circuit is not None:
        qc.compose(state_prep_circuit, qubits=[0], inplace=True)
    qc.barrier()

    # 2. Bell pair generation (Alice q1, Bob q2)
    qc.h(1)
    qc.cx(1, 2)
    qc.barrier()

    # 3. Alice operations
    qc.cx(0, 1)
    qc.h(0)
    qc.barrier()

    # 4. Bell measurement
    qc.measure(0, crz)
    qc.measure(1, crx)
    qc.barrier()

    # 5. Bob's conditional Pauli corrections
    with qc.if_test((crx, 1)):
        qc.x(2)
    with qc.if_test((crz, 1)):
        qc.z(2)
        
    return qc

def simulate_teleportation(qc: QuantumCircuit) -> dict:
    """
    Simulates the teleportation circuit on AerSimulator.
    Returns the statevector or counts depending on whether a final measurement is added.
    """
    simulator = AerSimulator()
    qc.save_statevector()
    result = simulator.run(qc).result()
    return {
        "statevector": result.get_statevector(),
        "counts": result.get_counts() if qc.cregs else {}
    }
