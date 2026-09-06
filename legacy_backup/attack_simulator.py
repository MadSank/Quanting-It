"""
Attack Simulator for Quantum Channel Tampering and Eavesdropping.

This module builds Qiskit Aer NoiseModels representing adversary (Eve) actions
on the quantum channel during teleportation.

Supported Attack Vectors:
1. Bit-Flip Attack (Pauli-X error with probability p)
2. Phase-Flip Attack (Pauli-Z error with probability p)
3. Bit-Phase-Flip Attack (Pauli-Y error with probability p)
4. Depolarizing Channel Attack (Uniform Pauli X/Y/Z error with probability p)
5. Intercept-Resend Attack (Measurement disturbance / randomizing error with probability p)
"""

from qiskit_aer.noise import NoiseModel, pauli_error, depolarizing_error


def build_attack_noise_model(attack_type: str = "none", attack_strength: float = 0.0) -> NoiseModel:
    """
    Constructs a Qiskit Aer NoiseModel targeting the channel operation ('id' gate on qubit 2).

    Args:
        attack_type: 'none', 'bit_flip', 'phase_flip', 'bit_phase_flip', 'depolarizing', or 'intercept_resend'
        attack_strength: Attack probability p in range [0.0, 1.0]

    Returns:
        NoiseModel: Qiskit Aer noise model (or None if attack_strength == 0 or attack_type == 'none')
    """
    attack_type = str(attack_type).lower().strip()
    p = float(attack_strength)

    if attack_type in ["none", "legitimate", "no_attack"] or p <= 1e-6:
        return None

    p = min(max(p, 0.0), 1.0)
    noise_model = NoiseModel()

    if attack_type == "bit_flip":
        # Applies Pauli-X error with probability p
        err = pauli_error([('X', p), ('I', 1.0 - p)])
        noise_model.add_all_qubit_quantum_error(err, ['id'])

    elif attack_type == "phase_flip":
        # Applies Pauli-Z error with probability p
        err = pauli_error([('Z', p), ('I', 1.0 - p)])
        noise_model.add_all_qubit_quantum_error(err, ['id'])

    elif attack_type == "bit_phase_flip":
        # Applies Pauli-Y error with probability p
        err = pauli_error([('Y', p), ('I', 1.0 - p)])
        noise_model.add_all_qubit_quantum_error(err, ['id'])

    elif attack_type == "depolarizing":
        # Depolarizing noise channel with probability p
        err = depolarizing_error(p, 1)
        noise_model.add_all_qubit_quantum_error(err, ['id'])

    elif attack_type == "intercept_resend":
        # Intercept-Resend attack: Eve measures qubit in Z-basis with prob p and resends.
        # This collapses quantum coherence, causing 50% state error whenever intercepted.
        # Modeled as equal probability of X, Y, Z, or I disturbance when intercepted.
        err = pauli_error([('X', p / 3), ('Y', p / 3), ('Z', p / 3), ('I', 1.0 - p)])
        noise_model.add_all_qubit_quantum_error(err, ['id'])

    else:
        raise ValueError(f"Unsupported attack_type '{attack_type}'. Choose from 'none', 'bit_flip', 'phase_flip', 'bit_phase_flip', 'depolarizing', 'intercept_resend'.")

    return noise_model
