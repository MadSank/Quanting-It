"""
Quantum Digital Signature (QDS) State Verification and Analysis Module.

This module coordinates running quantum teleportation experiments under optional
channel attack parameters, parses measurement outcome counts, and calculates
key metrics:
- Quantum Bit Error Rate (QBER)
- Reconstructed State Fidelity
- Verification Success Rate (VSR)
- Measurement Outcome Breakdown
"""

from typing import Dict, Any, Tuple
from src.teleportation import build_teleportation_circuit, run_teleportation_simulation
from src.attack_simulator import build_attack_noise_model


def parse_teleportation_counts(counts: Dict[str, int]) -> Dict[str, Any]:
    """
    Parses Qiskit Aer outcome count dictionary.

    Keys are formatted as "c_bob c_alice", e.g. "0 01", "1 10".
    
    Returns:
        Dict containing total_shots, success_count, error_count, qber, fidelity,
        and alice_measurement_counts.
    """
    total_shots = sum(counts.values())
    error_count = 0
    success_count = 0
    alice_counts = {"00": 0, "01": 0, "10": 0, "11": 0}
    bob_counts = {"0": 0, "1": 0}

    for key, count in counts.items():
        parts = key.strip().split()
        if len(parts) == 2:
            bob_bit, alice_bits = parts[0], parts[1]
        elif len(parts) == 1:
            # Single string fallback: first char is bob_bit, rest is alice_bits
            bob_bit = parts[0][0]
            alice_bits = parts[0][1:]
        else:
            bob_bit = '0'
            alice_bits = '00'

        bob_counts[bob_bit] = bob_counts.get(bob_bit, 0) + count
        alice_counts[alice_bits] = alice_counts.get(alice_bits, 0) + count

        if bob_bit == '1':
            error_count += count
        else:
            success_count += count

    qber = error_count / total_shots if total_shots > 0 else 0.0
    fidelity = success_count / total_shots if total_shots > 0 else 1.0

    return {
        "total_shots": total_shots,
        "success_count": success_count,
        "error_count": error_count,
        "qber": qber,
        "fidelity": fidelity,
        "verification_success_rate": fidelity,
        "bob_counts": bob_counts,
        "alice_counts": alice_counts,
        "raw_counts": counts
    }


def run_qds_teleportation_experiment(
    state_name: str = "0",
    theta: float = 0.0,
    phi: float = 0.0,
    attack_type: str = "none",
    attack_strength: float = 0.0,
    shots: int = 1000,
    seed_simulator: int = None
) -> Dict[str, Any]:
    """
    Runs a complete QDS teleportation pipeline experiment.

    Args:
        state_name: '0', '1', '+', '-', or 'custom'
        theta: Angle theta for custom state (if state_name == 'custom')
        phi: Angle phi for custom state (if state_name == 'custom')
        attack_type: 'none', 'bit_flip', 'phase_flip', 'bit_phase_flip', 'depolarizing', 'intercept_resend'
        attack_strength: Attack probability p in [0.0, 1.0]
        shots: Number of quantum measurement shots
        seed_simulator: Optional random seed for reproducible runs

    Returns:
        Dict containing experiment configuration and parsed measurement results.
    """
    circuit = build_teleportation_circuit(
        state_name=state_name,
        theta=theta,
        phi=phi,
        verification_mode=True
    )

    noise_model = build_attack_noise_model(
        attack_type=attack_type,
        attack_strength=attack_strength
    )

    raw_counts = run_teleportation_simulation(
        circuit=circuit,
        noise_model=noise_model,
        shots=shots,
        seed_simulator=seed_simulator
    )

    parsed = parse_teleportation_counts(raw_counts)

    return {
        "config": {
            "state_name": state_name,
            "theta": theta,
            "phi": phi,
            "attack_type": attack_type,
            "attack_strength": attack_strength,
            "shots": shots,
        },
        "circuit": circuit,
        "metrics": parsed
    }
