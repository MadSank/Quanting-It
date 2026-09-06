"""
[QUANTUM DIGITAL SIGNATURE - VERIFICATION]

Bob's QDS verification module. Statistical, not binary.

Protocol:
1. Bob re-derives the signing specification from the message hash.
2. Verify ML-DSA auth tag on correction bits (prevents classical DoS).
3. For each teleported qubit: apply Pauli corrections, measure in derived basis.
4. Compute mismatch rate and pass to ThreatEngine for evaluation.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

from src.qds_signer import QDSSignature, derive_signing_spec
from src.classical_channel import ClassicalChannelAuth


@dataclass
class QDSVerificationResult:
    """
    Statistical verification output from Bob's QDS check.
    """
    qubit_results: List[Dict[str, Any]]  # per-qubit {expected, measured, match}
    aggregate_mismatch_rate: float
    n_qubits: int
    n_mismatches: int
    is_valid: bool  # mismatch <= threshold
    correction_bits_valid: bool  # ML-DSA tag check


class QDSVerifier:
    """
    Bob's QDS verification engine. Performs projective measurements
    on teleported states and computes statistical mismatch rates.
    """

    def __init__(self, mismatch_threshold: float = 0.05):
        """
        Args:
            mismatch_threshold: Maximum acceptable mismatch rate (default 5%)
        """
        self.mismatch_threshold = mismatch_threshold
        self.sim = AerSimulator()

    def verify(self, signature: QDSSignature, message_hash: str,
               session_auth_context: str) -> QDSVerificationResult:
        """
        Verify a QDS signature by re-deriving the spec, checking correction
        bit integrity, and performing projective measurements.

        Args:
            signature: The QDSSignature to verify
            message_hash: Independently computed message hash
            session_auth_context: Shared auth context from QPKD

        Returns:
            QDSVerificationResult with statistical mismatch data
        """
        # Step 1: Verify correction bit integrity (ML-DSA)
        correction_bits_valid = True
        if signature.correction_auth_tag and signature.classical_pub_key:
            correction_bits_valid = ClassicalChannelAuth.verify_correction_bits(
                signature.correction_bits,
                signature.session_id,
                signature.sequence_number,
                signature.correction_auth_tag,
                signature.classical_pub_key,
            )

        if not correction_bits_valid:
            # Classical channel tampered — reject immediately
            return QDSVerificationResult(
                qubit_results=[],
                aggregate_mismatch_rate=1.0,
                n_qubits=signature.n_qubits,
                n_mismatches=signature.n_qubits,
                is_valid=False,
                correction_bits_valid=False,
            )

        # Step 2: Re-derive signing specification
        expected_spec = derive_signing_spec(
            message_hash, session_auth_context, signature.n_qubits
        )

        # Step 3: Projective measurement on each teleported qubit
        qubit_results = []
        n_mismatches = 0

        for i, spec in enumerate(expected_spec):
            if i >= len(signature.teleported_states):
                # Missing qubit — automatic mismatch
                qubit_results.append({
                    "index": i,
                    "expected_state": spec["state"],
                    "expected_bit": '1' if spec["state"] in ['|1>', '|->'] else '0',
                    "measured_bit": None,
                    "match": False,
                })
                n_mismatches += 1
                continue

            basis = spec["basis"]
            expected_state = spec["state"]
            sv = signature.teleported_states[i]["statevector"]
            sv_arr = np.asarray(sv)

            # Build measurement circuit
            # The statevector is for the full 3-qubit teleportation system.
            # Qubit 2 (MSB in Qiskit) is Bob's reconstructed qubit.
            qc = QuantumCircuit(3, 1)
            qc.initialize(sv_arr, [0, 1, 2])

            # Apply basis rotation for measurement
            if basis == "X":
                qc.h(2)

            qc.measure(2, 0)

            # Single-shot measurement (ideal noiseless simulation)
            counts = self.sim.run(qc, shots=1).result().get_counts()
            measured_bit = list(counts.keys())[0]

            expected_bit = '1' if expected_state in ['|1>', '|->'] else '0'
            match = measured_bit == expected_bit

            if not match:
                n_mismatches += 1

            qubit_results.append({
                "index": i,
                "expected_state": expected_state,
                "basis": basis,
                "expected_bit": expected_bit,
                "measured_bit": measured_bit,
                "match": match,
            })

        # Step 4: Compute aggregate mismatch rate
        aggregate_mismatch_rate = n_mismatches / signature.n_qubits if signature.n_qubits > 0 else 1.0
        is_valid = aggregate_mismatch_rate <= self.mismatch_threshold

        return QDSVerificationResult(
            qubit_results=qubit_results,
            aggregate_mismatch_rate=aggregate_mismatch_rate,
            n_qubits=signature.n_qubits,
            n_mismatches=n_mismatches,
            is_valid=is_valid,
            correction_bits_valid=correction_bits_valid,
        )
