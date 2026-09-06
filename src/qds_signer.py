"""
[QUANTUM DIGITAL SIGNATURE - SIGNING]

Alice's QDS signing module. This IS the signature — not a supplement to PQC.

Protocol:
1. Message hash determines a signing specification (basis + state per qubit).
2. Alice prepares Pauli eigenstates per the spec.
3. Each state is teleported through pre-distributed Bell pairs.
4. Classical correction bits (crz/crx) are collected and signed with ML-DSA.

Trust anchor: Only Alice, holding her halves of the pre-distributed Bell pairs,
can produce teleported states that Bob's halves will reconstruct correctly.
"""

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from qiskit import QuantumCircuit
from src.teleportation import create_teleportation_circuit, simulate_teleportation
from src.quantum_resources import SessionResourceManager, ResourceType
from src.classical_channel import ClassicalChannelAuth


@dataclass
class QDSSignature:
    """
    A teleportation-based quantum digital signature.
    """
    signature_id: str
    session_id: str
    sequence_number: int
    n_qubits: int
    teleported_states: List[Dict[str, Any]]  # {statevector, crz_bit, crx_bit}
    correction_bits: str  # Concatenated crz||crx bitstring
    correction_auth_tag: str  # ML-DSA signature over correction bits
    signing_spec_hash: str  # Hash of the spec for Bob's re-derivation
    classical_pub_key: str  # ML-DSA public key for correction bit verification


def derive_signing_spec(message_hash: str, session_auth_context: str,
                        n_qubits: int) -> List[Dict[str, Any]]:
    """
    Deterministically derive the signing specification from the message hash
    and session authentication context.

    Encoding (BB84-style Pauli eigenstates):
    - Auth context bit → basis selection (0=Z, 1=X)
    - Hash bit → state selection:
      - Z-basis: 0→|0⟩, 1→|1⟩
      - X-basis: 0→|+⟩, 1→|−⟩

    Args:
        message_hash: SHA-256 hex digest of the message binding
        session_auth_context: SHA-256 hex digest from QPKD phase
        n_qubits: Number of signature qubits (64 or 128)

    Returns:
        List of {basis, state, binding_bit} specifications
    """
    spec = []

    # Extend hash material if n_qubits > 256 bits
    # For 64 or 128 qubits, a single SHA-256 is sufficient
    hash_bin = bin(int(message_hash, 16))[2:].zfill(256)
    ctx_bin = bin(int(session_auth_context, 16))[2:].zfill(256)

    for i in range(n_qubits):
        binding_bit = int(hash_bin[i % 256])
        basis_selector = int(ctx_bin[i % 256])

        basis = "X" if basis_selector == 1 else "Z"

        if basis == "Z":
            state = "|1>" if binding_bit == 1 else "|0>"
        else:
            state = "|->" if binding_bit == 1 else "|+>"

        spec.append({
            "binding_bit": binding_bit,
            "basis": basis,
            "state": state,
        })

    return spec


def prepare_signing_state(expected_state: str) -> QuantumCircuit:
    """
    Prepare a Pauli eigenstate on a single qubit.

    |0⟩ → identity (default)
    |1⟩ → X gate
    |+⟩ → H gate
    |−⟩ → X then H gate
    """
    qc = QuantumCircuit(1)
    if expected_state == "|1>":
        qc.x(0)
    elif expected_state == "|+>":
        qc.h(0)
    elif expected_state == "|->":
        qc.x(0)
        qc.h(0)
    # |0> is default
    return qc


class QDSSigner:
    """
    Alice's QDS signing engine.
    """

    @staticmethod
    def sign(message_hash: str, session_auth_context: str,
             resource_manager: SessionResourceManager,
             session_id: str, sequence_number: int,
             n_qubits: int = 64,
             classical_priv_key: Any = None,
             classical_pub_key: str = None) -> QDSSignature:
        """
        Generate a teleportation-based quantum digital signature.

        Args:
            message_hash: SHA-256 hash of the message binding
            session_auth_context: From QPKD phase
            resource_manager: Manages Bell pair resources
            session_id: Current session ID
            sequence_number: Message sequence number
            n_qubits: Signature length (64 or 128)
            classical_priv_key: ML-DSA private key for correction bit signing
            classical_pub_key: ML-DSA public key hex

        Returns:
            QDSSignature containing teleported states and auth tags
        """
        # 1. Derive signing specification
        spec = derive_signing_spec(message_hash, session_auth_context, n_qubits)
        spec_hash = hashlib.sha256(
            str(spec).encode('utf-8')
        ).hexdigest()

        # 2. Consume Bell pair resources
        available_pairs = [
            k for k, v in resource_manager.resources.items()
            if v.resource_type == ResourceType.SIGNATURE_PAIR
            and v.status.name == "UNUSED"
        ]
        if len(available_pairs) < n_qubits:
            raise ValueError(
                f"Not enough SIGNATURE_PAIR resources: need {n_qubits}, "
                f"have {len(available_pairs)}"
            )

        # 3. Prepare, teleport, and record each signature qubit
        teleported_states = []
        correction_bits_list = []

        for i, s in enumerate(spec):
            pair_id = available_pairs[i]
            resource_manager.consume_resource(pair_id)

            # Prepare the Pauli eigenstate
            prep_qc = prepare_signing_state(s["state"])

            # Create and simulate teleportation circuit
            teleport_qc = create_teleportation_circuit(prep_qc)
            result = simulate_teleportation(teleport_qc)

            # Extract classical correction bits from measurement counts
            counts = result.get("counts", {})
            if counts:
                outcome = list(counts.keys())[0]
                # Parse Qiskit multi-register format: "crx crz" (space separated)
                parts = outcome.split()
                if len(parts) == 2:
                    crx_bit = int(parts[0])
                    crz_bit = int(parts[1])
                else:
                    crz_bit = 0
                    crx_bit = 0
            else:
                crz_bit = 0
                crx_bit = 0

            teleported_states.append({
                "symbol_index": i,
                "statevector": result["statevector"],
                "crz_bit": crz_bit,
                "crx_bit": crx_bit,
            })
            correction_bits_list.append(f"{crz_bit}{crx_bit}")

        # 4. Build correction bitstring and sign with ML-DSA
        correction_bits = "".join(correction_bits_list)

        if classical_priv_key is not None and classical_pub_key is not None:
            correction_auth_tag = ClassicalChannelAuth.sign_correction_bits(
                correction_bits, session_id, sequence_number, classical_priv_key
            )
        else:
            correction_auth_tag = ""

        return QDSSignature(
            signature_id=str(uuid.uuid4()),
            session_id=session_id,
            sequence_number=sequence_number,
            n_qubits=n_qubits,
            teleported_states=teleported_states,
            correction_bits=correction_bits,
            correction_auth_tag=correction_auth_tag,
            signing_spec_hash=spec_hash,
            classical_pub_key=classical_pub_key or "",
        )
