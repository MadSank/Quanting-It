import uuid
import time
from typing import Any, Optional, List, Dict
from src.session import SessionManager
from src.packet import SecurePacket
from src.crypto import compute_message_hash
from src.qpkd import QPKDSession
from src.qds_signer import GCSigner, GCSignature, QDSSigner
from src.gc_keys import GCKeyPair, GCKeyGenerator, VerifierKeyRegister
from src.teleportation import teleport_fingerprint_state
from src.quantum_resources import SessionResourceManager


class Alice:
    """
    Alice: Signer in the Gottesman-Chuang Quantum Digital Signature system.

    Alice holds classical private keys (k_0^i, k_1^i) for each position i ∈ {0, ..., M-1}.
    Alice distributes limited quantum public key copies |f_{k_b^i}⟩ to Bob and Charlie
    (via quantum teleportation channels with Bell pairs).
    Alice signs messages by revealing the private keys corresponding to the encoded message bits.
    """

    def __init__(
        self,
        session_manager: SessionManager,
        qpkd_session: Optional[QPKDSession] = None,
        resource_manager: Optional[SessionResourceManager] = None,
        classical_priv_key: Any = None,
        classical_pub_key: str = None,
        key_pair: Optional[GCKeyPair] = None,
        n_positions: int = 32,
        fingerprint_qubits: int = 8,
    ):
        """
        Args:
            session_manager: Manages sequence numbers and session states
            qpkd_session: Optional shared Bell pairs context (for channel monitoring)
            resource_manager: Optional resource pool tracking
            classical_priv_key: Optional ML-DSA private key for classical transcript signing
            classical_pub_key: Optional ML-DSA public key hex
            key_pair: Pre-generated GCKeyPair (or generated automatically)
            n_positions: Number of signature positions M (default 32)
            fingerprint_qubits: Number of qubits per fingerprint n (default 8)
        """
        self.session_manager = session_manager
        self.qpkd_session = qpkd_session
        self.resource_manager = resource_manager
        self.classical_priv_key = classical_priv_key
        self.classical_pub_key = classical_pub_key
        self.n_positions = n_positions
        self.fingerprint_qubits = fingerprint_qubits

        if key_pair is not None:
            self.key_pair = key_pair
        else:
            self.key_pair = GCKeyGenerator.generate(
                n_positions=n_positions,
                fingerprint_qubits=fingerprint_qubits,
            )

    def distribute_public_keys(
        self,
        verifier_names: List[str],
        teleport: bool = True
    ) -> Dict[str, VerifierKeyRegister]:
        """
        Distribute quantum public key copies to designated verifiers (Bob, Charlie).

        Uses teleportation as the channel adaptation layer:
        Alice uses Bell pairs to teleport the fingerprint states to the verifiers,
        sending classical correction bits so they reconstruct the states.

        Returns:
            Dict mapping verifier name to their VerifierKeyRegister.
        """
        registers = {}
        for name in verifier_names:
            reg = VerifierKeyRegister(owner=name)
            for i in range(self.key_pair.n_positions):
                for b in (0, 1):
                    copy = self.key_pair.distribute_copy(i, b, name)
                    if teleport:
                        teleported_sv, _ = teleport_fingerprint_state(
                            copy.statevector, self.key_pair.fingerprint_qubits
                        )
                        copy.statevector = teleported_sv
                    reg.store(copy)
            registers[name] = reg
        return registers

    def create_packet(self, message: str, n_qubits: int = 32) -> SecurePacket:
        """
        Creates a SecurePacket using Gottesman-Chuang QDS.

        Args:
            message: The plaintext message
            n_qubits: Number of signature positions / qubits (demo scale)
        """
        session = self.session_manager.current_session
        if not session:
            raise ValueError("No active session")

        # 1. Classical Setup (Hash Binding)
        seq_num = session.get_next_sequence_number()
        msg_hash = compute_message_hash(
            message,
            session.session_id,
            session.challenge,
            seq_num
        )

        # 2. GC QDS Signing (asymmetric: Alice reveals private keys)
        signature = GCSigner.sign(
            message=message.encode("utf-8"),
            key_pair=self.key_pair,
            session_id=session.session_id,
            sequence_number=seq_num
        )
        if self.classical_pub_key:
            signature.classical_pub_key = self.classical_pub_key

        # 3. Canonical ML-DSA Transcript Signing (Auxiliary Post-Quantum Layer)
        canonical_transcript = (
            f"{session.session_id}||{seq_num}||{msg_hash}||"
            f"{signature.correction_bits[:32]}||n_positions={signature.n_positions}"
        )
        ml_dsa_sig = None
        if self.classical_priv_key:
            try:
                ml_dsa_sig = self.classical_priv_key.sign(
                    canonical_transcript.encode("utf-8")
                ).hex()
            except Exception:
                ml_dsa_sig = None

        # 4. Assemble SecurePacket
        packet = SecurePacket(
            session_id=session.session_id,
            sequence_number=seq_num,
            message=message,
            message_hash=msg_hash,
            qds_signature=signature,
            classical_auth_tag=None,
            ml_dsa_signature=ml_dsa_sig,
            metadata={
                "timestamp": time.time(),
                "n_positions": self.key_pair.n_positions,
                "fingerprint_qubits": self.key_pair.fingerprint_qubits,
                "canonical_transcript": canonical_transcript,
            }
        )
        return packet
