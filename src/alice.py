import uuid
import time
from typing import Any, Optional
from src.session import SessionManager
from src.packet import SecurePacket
from src.crypto import compute_message_hash
from src.qpkd import QPKDSession
from src.qds_signer import QDSSigner
from src.quantum_resources import SessionResourceManager


class Alice:
    def __init__(self,
                 session_manager: SessionManager,
                 qpkd_session: QPKDSession,
                 resource_manager: SessionResourceManager,
                 classical_priv_key: Any = None,
                 classical_pub_key: str = None):
        """
        Args:
            session_manager: Manages sequence numbers and session states
            qpkd_session: Contains shared Bell pairs from distribution phase
            resource_manager: Resource pool tracking Bell pairs
            classical_priv_key: ML-DSA private key for session metadata/correction bits
            classical_pub_key: ML-DSA public key hex
        """
        self.session_manager = session_manager
        self.qpkd_session = qpkd_session
        self.resource_manager = resource_manager
        self.classical_priv_key = classical_priv_key
        self.classical_pub_key = classical_pub_key

    def create_packet(self, message: str, n_qubits: int = 64) -> SecurePacket:
        """
        Creates a SecurePacket using teleportation-based QDS.

        Args:
            message: The plaintext message
            n_qubits: Number of signature qubits (64 or 128)
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

        # 2. QDS Signing (Teleportation-based)
        auth_context = self.qpkd_session.get_session_auth_context()
        
        signature = QDSSigner.sign(
            message_hash=msg_hash,
            session_auth_context=auth_context,
            resource_manager=self.resource_manager,
            session_id=session.session_id,
            sequence_number=seq_num,
            n_qubits=n_qubits,
            classical_priv_key=self.classical_priv_key,
            classical_pub_key=self.classical_pub_key
        )

        # 2b. Canonical ML-DSA Transcript Signing
        q_meta = f"n_qubits={n_qubits}"
        canonical_transcript = f"{session.session_id}||{seq_num}||{msg_hash}||{signature.correction_bits}||{q_meta}"
        
        ml_dsa_sig = None
        if self.classical_priv_key:
            ml_dsa_sig = self.classical_priv_key.sign(canonical_transcript.encode('utf-8')).hex()

        # 3. Create Packet
        packet = SecurePacket(
            session_id=session.session_id,
            sequence_number=seq_num,
            message=message,
            message_hash=msg_hash,
            qds_signature=signature,
            classical_auth_tag=None, # Replaced by the tag inside signature.correction_auth_tag
            ml_dsa_signature=ml_dsa_sig,
            metadata={
                "timestamp": time.time(),
                "n_qubits": n_qubits,
                "canonical_transcript": canonical_transcript
            }
        )
        return packet
