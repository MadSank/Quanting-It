from src.session import Session
from src.packet import SecurePacket
from src.crypto import compute_message_hash
from src.quantum_fingerprint import derive_fingerprint_binding, derive_fingerprint_specification, generate_quantum_fingerprint
from src.quantum_resources import SessionResourceManager
from src.pq_signature import DEMO_PQ_SIGNER

class Alice:
    def __init__(self, session: Session, session_auth_context: str, resource_manager: SessionResourceManager):
        self.session = session
        self.session_auth_context = session_auth_context
        self.resource_manager = resource_manager
        # In a real system, keys would be generated once per session or identity
        self.pq_pub, self.pq_priv = DEMO_PQ_SIGNER.generate_keys()

    def create_packet(self, message: str, proof_length: int = 8) -> SecurePacket:
        """
        Generates a legitimate packet with PQ signature and quantum fingerprint.
        """
        seq = self.session.get_next_sequence_number()
        
        # 1. Classical Hash
        msg_hash = compute_message_hash(message, self.session.session_id, self.session.challenge, seq)
        
        # 2. PQ Signature
        signature = DEMO_PQ_SIGNER.sign(msg_hash, self.pq_priv, self.pq_pub)
        
        # 3. Quantum Fingerprint
        fp_binding = derive_fingerprint_binding(
            msg_hash, 
            self.session_auth_context, 
            self.session.session_id, 
            seq
        )
        expected_spec = derive_fingerprint_specification(fp_binding, self.session_auth_context, proof_length)
        fingerprint = generate_quantum_fingerprint(self.session.session_id, seq, expected_spec, self.resource_manager)
        
        return SecurePacket(
            session_id=self.session.session_id,
            sequence_number=seq,
            message=message,
            message_hash=msg_hash,
            pq_signature=signature,
            pq_public_key=self.pq_pub,
            quantum_fingerprint=fingerprint
        )
