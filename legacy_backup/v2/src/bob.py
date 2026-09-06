from src.session import Session, SessionState, SessionError
from src.packet import SecurePacket
from src.crypto import verify_message_hash, compute_message_hash
from src.quantum_fingerprint import derive_fingerprint_binding, derive_fingerprint_specification, verify_quantum_fingerprint
from src.pq_signature import DEMO_PQ_SIGNER
from src.e91_monitor import E91Monitor
from src.metrics import AttackResult, AttackType

class Bob:
    def __init__(self, session: Session, session_auth_context: str, e91_monitor: E91Monitor = None):
        self.session = session
        self.session_auth_context = session_auth_context
        # Use provided monitor or create a clean one
        self.e91_monitor = e91_monitor if e91_monitor else E91Monitor(error_threshold=0.15)

    def verify_packet(self, packet: SecurePacket, simulate_e91_attack: str = "NONE") -> AttackResult:
        """
        Bob's hybrid verification pipeline. Evaluates all layers.
        """
        details = {
            "SESSION": True,
            "REPLAY": True,
            "CLASSICAL_HASH": True,
            "PQ_SIGNATURE": True,
            "QUANTUM_BINDING": True,
            "E91_CHANNEL": True
        }
        
        first_failure_layer = "NONE"
        first_failure_code = "ACCEPTED"
        attack_successful = True
        detected = False
        detected_type = AttackType.MESSAGE_TAMPERING # default fallback
        
        # Helper to record failure
        def fail(layer, code):
            nonlocal first_failure_layer, first_failure_code, attack_successful, detected
            details[layer] = False
            if not detected:
                first_failure_layer = layer
                first_failure_code = code
                detected = True
                attack_successful = False

        # CHECK 1: Session validation
        if packet.session_id != self.session.session_id:
            fail("SESSION", "INVALID_SESSION")
            
        if self.session.state not in [SessionState.ACTIVE, SessionState.VERIFYING]:
            fail("SESSION", "INVALID_SESSION_STATE")

        # CHECK 2: Sequence check (Replay)
        try:
            # Note: in a real system we only consume if valid, but for demo we consume first
            # Wait, if we just check it:
            if packet.sequence_number in self.session.consumed_sequences:
                fail("REPLAY", "REPLAY_DETECTED")
            else:
                self.session.consume_sequence(packet.sequence_number)
        except SessionError as e:
            fail("REPLAY", str(e))

        # CHECK 3: Hash validation
        expected_hash = compute_message_hash(packet.message, self.session.session_id, self.session.challenge, packet.sequence_number)
        if expected_hash != packet.message_hash:
            fail("CLASSICAL_HASH", "HASH_MISMATCH")

        # CHECK 4: PQ Signature Verification
        if not packet.pq_signature or not packet.pq_public_key:
            fail("PQ_SIGNATURE", "MISSING_SIGNATURE")
        else:
            is_pq_valid = DEMO_PQ_SIGNER.verify(packet.message_hash, packet.pq_signature, packet.pq_public_key)
            if not is_pq_valid:
                fail("PQ_SIGNATURE", "INVALID_SIGNATURE")

        # CHECK 5: Quantum Fingerprint Verification
        if packet.quantum_fingerprint is None:
            fail("QUANTUM_BINDING", "MISSING_FINGERPRINT")
        else:
            fp_binding = derive_fingerprint_binding(
                packet.message_hash, 
                self.session_auth_context, 
                self.session.session_id, 
                packet.sequence_number
            )
            expected_spec = derive_fingerprint_specification(fp_binding, self.session_auth_context, packet.quantum_fingerprint.proof_length)

            is_fp_valid = verify_quantum_fingerprint(packet.quantum_fingerprint, expected_spec)
            if not is_fp_valid:
                fail("QUANTUM_BINDING", "QUANTUM_VERIFICATION_FAILED")
            
        # CHECK 6: E91-Inspired Channel Integrity
        e91_error_rate = self.e91_monitor.simulate_channel(attack_type=simulate_e91_attack)
        if not self.e91_monitor.verify_channel_integrity(e91_error_rate):
            fail("E91_CHANNEL", "CHANNEL_DISTURBANCE_DETECTED")
            
        return AttackResult("id", detected_type, attack_successful, detected, first_failure_layer, first_failure_code, details=details)
