from typing import Any
from src.session import SessionManager
from src.packet import SecurePacket
from src.crypto import compute_message_hash
from src.qpkd import QPKDSession
from src.qds_verifier import QDSVerifier
from src.threat_engine import ThreatScorer
from src.e91_monitor import E91Monitor
from src.metrics import AttackResult, AttackType


class Bob:
    def __init__(self,
                 session_manager: SessionManager,
                 qpkd_session: QPKDSession,
                 e91_monitor: E91Monitor,
                 threat_scorer: ThreatScorer,
                 trusted_classical_pub_key: str = None):
        """
        Args:
            session_manager: Tracks sequence numbers and active sessions
            qpkd_session: Contains shared Bell pairs and auth context
            e91_monitor: Checks the channel for disturbance
            threat_scorer: Converts verification metrics into a ThreatScore
            trusted_classical_pub_key: ML-DSA public key hex for Alice
        """
        self.session_manager = session_manager
        self.qpkd_session = qpkd_session
        self.e91_monitor = e91_monitor
        self.threat_scorer = threat_scorer
        self.trusted_classical_pub_key = trusted_classical_pub_key
        self.qds_verifier = QDSVerifier(mismatch_threshold=threat_scorer.qds_threshold)

    def verify_packet(self, packet: SecurePacket, simulate_e91_attack: str = "NONE") -> AttackResult:
        """
        Executes the 6-layer statistical verification pipeline.
        Returns an AttackResult containing a comprehensive ThreatScore.
        """
        session = self.session_manager.current_session

        # Layer 1: Session State Check
        session_valid = session is not None and packet.session_id == session.session_id
        
        # Layer 2: Replay Protection Check
        replay_valid = session_valid and self.session_manager.verify_sequence_number(packet.sequence_number)

        # Layer 3: Classical Hash Binding Check
        if session_valid:
            expected_hash = compute_message_hash(
                packet.message,
                session.session_id,
                session.challenge,
                packet.sequence_number
            )
            classical_hash_valid = (packet.message_hash == expected_hash)
        else:
            classical_hash_valid = False

        # Layer 3.5: Verify Canonical ML-DSA Transcript
        ml_dsa_valid = False
        if classical_hash_valid and packet.ml_dsa_signature and self.trusted_classical_pub_key and packet.qds_signature:
            q_meta = f"n_qubits={packet.qds_signature.n_qubits}"
            canonical_transcript = f"{packet.session_id}||{packet.sequence_number}||{packet.message_hash}||{packet.qds_signature.correction_bits}||{q_meta}"
            try:
                from cryptography.hazmat.primitives.asymmetric import mldsa
                pub_key = mldsa.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(self.trusted_classical_pub_key))
                pub_key.verify(bytes.fromhex(packet.ml_dsa_signature), canonical_transcript.encode('utf-8'))
                ml_dsa_valid = True
            except Exception:
                ml_dsa_valid = False
        else:
            ml_dsa_valid = False

        # Layer 4 & 5: QDS Verification & Correction Bit Integrity
        auth_context = self.qpkd_session.get_session_auth_context()
        
        if packet.qds_signature:
            packet.qds_signature.classical_pub_key = self.trusted_classical_pub_key
            qds_result = self.qds_verifier.verify(
                packet.qds_signature,
                packet.message_hash,
                auth_context
            )
            qds_mismatch_rate = qds_result.aggregate_mismatch_rate
            qds_n_qubits = qds_result.n_qubits
            qds_n_mismatches = qds_result.n_mismatches
            correction_bits_valid = qds_result.correction_bits_valid
        else:
            # Missing signature
            qds_mismatch_rate = 1.0
            qds_n_qubits = 64
            qds_n_mismatches = 64
            correction_bits_valid = False

        # Layer 6: E91 Channel Monitor Check
        e91_stats = self.e91_monitor.measure_disturbance(attack_type=simulate_e91_attack)
        e91_error_rate = e91_stats["error_rate"]

        # Aggregate via ThreatScorer
        threat_score = self.threat_scorer.evaluate(
            qds_mismatch_rate=qds_mismatch_rate,
            qds_n_qubits=qds_n_qubits,
            qds_n_mismatches=qds_n_mismatches,
            correction_bits_valid=correction_bits_valid,
            e91_error_rate=e91_error_rate,
            classical_hash_valid=classical_hash_valid,
            session_valid=session_valid,
            replay_valid=replay_valid,
            ml_dsa_valid=ml_dsa_valid
        )

        # Determine if this was an attack based on which checks failed
        if threat_score.is_accepted:
            attack_type = AttackType.NO_ATTACK
            detected = False
            rejection_code = "ACCEPTED"
            layer = "NONE"
        else:
            detected = True
            if not session_valid:
                attack_type = AttackType.COMPROMISED_SESSION_CONTEXT
                rejection_code = "ERR_SESSION_INVALID"
                layer = "SESSION_STATE"
            elif not replay_valid:
                attack_type = AttackType.REPLAY
                rejection_code = "ERR_REPLAY_DETECTED"
                layer = "REPLAY_PROTECTION"
            elif not classical_hash_valid:
                attack_type = AttackType.HASH_TAMPERING
                rejection_code = "ERR_HASH_MISMATCH"
                layer = "CLASSICAL_HASH"
            elif not correction_bits_valid:
                attack_type = AttackType.MESSAGE_TAMPERING  # Eve flipped bits on classical channel
                rejection_code = "ERR_CORRECTION_BITS_TAMPERED"
                layer = "CORRECTION_BITS"
            elif not ml_dsa_valid:
                attack_type = AttackType.SIGNATURE_TAMPERING
                rejection_code = "ERR_MLDSA_SIGNATURE_INVALID"
                layer = "ML_DSA_VERIFICATION"
            elif qds_mismatch_rate > self.threat_scorer.qds_threshold:
                attack_type = AttackType.FORGERY_ATTEMPT
                rejection_code = "ERR_QDS_MISMATCH_THRESHOLD_EXCEEDED"
                layer = "QDS_VERIFICATION"
            elif e91_error_rate > self.threat_scorer.e91_threshold:
                attack_type = AttackType.E91_CHANNEL_DISTURBANCE
                rejection_code = "ERR_E91_DISTURBANCE_HIGH"
                layer = "E91_CHANNEL"
            else:
                attack_type = AttackType.FORGERY_ATTEMPT
                rejection_code = "ERR_UNKNOWN"
                layer = "UNKNOWN"

        return AttackResult(
            attack_id="eval_" + packet.message_hash[:8],
            attack_type=attack_type,
            attack_successful=not detected and attack_type != AttackType.NO_ATTACK,
            detected=detected,
            detection_layer=layer,
            rejection_code=rejection_code,
            threat_score=threat_score
        )
