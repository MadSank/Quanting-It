from typing import Any, Optional
from src.session import SessionManager
from src.packet import SecurePacket
from src.crypto import compute_message_hash
from src.qpkd import QPKDSession
from src.qds_verifier import GCVerifier, GCVerificationResult, VerificationOutcome, QDSVerifier
from src.gc_keys import VerifierKeyRegister
from src.threat_engine import ThreatScorer, GCThreatScorer, ThreatScore
from src.e91_monitor import E91Monitor
from src.metrics import AttackResult, AttackType, DefenseStatus


class Bob:
    """
    Bob: Primary Verifier in the Gottesman-Chuang Quantum Digital Signature system.

    Bob holds a VerifierKeyRegister containing quantum public key copies |f_{k_b^i}⟩.
    Bob verifies Alice's signature by executing SWAP tests between states generated
    from Alice's revealed private keys and Bob's stored quantum copies.
    """

    def __init__(
        self,
        session_manager: SessionManager,
        qpkd_session: Optional[QPKDSession] = None,
        e91_monitor: Optional[E91Monitor] = None,
        threat_scorer: Optional[Any] = None,
        trusted_classical_pub_key: str = None,
        key_register: Optional[VerifierKeyRegister] = None,
        acceptance_threshold: float = 0.05,
        rejection_threshold: float = 0.20,
    ):
        """
        Args:
            session_manager: Tracks sequence numbers and active sessions
            qpkd_session: Contains shared Bell pairs / context (for channel monitoring)
            e91_monitor: Checks the channel for physical disturbance
            threat_scorer: Converts verification metrics into a ThreatScore
            trusted_classical_pub_key: ML-DSA public key hex for Alice
            key_register: Bob's stored quantum public keys
            acceptance_threshold: c₁ — Bob's acceptance threshold fraction
            rejection_threshold: c₂ — Rejection threshold fraction
        """
        self.session_manager = session_manager
        self.qpkd_session = qpkd_session
        self.e91_monitor = e91_monitor or E91Monitor(n_pairs=64)
        self.trusted_classical_pub_key = trusted_classical_pub_key
        self.key_register = key_register or VerifierKeyRegister(owner="Bob")

        # Threat scorer setup
        if threat_scorer is not None:
            self.threat_scorer = threat_scorer
            if hasattr(threat_scorer, "qds_threshold"):
                acceptance_threshold = threat_scorer.qds_threshold
        else:
            self.threat_scorer = GCThreatScorer(
                c1_threshold_fraction=acceptance_threshold,
                c2_threshold_fraction=rejection_threshold,
            )

        self.qds_verifier = GCVerifier(
            acceptance_threshold=acceptance_threshold,
            rejection_threshold=rejection_threshold,
            key_register=self.key_register,
        )

    def receive_public_keys(self, register: VerifierKeyRegister) -> None:
        """Receive and store distributed quantum public key register."""
        self.key_register = register
        self.qds_verifier.key_register = register

    def verify_packet(
        self,
        packet: SecurePacket,
        simulate_e91_attack: str = "NONE",
        is_transfer: bool = False
    ) -> AttackResult:
        """
        Executes the multi-layer statistical verification pipeline:
        1. Session State Check
        2. Replay Protection Check
        3. Classical Hash Binding Check
        3.5 ML-DSA Canonical Transcript Verification (Auxiliary)
        4. GC QDS SWAP Test Verification
        5. E91 Channel Monitor Check

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
        ml_dsa_valid = True  # Default true if ML-DSA not enforced
        if packet.ml_dsa_signature and self.trusted_classical_pub_key and packet.qds_signature:
            canonical_transcript = (
                f"{packet.session_id}||{packet.sequence_number}||{packet.message_hash}||"
                f"{getattr(packet.qds_signature, 'correction_bits', '')[:32]}||"
                f"n_positions={getattr(packet.qds_signature, 'n_positions', 32)}"
            )
            try:
                from cryptography.hazmat.primitives.asymmetric import mldsa
                pub_key = mldsa.MLDSA65PublicKey.from_public_bytes(
                    bytes.fromhex(self.trusted_classical_pub_key)
                )
                pub_key.verify(bytes.fromhex(packet.ml_dsa_signature), canonical_transcript.encode("utf-8"))
                ml_dsa_valid = True
            except Exception:
                ml_dsa_valid = False

        # Layer 4: GC QDS SWAP Test Verification
        qds_mismatch_rate = 1.0
        qds_n_qubits = 32
        qds_n_mismatches = 32
        copy_available = True
        qds_is_valid = False
        qds_res = None

        if packet.qds_signature and self.key_register:
            sig = packet.qds_signature
            qds_n_qubits = getattr(sig, "n_positions", 32)

            # Check if verifier has any available copies
            has_any = any(
                self.key_register.has_available_copy(i, 0) or self.key_register.has_available_copy(i, 1)
                for i in range(qds_n_qubits)
            )
            if not has_any:
                copy_available = False

            # Run SWAP test verification
            msg_bytes = packet.message.encode("utf-8") if isinstance(packet.message, str) else packet.message
            qds_res: GCVerificationResult = self.qds_verifier.verify(
                signature=sig,
                key_register=self.key_register,
                message=msg_bytes,
            )
            qds_n_mismatches = qds_res.n_failures
            qds_mismatch_rate = qds_res.mismatch_rate
            threshold = self.qds_verifier.c2 if is_transfer else self.qds_verifier.c1
            qds_is_valid = (qds_res.mismatch_rate <= threshold) and copy_available
        else:
            copy_available = False
            qds_is_valid = False

        # Layer 5: E91 Channel Monitor Check
        e91_stats = self.e91_monitor.measure_disturbance(attack_type=simulate_e91_attack)
        e91_error_rate = e91_stats["error_rate"]

        # Threat Scoring
        if hasattr(self.threat_scorer, "evaluate_gc"):
            threat_score: ThreatScore = self.threat_scorer.evaluate_gc(
                m_positions=qds_n_qubits,
                n_mismatches=qds_n_mismatches,
                is_transfer=is_transfer,
                e91_error_rate=e91_error_rate,
                classical_hash_valid=classical_hash_valid,
                session_valid=session_valid,
                replay_valid=replay_valid,
                copy_available=copy_available,
                ml_dsa_valid=ml_dsa_valid,
            )
        else:
            threat_score: ThreatScore = self.threat_scorer.evaluate(
                qds_mismatch_rate=qds_mismatch_rate,
                qds_n_qubits=qds_n_qubits,
                qds_n_mismatches=qds_n_mismatches,
                correction_bits_valid=copy_available,
                e91_error_rate=e91_error_rate,
                classical_hash_valid=classical_hash_valid,
                session_valid=session_valid,
                replay_valid=replay_valid,
                ml_dsa_valid=ml_dsa_valid,
            )

        # Classify attack and defense status honestly
        attack_successful = False
        detected = False
        defense_status = DefenseStatus.PREVENTED
        rejection_code = "ACCEPTED"
        detection_layer = "NONE"
        attack_type = AttackType.NO_ATTACK

        if not session_valid:
            attack_type = AttackType.COMPROMISED_SESSION_CONTEXT
            detected = True
            rejection_code = "INVALID_SESSION"
            detection_layer = "SESSION_STATE"
            defense_status = DefenseStatus.DETECTED
        elif not replay_valid:
            attack_type = AttackType.REPLAY
            detected = True
            rejection_code = "REPLAY_DETECTED"
            detection_layer = "REPLAY_PROTECTION"
            defense_status = DefenseStatus.DETECTED
        elif not classical_hash_valid:
            attack_type = AttackType.HASH_TAMPERING
            detected = True
            rejection_code = "HASH_MISMATCH"
            detection_layer = "CLASSICAL_HASH"
            defense_status = DefenseStatus.DETECTED
        elif not ml_dsa_valid:
            attack_type = AttackType.SIGNATURE_TAMPERING
            detected = True
            rejection_code = "ML_DSA_INVALID"
            detection_layer = "ML_DSA_VERIFICATION"
            defense_status = DefenseStatus.DETECTED
        elif not copy_available:
            attack_type = AttackType.COPY_EXHAUSTION
            detected = True
            rejection_code = "NO_CLONING_BUDGET_EXHAUSTED"
            detection_layer = "COPY_BUDGET"
            defense_status = DefenseStatus.PREVENTED
        elif not qds_is_valid:
            attack_type = AttackType.FORGERY_ATTEMPT
            detected = True
            rejection_code = "QDS_SWAP_TEST_THRESHOLD_EXCEEDED"
            detection_layer = "QDS_VERIFICATION"
            defense_status = DefenseStatus.DETECTED
        elif e91_error_rate > getattr(self.e91_monitor, "error_threshold", 0.15):
            attack_type = AttackType.E91_CHANNEL_DISTURBANCE
            detected = True
            rejection_code = "E91_THRESHOLD_EXCEEDED"
            detection_layer = "E91_CHANNEL"
            defense_status = DefenseStatus.DETECTED

        is_accepted = threat_score.is_accepted

        return AttackResult(
            attack_id=f"chk_{packet.sequence_number}_{packet.session_id[:8]}",
            attack_type=attack_type,
            attack_successful=(not is_accepted and not detected),
            detected=detected,
            detection_layer=detection_layer,
            rejection_code=rejection_code,
            threat_score=threat_score,
            defense_status=defense_status,
            details={
                "qds_mismatch_rate": qds_mismatch_rate,
                "qds_n_mismatches": qds_n_mismatches,
                "qds_n_qubits": qds_n_qubits,
                "copy_available": copy_available,
                "e91_error_rate": e91_error_rate,
                "is_accepted": is_accepted,
                "verifier": self.key_register.owner if self.key_register else "Bob",
                "is_transfer": is_transfer,
                "qds_result": qds_res,
            }
        )
