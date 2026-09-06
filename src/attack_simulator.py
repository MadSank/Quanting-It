from typing import List, Dict, Any, Tuple
from src.session import Session, SessionManager
from src.alice import Alice
from src.bob import Bob
from src.eve import Eve
from src.metrics import SecurityMetrics, AttackResult, AttackType
from src.quantum_resources import SessionResourceManager, ResourceType
from src.crypto import generate_challenge
from src.qpkd import QPKDSession
from src.threat_engine import ThreatScorer
from src.e91_monitor import E91Monitor
from src.classical_channel import ClassicalChannelAuth

class AttackSimulator:
    def __init__(self, n_qubits: int = 64):
        self.n_qubits = n_qubits
        self.metrics = SecurityMetrics()
        
    def setup_session(self) -> Tuple[Alice, Bob, Session]:
        session_manager = SessionManager()
        chal = generate_challenge()
        session_manager.start_session(chal)
        session = session_manager.current_session
        
        # QPKD Phase (E91)
        qpkd = QPKDSession(session.session_id)
        qpkd.distribute_keys(n_signature_pairs=self.n_qubits, n_monitor_pairs=20)
        
        manager = SessionResourceManager(session.session_id)
        manager.allocate_pairs(self.n_qubits, ResourceType.SIGNATURE_PAIR)
        
        pub_key, priv_key = ClassicalChannelAuth.generate_keys()
        
        e91_monitor = E91Monitor(error_threshold=0.15)
        threat_scorer = ThreatScorer(qds_threshold=0.05, e91_threshold=0.15)
        
        alice = Alice(
            session_manager=session_manager,
            qpkd_session=qpkd,
            resource_manager=manager,
            classical_priv_key=priv_key,
            classical_pub_key=pub_key
        )
        bob = Bob(
            session_manager=session_manager,
            qpkd_session=qpkd,
            e91_monitor=e91_monitor,
            threat_scorer=threat_scorer,
            trusted_classical_pub_key=pub_key
        )
        
        return alice, bob, session

    def run_attack(self, attack_type: AttackType, attack_id: str, **kwargs) -> AttackResult:
        alice, bob, session = self.setup_session()
        
        if attack_type == AttackType.NO_ATTACK:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.MESSAGE_TAMPERING:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            tampered_packet = Eve.tamper_message(packet, "HELLO EVE")
            result = bob.verify_packet(tampered_packet)
            
        elif attack_type == AttackType.HASH_TAMPERING:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            tampered_packet = Eve.tamper_hash(packet, "deadbeef00000000000000000000000000000000000000000000000000000000")
            result = bob.verify_packet(tampered_packet)

        elif attack_type == AttackType.SIGNATURE_TAMPERING:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            tampered_packet = Eve.tamper_ml_dsa_signature(packet)
            result = bob.verify_packet(tampered_packet)
            
        elif attack_type == AttackType.FORGERY_ATTEMPT:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            # Eve intercepts and replaces the entire signature with a forge
            forged_sig = Eve.forge_signature(
                packet.message_hash, "47c8a4a20f33b6d2cc6d84b5d0056409fe0ce030c540313b7baa40fc55677280", 
                self.n_qubits, packet.session_id, packet.sequence_number
            )
            packet.qds_signature = forged_sig
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.IMPERSONATION:
            # Eve tries to act as Alice without the QPKD session
            eve_alice, _, _ = self.setup_session()
            packet = eve_alice.create_packet("IMPERSONATING ALICE", self.n_qubits)
            
            # Eve attempts to spoof the session context to bypass Layer 1 (Session State)
            packet.session_id = session.session_id
            packet.sequence_number = session.current_sequence_number + 1
            # She recalculates the message hash based on Bob's expected session state
            from src.crypto import compute_message_hash
            packet.message_hash = compute_message_hash(
                packet.message, session.session_id, session.challenge, packet.sequence_number
            )
            # She re-signs the correction bits using her own key but claiming Bob's session context
            # We can just generate a new signature using Eve's forged context
            packet.qds_signature = Eve.forge_signature(
                packet.message_hash, "dummy_auth_context", self.n_qubits, packet.session_id, packet.sequence_number
            )
            
            result = bob.verify_packet(packet) # Bob uses his auth context and Bell halves

        elif attack_type == AttackType.SEQUENCE_TAMPERING:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            tampered_packet = Eve.tamper_sequence(packet, 999)
            result = bob.verify_packet(tampered_packet)
            
        elif attack_type == AttackType.REPLAY:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            bob.verify_packet(packet)
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.QUANTUM_X:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            tampered_sig = Eve.apply_pauli_x(packet.qds_signature, [0])
            packet.qds_signature = tampered_sig
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.QUANTUM_Z:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            tampered_sig = Eve.apply_pauli_z(packet.qds_signature, [0])
            packet.qds_signature = tampered_sig
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.QUANTUM_Y:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            tampered_sig = Eve.apply_pauli_y(packet.qds_signature, [0])
            packet.qds_signature = tampered_sig
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.QUANTUM_DEPOLARIZING:
            prob = kwargs.get("error_probability", 0.5)
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            tampered_sig = Eve.apply_depolarizing_noise(packet.qds_signature, prob)
            packet.qds_signature = tampered_sig
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.INTERCEPT_RESEND:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            tampered_sig = Eve.intercept_measure_resend(packet.qds_signature, list(range(self.n_qubits)))
            packet.qds_signature = tampered_sig
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.E91_CHANNEL_DISTURBANCE:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            # Use actual simulated disturbance instead of a lambda mock
            result = bob.verify_packet(packet, simulate_e91_attack="INTERCEPT_RESEND")

        elif attack_type == AttackType.PROOF_SUBSTITUTION:
            packet_a = alice.create_packet("MSG A", self.n_qubits)
            packet_b = alice.create_packet("MSG B", self.n_qubits)
            packet_b.qds_signature = packet_a.qds_signature
            result = bob.verify_packet(packet_b)
            
        elif attack_type == AttackType.CROSS_SESSION_REUSE:
            a_alice, a_bob, a_sess = self.setup_session()
            b_alice, b_bob, b_sess = self.setup_session()
            
            packet_a = a_alice.create_packet("HELLO", self.n_qubits)
            packet_b = b_alice.create_packet("HELLO", self.n_qubits)
            
            packet_b.qds_signature = packet_a.qds_signature
            result = b_bob.verify_packet(packet_b)
            
        elif attack_type == AttackType.COMPROMISED_SESSION_CONTEXT:
            packet = alice.create_packet("MSG", self.n_qubits)
            packet.session_id = "stolen_session"
            result = bob.verify_packet(packet)
            
        else:
            raise ValueError(f"Unknown attack type: {attack_type}")

        result.attack_id = attack_id
        result.attack_type = attack_type
        self.metrics.record_attack_result(result)
        return result
