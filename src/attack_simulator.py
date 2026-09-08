from typing import List, Dict, Any, Tuple, Optional
from src.session import Session, SessionManager
from src.alice import Alice
from src.bob import Bob
from src.eve import Eve
from src.metrics import SecurityMetrics, AttackResult, AttackType, DefenseStatus
from src.quantum_resources import SessionResourceManager, ResourceType
from src.crypto import generate_challenge
from src.qpkd import QPKDSession
from src.threat_engine import ThreatScorer, GCThreatScorer
from src.e91_monitor import E91Monitor
from src.classical_channel import ClassicalChannelAuth
from src.gc_keys import GCKeyGenerator, GCKeyPair, VerifierKeyRegister
from src.packet import SecurePacket


class AttackSimulator:
    """
    Simulates attacks on the Gottesman-Chuang Quantum Digital Signature system.
    Evaluates defense status and detection layers across all threat vectors.
    """

    def __init__(self, n_qubits: int = 32):
        self.n_qubits = n_qubits
        self.metrics = SecurityMetrics()

    def setup_session(self) -> Tuple[Alice, Bob, Session]:
        session_manager = SessionManager()
        chal = generate_challenge()
        session_manager.start_session(chal)
        session = session_manager.current_session

        pub_key, priv_key = ClassicalChannelAuth.generate_keys()

        e91_monitor = E91Monitor(error_threshold=0.15)
        threat_scorer = GCThreatScorer(
            c1_threshold_fraction=0.05,
            c2_threshold_fraction=0.20,
            e91_threshold=0.15
        )

        alice = Alice(
            session_manager=session_manager,
            classical_priv_key=priv_key,
            classical_pub_key=pub_key,
            n_positions=self.n_qubits,
            fingerprint_qubits=8,
        )

        # Distribute public key copies to Bob and Charlie
        key_registers = alice.distribute_public_keys(["Bob", "Charlie"], teleport=True)

        bob = Bob(
            session_manager=session_manager,
            e91_monitor=e91_monitor,
            threat_scorer=threat_scorer,
            trusted_classical_pub_key=pub_key,
            key_register=key_registers["Bob"],
            acceptance_threshold=0.05,
            rejection_threshold=0.20,
        )

        return alice, bob, session

    def setup_environment(self) -> Tuple[Alice, Bob, Session]:
        """Setup Alice, Bob, and active session environment (alias for setup_session)."""
        return self.setup_session()

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
            tampered_packet = Eve.tamper_hash(
                packet, "deadbeef00000000000000000000000000000000000000000000000000000000"
            )
            result = bob.verify_packet(tampered_packet)

        elif attack_type == AttackType.SIGNATURE_TAMPERING:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            tampered_packet = Eve.tamper_ml_dsa_signature(packet)
            result = bob.verify_packet(tampered_packet)

        elif attack_type == AttackType.FORGERY_ATTEMPT:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            # Eve attempts to forge without Alice's private keys
            forged_sig = Eve.forge_gc_signature(
                message=packet.message.encode("utf-8"),
                n_positions=self.n_qubits,
                key_bytes=16,
                session_id=packet.session_id,
                sequence_number=packet.sequence_number,
            )
            packet.qds_signature = forged_sig
            result = bob.verify_packet(packet)

        elif attack_type == AttackType.IMPERSONATION:
            # Eve acts as Alice: computes the valid hash for Bob's session,
            # but signs with her own key material (lacking Alice's private keys).
            from src.crypto import compute_message_hash
            seq_num = session.current_sequence_number + 1
            msg = "IMPERSONATING ALICE"
            msg_hash = compute_message_hash(msg, session.session_id, session.challenge, seq_num)
            forged_sig = Eve.forge_gc_signature(
                message=msg.encode("utf-8"),
                n_positions=self.n_qubits,
                key_bytes=16,
                session_id=session.session_id,
                sequence_number=seq_num,
            )
            packet = SecurePacket(
                session_id=session.session_id,
                sequence_number=seq_num,
                message=msg,
                message_hash=msg_hash,
                qds_signature=forged_sig,
            )
            result = bob.verify_packet(packet)

        elif attack_type == AttackType.SEQUENCE_TAMPERING:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            tampered_packet = Eve.tamper_sequence(packet, 999)
            result = bob.verify_packet(tampered_packet)

        elif attack_type == AttackType.REPLAY:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            # First verification consumes public key copy and updates sequence
            bob.verify_packet(packet)
            # Replay attempt: copy is already consumed and sequence is stale
            result = bob.verify_packet(packet)

        elif attack_type == AttackType.KEY_SUBSTITUTION:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            tampered_packet = Eve.tamper_revealed_key(packet, position_idx=0)
            result = bob.verify_packet(tampered_packet)

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

        elif attack_type == AttackType.E91_CHANNEL_DISTURBANCE:
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            result = bob.verify_packet(packet, simulate_e91_attack="INTERCEPT_RESEND")

        elif attack_type == AttackType.INTERCEPT_RESEND:
            # Intercept-resend disturbs both public key channel and E91 monitor
            if bob.key_register:
                for (pos, bit), copy in list(bob.key_register.copies.items()):
                    from src.teleportation import teleport_fingerprint_state
                    tampered_sv, _ = teleport_fingerprint_state(
                        copy.statevector, 8, noise_rate=0.5
                    )
                    copy.statevector = tampered_sv
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            result = bob.verify_packet(packet, simulate_e91_attack="INTERCEPT_RESEND")

        elif attack_type in (AttackType.QUANTUM_X, AttackType.QUANTUM_Z, AttackType.QUANTUM_Y):
            # Pauli attacks applied to Bob's stored public key states
            pauli_name = attack_type.name.replace("QUANTUM_", "")
            if bob.key_register:
                for (pos, bit), copy in list(bob.key_register.copies.items()):
                    from src.teleportation import teleport_fingerprint_state
                    tampered_sv, _ = teleport_fingerprint_state(
                        copy.statevector, 8, pauli_attack=pauli_name
                    )
                    copy.statevector = tampered_sv
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            result = bob.verify_packet(packet)

        elif attack_type == AttackType.QUANTUM_DEPOLARIZING:
            noise_rate = kwargs.get("error_probability", 0.5)
            if bob.key_register:
                for (pos, bit), copy in list(bob.key_register.copies.items()):
                    from src.teleportation import teleport_fingerprint_state
                    tampered_sv, _ = teleport_fingerprint_state(
                        copy.statevector, 8, noise_rate=noise_rate
                    )
                    copy.statevector = tampered_sv
            packet = alice.create_packet("HELLO BOB", self.n_qubits)
            result = bob.verify_packet(packet)

        else:
            raise ValueError(f"Unknown attack type: {attack_type}")

        result.attack_id = attack_id
        result.attack_type = attack_type
        self.metrics.record_attack_result(result)
        return result
