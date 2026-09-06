from typing import List, Dict, Any
from src.session import Session
from src.alice import Alice
from src.bob import Bob
from src.eve import Eve
from src.metrics import SecurityMetrics, AttackResult, AttackType
from src.quantum_resources import SessionResourceManager, ResourceType
from src.crypto import generate_challenge

class AttackSimulator:
    def __init__(self, proof_length: int = 8):
        self.proof_length = proof_length
        self.metrics = SecurityMetrics()
        
    def setup_session(self) -> tuple[Alice, Bob, Session]:
        session = Session()
        chal = generate_challenge()
        session.start_session(chal)
        session.activate()
        
        manager = SessionResourceManager(session.session_id)
        manager.allocate_pairs(100, ResourceType.TELEPORT_PAIR)
        
        import hashlib
        auth_ctx_raw = f"CONTEXT_{session.session_id}"
        auth_ctx = hashlib.sha256(auth_ctx_raw.encode()).hexdigest()
        
        alice = Alice(session, auth_ctx, manager)
        bob = Bob(session, auth_ctx)
        
        return alice, bob, session

    def run_attack(self, attack_type: AttackType, attack_id: str, **kwargs) -> AttackResult:
        alice, bob, session = self.setup_session()
        
        if attack_type == AttackType.NO_ATTACK:
            packet = alice.create_packet("HELLO BOB", self.proof_length)
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.MESSAGE_TAMPERING:
            packet = alice.create_packet("HELLO BOB", self.proof_length)
            tampered_packet = Eve.tamper_message(packet, "HELLO EVE")
            result = bob.verify_packet(tampered_packet)
            
        elif attack_type == AttackType.HASH_TAMPERING:
            packet = alice.create_packet("HELLO BOB", self.proof_length)
            tampered_packet = Eve.tamper_hash(packet, "badhash000")
            result = bob.verify_packet(tampered_packet)
            
        elif attack_type == AttackType.SIGNATURE_TAMPERING:
            packet = alice.create_packet("HELLO BOB", self.proof_length)
            tampered_packet = Eve.tamper_signature(packet, packet.pq_signature[:-4] + "0000")
            result = bob.verify_packet(tampered_packet)

        elif attack_type == AttackType.SEQUENCE_TAMPERING:
            packet = alice.create_packet("HELLO BOB", self.proof_length)
            tampered_packet = Eve.tamper_sequence(packet, 999)
            result = bob.verify_packet(tampered_packet)
            
        elif attack_type == AttackType.REPLAY:
            packet = alice.create_packet("HELLO BOB", self.proof_length)
            bob.verify_packet(packet)
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.QUANTUM_X:
            packet = alice.create_packet("HELLO BOB", self.proof_length)
            tampered_proof = Eve.apply_pauli_x(packet.quantum_fingerprint, [0])
            packet.quantum_fingerprint = tampered_proof
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.QUANTUM_Z:
            packet = alice.create_packet("HELLO BOB", self.proof_length)
            tampered_proof = Eve.apply_pauli_z(packet.quantum_fingerprint, [0])
            packet.quantum_fingerprint = tampered_proof
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.QUANTUM_Y:
            packet = alice.create_packet("HELLO BOB", self.proof_length)
            tampered_proof = Eve.apply_pauli_y(packet.quantum_fingerprint, [0])
            packet.quantum_fingerprint = tampered_proof
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.QUANTUM_DEPOLARIZING:
            prob = kwargs.get("error_probability", 0.5)
            packet = alice.create_packet("HELLO BOB", self.proof_length)
            tampered_proof = Eve.apply_depolarizing_noise(packet.quantum_fingerprint, prob)
            packet.quantum_fingerprint = tampered_proof
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.INTERCEPT_RESEND:
            packet = alice.create_packet("HELLO BOB", self.proof_length)
            tampered_proof = Eve.intercept_measure_resend(packet.quantum_fingerprint, list(range(self.proof_length)))
            packet.quantum_fingerprint = tampered_proof
            result = bob.verify_packet(packet)
            
        elif attack_type == AttackType.E91_CHANNEL_DISTURBANCE:
            packet = alice.create_packet("HELLO BOB", self.proof_length)
            # E91 disturbance simulated at Bob's end
            result = bob.verify_packet(packet, simulate_e91_attack="INTERCEPT_RESEND")

        elif attack_type == AttackType.PROOF_SUBSTITUTION:
            packet_a = alice.create_packet("MSG A", self.proof_length)
            packet_b = alice.create_packet("MSG B", self.proof_length)
            tampered_packet_b = Eve.substitute_quantum_fingerprint(packet_b, packet_a.quantum_fingerprint)
            result = bob.verify_packet(tampered_packet_b)
            
        elif attack_type == AttackType.CROSS_SESSION_REUSE:
            a_alice, a_bob, a_sess = self.setup_session()
            b_alice, b_bob, b_sess = self.setup_session()
            
            packet_a = a_alice.create_packet("HELLO", self.proof_length)
            packet_b = b_alice.create_packet("HELLO", self.proof_length)
            
            tampered_packet_b = Eve.substitute_quantum_fingerprint(packet_b, packet_a.quantum_fingerprint)
            result = b_bob.verify_packet(tampered_packet_b)
            
        elif attack_type == AttackType.COMPROMISED_SESSION_CONTEXT:
            # We mock the compromise of classical keys and context but Bob verifies E91 channel which fails or signature fails
            # Here, Eve completely forges the classical + quantum elements for a DIFFERENT message using stolen context.
            # But the PQ keys weren't stolen!
            # Wait, let's just use Bob's verification and see it fail at PQ_SIGNATURE or FINGERPRINT.
            packet = alice.create_packet("MSG", self.proof_length)
            # Eve uses her own keys to sign
            from src.pq_signature import DEMO_PQ_SIGNER
            bad_pub, bad_priv = DEMO_PQ_SIGNER.generate_keys()
            packet.pq_signature = DEMO_PQ_SIGNER.sign(packet.message_hash, bad_priv, bad_pub)
            # But she doesn't know she can't change Bob's expected PQ key if it's tied to session. 
            # In our system, Bob just uses packet.pq_public_key, which is a structural weakness of our mock!
            # So Bob will accept the signature, BUT the message hash verification might fail if she tampered with the message.
            # If she didn't tamper with message, she's just replacing the signature. 
            # Let's say she changes the message and the hash and signs it with her key.
            from src.crypto import compute_message_hash
            packet.message = "EVIL"
            packet.message_hash = compute_message_hash(packet.message, session.session_id, session.challenge, packet.sequence_number)
            packet.pq_public_key = bad_pub
            packet.pq_signature = DEMO_PQ_SIGNER.sign(packet.message_hash, bad_priv, bad_pub)
            # Now the fingerprint won't match the new hash! 
            result = bob.verify_packet(packet)
            
        else:
            raise ValueError(f"Unknown attack type: {attack_type}")

        result.attack_id = attack_id
        result.attack_type = attack_type
        self.metrics.record_attack_result(result)
        return result
