import copy
import random
import uuid
from typing import List, Dict, Any, Tuple
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

from src.packet import SecurePacket
from src.qds_signer import GCSignature, QDSSignature
from src.teleportation import create_teleportation_circuit, simulate_teleportation

class Eve:
    @staticmethod
    def tamper_message(packet: SecurePacket, new_message: str) -> SecurePacket:
        tampered = copy.deepcopy(packet)
        tampered.message = new_message
        return tampered
        
    @staticmethod
    def tamper_hash(packet: SecurePacket, new_hash: str) -> SecurePacket:
        tampered = copy.deepcopy(packet)
        tampered.message_hash = new_hash
        return tampered

    @staticmethod
    def tamper_ml_dsa_signature(packet: SecurePacket) -> SecurePacket:
        """Modifies the ML-DSA signature to simulate tampering."""
        tampered = copy.deepcopy(packet)
        if tampered.ml_dsa_signature:
            # Change a few bytes in the hex signature
            sig_list = list(tampered.ml_dsa_signature)
            if len(sig_list) > 10:
                sig_list[8] = '0' if sig_list[8] != '0' else '1'
                sig_list[9] = '0' if sig_list[9] != '0' else '1'
            tampered.ml_dsa_signature = "".join(sig_list)
        return tampered

    @staticmethod
    def tamper_correction_bits(packet: SecurePacket, index: int) -> SecurePacket:
        """Flips a single correction bit to simulate a DoS attack."""
        tampered = copy.deepcopy(packet)
        if not tampered.qds_signature:
            return tampered
            
        bits = list(tampered.qds_signature.correction_bits)
        if index < len(bits):
            bits[index] = '1' if bits[index] == '0' else '0'
        tampered.qds_signature.correction_bits = "".join(bits)
        return tampered

    @staticmethod
    def tamper_sequence(packet: SecurePacket, new_sequence: int) -> SecurePacket:
        tampered = copy.deepcopy(packet)
        tampered.sequence_number = new_sequence
        return tampered

    @staticmethod
    def forge_signature(
        message_hash: str = "",
        auth_context: str = "",
        n_qubits: int = 64,
        session_id: str = "forged_session",
        seq_num: int = 1,
        message: bytes = b"FORGED",
    ) -> GCSignature:
        """
        Eve attempts to forge a signature without the quantum key material.
        Generates random keys for each message bit position.
        """
        return Eve.forge_gc_signature(
            message=message,
            n_positions=n_qubits,
            key_bytes=16,
            session_id=session_id,
            sequence_number=seq_num,
        )

    @staticmethod
    def _apply_quantum_operation(signature: QDSSignature, symbol_indices: List[int], op_func) -> QDSSignature:
        tampered_sig = copy.deepcopy(signature)
        
        for i in symbol_indices:
            sv = tampered_sig.teleported_states[i]["statevector"]
            if not isinstance(sv, Statevector):
                sv = Statevector(sv)
                
            qc = QuantumCircuit(3)
            op_func(qc, 2)
            
            new_sv = sv.evolve(qc)
            tampered_sig.teleported_states[i]["statevector"] = new_sv
            
        return tampered_sig

    @staticmethod
    def apply_pauli_x(signature: QDSSignature, symbol_indices: List[int]) -> QDSSignature:
        return Eve._apply_quantum_operation(signature, symbol_indices, lambda qc, qubit: qc.x(qubit))

    @staticmethod
    def apply_pauli_z(signature: QDSSignature, symbol_indices: List[int]) -> QDSSignature:
        return Eve._apply_quantum_operation(signature, symbol_indices, lambda qc, qubit: qc.z(qubit))

    @staticmethod
    def apply_pauli_y(signature: QDSSignature, symbol_indices: List[int]) -> QDSSignature:
        return Eve._apply_quantum_operation(signature, symbol_indices, lambda qc, qubit: qc.y(qubit))
        
    @staticmethod
    def intercept_measure_resend(signature: QDSSignature, symbol_indices: List[int], seed: int = None) -> QDSSignature:
        tampered_sig = copy.deepcopy(signature)
        rng = random.Random(seed)
        
        for i in symbol_indices:
            sv = tampered_sig.teleported_states[i]["statevector"]
            if not isinstance(sv, Statevector):
                sv = Statevector(sv)
                
            basis = rng.choice(["Z", "X"])
            
            qc_pre = QuantumCircuit(3)
            if basis == "X":
                qc_pre.h(2)
                
            sv_rotated = sv.evolve(qc_pre)
            
            outcome, collapsed_sv = sv_rotated.measure([2])
            
            qc_post = QuantumCircuit(3)
            if basis == "X":
                qc_post.h(2)
                
            new_sv = collapsed_sv.evolve(qc_post)
            tampered_sig.teleported_states[i]["statevector"] = new_sv
            
        return tampered_sig

        return tampered_sig

    @staticmethod
    def forge_gc_signature(
        message: bytes,
        n_positions: int = 32,
        key_bytes: int = 16,
        session_id: str = "forged_session",
        sequence_number: int = 1,
    ) -> GCSignature:
        """
        Eve creates a forged GC signature without knowing Alice's private keys.
        Eve generates completely random keys for each message bit position.
        By Holevo's theorem, Eve cannot invert Alice's public keys.
        """
        import os
        from src.qds_signer import GCSigner
        message_bits = GCSigner.encode_message(message, n_positions)
        forged_keys = [os.urandom(key_bytes) for _ in range(n_positions)]
        return GCSignature(
            message=message,
            message_bits=message_bits,
            n_positions=n_positions,
            revealed_keys=forged_keys,
            fingerprint_qubits=8,
            private_key_bits=key_bytes * 8,
            session_id=session_id,
            sequence_number=sequence_number,
        )

    @staticmethod
    def tamper_revealed_key(packet: SecurePacket, position_idx: int) -> SecurePacket:
        """Tamper with a single revealed private key in the signature."""
        import os
        tampered = copy.deepcopy(packet)
        if tampered.qds_signature and hasattr(tampered.qds_signature, "revealed_keys"):
            keys = list(tampered.qds_signature.revealed_keys)
            if position_idx < len(keys):
                old_key = keys[position_idx]
                keys[position_idx] = os.urandom(len(old_key))
                tampered.qds_signature.revealed_keys = keys
        return tampered

    @staticmethod
    def substitute_public_key(
        register: "VerifierKeyRegister",
        position: int,
        bit: int,
        fake_state: "Statevector"
    ) -> None:
        """
        Eve substitutes a verifier's stored public key copy with a fake state.
        This tests public-key substitution detection.
        """
        from src.gc_keys import PublicKeyCopy, CopyStatus
        register.copies[(position, bit)] = PublicKeyCopy(
            position=position,
            bit=bit,
            statevector=fake_state,
            status=CopyStatus.DISTRIBUTED,
            owner=register.owner,
        )
