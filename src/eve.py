import copy
import random
import uuid
from typing import List, Dict, Any, Tuple
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

from src.packet import SecurePacket
from src.qds_signer import QDSSignature
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
    def forge_signature(message_hash: str, auth_context: str, n_qubits: int = 64, session_id: str = "forged_session", seq_num: int = 1) -> QDSSignature:
        """
        Eve attempts to forge a signature without the quantum key material.
        She guesses the basis (Z or X) and prepares a random state.
        This is the attack modeled by the ThreatEngine forgery bound.
        """
        teleported_states = []
        correction_bits_list = []
        
        for i in range(n_qubits):
            basis = random.choice(['Z', 'X'])
            state_bit = random.choice([0, 1])
            
            qc = QuantumCircuit(1)
            if basis == 'Z':
                if state_bit == 1:
                    qc.x(0)
            else:
                if state_bit == 0:
                    qc.h(0)
                else:
                    qc.x(0)
                    qc.h(0)
                    
            # Eve simulates teleportation (without Alice's Bell pair halves)
            teleport_qc = create_teleportation_circuit(qc)
            result = simulate_teleportation(teleport_qc)
            
            counts = result.get("counts", {})
            if counts:
                outcome = list(counts.keys())[0]
                parts = outcome.split()
                if len(parts) == 2:
                    crx_bit = int(parts[0])
                    crz_bit = int(parts[1])
                else:
                    crz_bit = 0
                    crx_bit = 0
            else:
                crz_bit = 0
                crx_bit = 0
                
            teleported_states.append({
                "symbol_index": i,
                "statevector": result["statevector"],
                "crz_bit": crz_bit,
                "crx_bit": crx_bit,
            })
            correction_bits_list.append(f"{crz_bit}{crx_bit}")
            
        correction_bits = "".join(correction_bits_list)
            
        from src.classical_channel import ClassicalChannelAuth
        eve_pub, eve_priv = ClassicalChannelAuth.generate_keys()
        
        auth_tag = ClassicalChannelAuth.sign_correction_bits(
            correction_bits, session_id, seq_num, eve_priv
        )
            
        return QDSSignature(
            signature_id=str(uuid.uuid4()),
            session_id=session_id,
            sequence_number=seq_num,
            n_qubits=n_qubits,
            teleported_states=teleported_states,
            correction_bits=correction_bits,
            correction_auth_tag=auth_tag,
            signing_spec_hash="forged_hash",
            classical_pub_key=eve_pub
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

    @staticmethod
    def apply_depolarizing_noise(signature: QDSSignature, error_probability: float, seed: int = None) -> QDSSignature:
        tampered_sig = copy.deepcopy(signature)
        rng = random.Random(seed)
        
        for i in range(len(signature.teleported_states)):
            if rng.random() < error_probability:
                op = rng.choice(["X", "Y", "Z"])
                if op == "X":
                    tampered_sig = Eve.apply_pauli_x(tampered_sig, [i])
                elif op == "Y":
                    tampered_sig = Eve.apply_pauli_y(tampered_sig, [i])
                elif op == "Z":
                    tampered_sig = Eve.apply_pauli_z(tampered_sig, [i])
                    
        return tampered_sig
