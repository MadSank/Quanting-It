import copy
import random
from typing import List, Dict, Any, Tuple
from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

from src.packet import SecurePacket
from src.quantum_fingerprint import QuantumFingerprint

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
    def tamper_signature(packet: SecurePacket, new_signature: str) -> SecurePacket:
        tampered = copy.deepcopy(packet)
        tampered.pq_signature = new_signature
        return tampered

    @staticmethod
    def tamper_sequence(packet: SecurePacket, new_sequence: int) -> SecurePacket:
        tampered = copy.deepcopy(packet)
        tampered.sequence_number = new_sequence
        return tampered
        
    @staticmethod
    def substitute_quantum_fingerprint(packet: SecurePacket, new_proof: QuantumFingerprint) -> SecurePacket:
        tampered = copy.deepcopy(packet)
        tampered.quantum_fingerprint = copy.deepcopy(new_proof)
        return tampered

    @staticmethod
    def _apply_quantum_operation(proof: QuantumFingerprint, symbol_indices: List[int], op_func) -> QuantumFingerprint:
        tampered_proof = copy.deepcopy(proof)
        
        for i in symbol_indices:
            sv = tampered_proof.teleportation_metadata[i]["teleport_statevector"]
            if not isinstance(sv, Statevector):
                sv = Statevector(sv)
                
            qc = QuantumCircuit(3)
            op_func(qc, 2)
            
            new_sv = sv.evolve(qc)
            tampered_proof.teleportation_metadata[i]["teleport_statevector"] = new_sv
            
        return tampered_proof

    @staticmethod
    def apply_pauli_x(proof: QuantumFingerprint, symbol_indices: List[int]) -> QuantumFingerprint:
        return Eve._apply_quantum_operation(proof, symbol_indices, lambda qc, qubit: qc.x(qubit))

    @staticmethod
    def apply_pauli_z(proof: QuantumFingerprint, symbol_indices: List[int]) -> QuantumFingerprint:
        return Eve._apply_quantum_operation(proof, symbol_indices, lambda qc, qubit: qc.z(qubit))

    @staticmethod
    def apply_pauli_y(proof: QuantumFingerprint, symbol_indices: List[int]) -> QuantumFingerprint:
        return Eve._apply_quantum_operation(proof, symbol_indices, lambda qc, qubit: qc.y(qubit))
        
    @staticmethod
    def intercept_measure_resend(proof: QuantumFingerprint, symbol_indices: List[int], seed: int = None) -> QuantumFingerprint:
        tampered_proof = copy.deepcopy(proof)
        rng = random.Random(seed)
        
        for i in symbol_indices:
            sv = tampered_proof.teleportation_metadata[i]["teleport_statevector"]
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
            tampered_proof.teleportation_metadata[i]["teleport_statevector"] = new_sv
            
        return tampered_proof

    @staticmethod
    def apply_depolarizing_noise(proof: QuantumFingerprint, error_probability: float, seed: int = None) -> QuantumFingerprint:
        tampered_proof = copy.deepcopy(proof)
        rng = random.Random(seed)
        
        for i in range(len(proof.teleportation_metadata)):
            if rng.random() < error_probability:
                op = rng.choice(["X", "Y", "Z"])
                if op == "X":
                    tampered_proof = Eve.apply_pauli_x(tampered_proof, [i])
                elif op == "Y":
                    tampered_proof = Eve.apply_pauli_y(tampered_proof, [i])
                elif op == "Z":
                    tampered_proof = Eve.apply_pauli_z(tampered_proof, [i])
                    
        return tampered_proof
